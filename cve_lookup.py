import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE_DIR = Path(os.environ.get("NVD_CACHE_DIR", ".cache/nvd"))
NVD_CACHE_TTL = int(os.environ.get("NVD_CACHE_TTL", str(24 * 3600)))
NVD_CACHE_ENABLED = os.environ.get("NVD_CACHE", "1").strip().lower() not in (
    "0",
    "false",
    "no",
)
NVD_MAX_RETRIES = int(os.environ.get("NVD_MAX_RETRIES", "3"))

_NVD_STATS: Dict[str, int] = {
    "requests": 0,
    "cache_hits": 0,
    "cache_misses": 0,
    "retries": 0,
    "errors": 0,
}

_METRIC_ORDER = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
_METRIC_VERSION = {"cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}

# product (from banners) -> (vendor, cpe product component)
_CPE_APPLICATIONS: Dict[str, Tuple[str, str]] = {
    "openssh": ("openbsd", "openssh"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "iis": ("microsoft", "internet_information_services"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mssql": ("microsoft", "sql_server"),
    "openssl": ("openssl", "openssl"),
    "tomcat": ("apache", "tomcat"),
    "postfix": ("postfix", "postfix"),
    "vsftpd": ("vsftpd", "vsftpd"),
}


def reset_nvd_fetch_stats() -> None:
    for k in _NVD_STATS:
        _NVD_STATS[k] = 0


def consume_nvd_fetch_stats() -> Dict[str, Any]:
    out = {
        **dict(_NVD_STATS),
        "cache_enabled": NVD_CACHE_ENABLED,
        "cache_dir": str(NVD_CACHE_DIR),
    }
    reset_nvd_fetch_stats()
    return out


def _cache_file_for_url(url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:40]
    return NVD_CACHE_DIR / f"{digest}.json"


def _read_cache(url: str) -> Optional[dict]:
    if not NVD_CACHE_ENABLED:
        return None
    path = _cache_file_for_url(url)
    if not path.is_file():
        return None
    try:
        age = time.time() - path.stat().st_mtime
        if age > NVD_CACHE_TTL:
            return None
        with path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
        if isinstance(payload, dict) and "vulnerabilities" in payload:
            _NVD_STATS["cache_hits"] += 1
            return payload
    except (OSError, json.JSONDecodeError, TypeError):
        pass
    return None


def _write_cache(url: str, data: dict) -> None:
    if not NVD_CACHE_ENABLED:
        return
    try:
        NVD_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = _cache_file_for_url(url)
        tmp = path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(data, fh)
        tmp.replace(path)
    except OSError:
        pass


def _nvd_request_live(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "Vul-Scanner/1.0"})
    last_err: Optional[Exception] = None
    for attempt in range(max(1, NVD_MAX_RETRIES)):
        _NVD_STATS["requests"] += 1
        try:
            with urllib.request.urlopen(req, timeout=14) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code in (429, 500, 502, 503, 504) and attempt + 1 < NVD_MAX_RETRIES:
                _NVD_STATS["retries"] += 1
                time.sleep(1.2 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last_err = e
            if attempt + 1 < NVD_MAX_RETRIES:
                _NVD_STATS["retries"] += 1
                time.sleep(1.0 * (attempt + 1))
                continue
            raise
    if last_err:
        raise last_err
    return {}


def _nvd_request(url: str) -> dict:
    cached = _read_cache(url)
    if cached is not None:
        return cached
    _NVD_STATS["cache_misses"] += 1
    try:
        data = _nvd_request_live(url)
    except Exception:
        _NVD_STATS["errors"] += 1
        raise
    if isinstance(data, dict):
        _write_cache(url, data)
    return data


def _extract_cvss(metrics: dict):
    if not metrics:
        return None, None, None, None
    for key in _METRIC_ORDER:
        arr = metrics.get(key)
        if not arr or not isinstance(arr, list):
            continue
        m0 = arr[0]
        cvss_data = m0.get("cvssData") or {}
        base = cvss_data.get("baseScore")
        if base is None:
            continue
        vec = cvss_data.get("vectorString")
        sev = cvss_data.get("baseSeverity") or cvss_data.get("severity")
        return float(base), vec, _METRIC_VERSION.get(key), sev
    return None, None, None, None


def _sanitize_cpe_version(version_token: str) -> Optional[str]:
    v = (version_token or "").strip()
    if not v:
        return None
    v = re.sub(r"[^A-Za-z0-9._\-+]", "_", v)
    if not v or v in ("*", "-"):
        return None
    return v[:64]


def build_cpe(product: str, version_token: str) -> Optional[str]:
    """Build CPE 2.3 application name for NVD cpeName filter (vendor/product/version required)."""
    prod = (product or "").lower().strip()
    mapping = _CPE_APPLICATIONS.get(prod)
    if not mapping:
        return None
    ver = _sanitize_cpe_version(version_token)
    if not ver:
        return None
    vendor, cpe_product = mapping
    return f"cpe:2.3:a:{vendor}:{cpe_product}:{ver}:*:*:*:*:*:*:*"


def cpe_for_installed(installed_row: dict) -> Optional[str]:
    return build_cpe(installed_row.get("product"), installed_row.get("version_token"))


def _parse_vulnerability_item(item: dict) -> Optional[dict]:
    cve = item.get("cve") or {}
    cve_id = cve.get("id") or cve.get("CVE_data_meta", {}).get("ID")
    if not cve_id:
        return None
    desc = ""
    descriptions = cve.get("descriptions") or cve.get("description", [])
    if isinstance(descriptions, list) and descriptions:
        desc = (
            descriptions[0].get("value", "")
            if isinstance(descriptions[0], dict)
            else str(descriptions[0])
        )
    elif isinstance(descriptions, str):
        desc = descriptions
    metrics = cve.get("metrics") or {}
    cvss_score, cvss_vector, cvss_ver, severity = _extract_cvss(metrics)
    return {
        "cve_id": cve_id,
        "summary": (desc or "")[:400],
        "cvss": cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_version": cvss_ver,
        "severity": severity,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{urllib.parse.quote(cve_id)}",
    }


def _fetch_cves(url: str, max_results: int, verbose: bool = False) -> List[dict]:
    if verbose:
        print(url)
    try:
        data = _nvd_request(url)
    except Exception as exc:
        if verbose:
            print(f"NVD error: {exc}")
        return []
    items = data.get("vulnerabilities") or []
    results = []
    for item in items[:max_results]:
        row = _parse_vulnerability_item(item)
        if row:
            results.append(row)
    return results


def find_cves(keyword, max_results=5, verbose=False):
    if not keyword or not str(keyword).strip():
        return []
    q = urllib.parse.quote(str(keyword).strip())
    url = f"{NVD_BASE}?keywordSearch={q}&resultsPerPage={max_results}"
    return _fetch_cves(url, max_results, verbose=verbose)


def find_cves_by_cpe(cpe_name: str, max_results: int = 8, verbose: bool = False) -> List[dict]:
    cpe = (cpe_name or "").strip()
    if not cpe.lower().startswith("cpe:"):
        return []
    q = urllib.parse.quote(cpe)
    url = f"{NVD_BASE}?cpeName={q}&resultsPerPage={min(max(1, max_results), 50)}"
    rows = _fetch_cves(url, max_results, verbose=verbose)
    for row in rows:
        row["match_method"] = "cpe"
        row["cpe_name"] = cpe
    return rows


# NVD fetch pool vs keep after rank/filter (per product)
CPE_NVD_FETCH_MAX = 30
CPE_KEEP_PER_PRODUCT = 5
CPE_KEEP_STEALTH = 3

_CVE_YEAR_RE = re.compile(r"^CVE-(\d{4})-", re.I)


def cve_id_year(cve_id: str) -> int:
    m = _CVE_YEAR_RE.match((cve_id or "").strip())
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return 0


def rank_cpe_cves(cves: List[dict]) -> List[dict]:
    """
    Order CPE hits for triage: KEV, EPSS percentile (if present), CVSS, CVE year (newer first).
    """

    def sort_key(c: dict) -> tuple:
        kev = 1 if c.get("known_exploited") else 0
        try:
            epss_p = float(c.get("epss_percentile") or 0)
        except (TypeError, ValueError):
            epss_p = 0.0
        try:
            cvss = float(c.get("cvss") or 0)
        except (TypeError, ValueError):
            cvss = 0.0
        year = cve_id_year(c.get("cve_id") or "")
        return (kev, epss_p, cvss, year, c.get("cve_id") or "")

    return sorted(cves, key=sort_key, reverse=True)


def select_cpe_cves(
    cves: List[dict],
    *,
    max_keep: int = CPE_KEEP_PER_PRODUCT,
    installed: Optional[List[dict]] = None,
    min_cvss_unless_kev: Optional[float] = 4.0,
    min_year_unless_kev: int = 2010,
) -> Tuple[List[dict], Dict[str, int]]:
    """
    Drop version-not-applicable rows, deprioritize ancient low-CVSS noise, rank, and cap count.
    """
    stats = {
        "fetched": len(cves),
        "kept": 0,
        "dropped_version": 0,
        "dropped_stale_low": 0,
    }
    pool: List[dict] = []
    if installed:
        try:
            from version_match import assess_version_match

            for c in cves:
                vm, _ = assess_version_match(c, installed)
                if vm == "not_applicable":
                    stats["dropped_version"] += 1
                    continue
                pool.append(c)
        except ImportError:
            pool = list(cves)
    else:
        pool = list(cves)

    if min_cvss_unless_kev is not None and min_year_unless_kev:
        filtered: List[dict] = []
        for c in pool:
            if c.get("known_exploited"):
                filtered.append(c)
                continue
            year = cve_id_year(c.get("cve_id") or "")
            try:
                cvss = float(c.get("cvss") or 0)
            except (TypeError, ValueError):
                cvss = 0.0
            if year < min_year_unless_kev and cvss < min_cvss_unless_kev:
                stats["dropped_stale_low"] += 1
                continue
            filtered.append(c)
        pool = filtered

    ranked = rank_cpe_cves(pool)
    kept = ranked[: max(0, max_keep)]
    stats["kept"] = len(kept)
    return kept, stats
