import re
import urllib.parse
import urllib.request
import json
from typing import Any, Dict, List, Optional, Tuple

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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
}


def _nvd_request(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "Vul-Scanner/1.0"})
    with urllib.request.urlopen(req, timeout=12) as resp:
        return json.load(resp)


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
    except Exception:
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
