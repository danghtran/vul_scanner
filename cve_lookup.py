import urllib.parse
import urllib.request
import json

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_METRIC_ORDER = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
_METRIC_VERSION = {"cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}


def _nvd_request(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Vul-Scanner/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
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


def find_cves(keyword, max_results=5, verbose=False):
    if not keyword or not str(keyword).strip():
        return []

    q = urllib.parse.quote(str(keyword).strip())
    url = f"{NVD_BASE}?keywordSearch={q}&resultsPerPage={max_results}"
    if verbose:
        print(url)
    try:
        data = _nvd_request(url)
    except Exception:
        return []

    items = data.get("vulnerabilities") or []
    results = []
    for item in items[:max_results]:
        cve = item.get("cve") or {}
        cve_id = cve.get("id") or cve.get("CVE_data_meta", {}).get("ID")
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

        metrics = item.get("cve", {}).get("metrics") or cve.get("metrics") or {}
        cvss_score, cvss_vector, cvss_ver, severity = _extract_cvss(metrics)

        if not cve_id:
            continue
        results.append(
            {
                "cve_id": cve_id,
                "summary": (desc or "")[:400],
                "cvss": cvss_score,
                "cvss_vector": cvss_vector,
                "cvss_version": cvss_ver,
                "severity": severity,
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{urllib.parse.quote(cve_id)}",
            }
        )
    return results
