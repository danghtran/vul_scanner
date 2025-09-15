import urllib.parse
import urllib.request
import json

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _nvd_request(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'MVP-Scanner-CVE/1.0'})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp)

def find_cves(keyword, max_results=5):

    if not keyword or not keyword.strip():
        return []

    q = urllib.parse.quote(keyword)
    url = f"{NVD_BASE}?keywordSearch={q}&resultsPerPage={max_results}"
    print(url)
    try:
        data = _nvd_request(url)
    except Exception:
        return []

    items = data.get('vulnerabilities') or data.get('vulnerabilities', [])
    results = []
    for item in items[:max_results]:
        # NVD v2 returns items with 'cve' and 'cve.id' etc.
        cve = item.get('cve') or {}
        cve_id = cve.get('id') or cve.get('CVE_data_meta', {}).get('ID')
        # description could be nested
        desc = ''
        descriptions = cve.get('descriptions') or cve.get('description', [])
        if isinstance(descriptions, list) and descriptions:
            desc = descriptions[0].get('value', '') if isinstance(descriptions[0], dict) else str(descriptions[0])
        elif isinstance(descriptions, str):
            desc = descriptions

        # try to get CVSS score (v3 preferred)
        cvss_score = None
        metrics = item.get('cve', {}).get('metrics') or cve.get('metrics', {})
        # NVD v2 structure: metrics -> cvssMetricV31 or cvssMetricV30 or cvssMetricV2
        if metrics:
            for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                arr = metrics.get(key)
                if arr and isinstance(arr, list) and arr:
                    base_score = arr[0].get('cvssData', {}).get('baseScore')
                    if base_score is not None:
                        cvss_score = float(base_score)
                        break

        if not cve_id:
            continue
        results.append({
            'cve_id': cve_id,
            'summary': (desc or '')[:400],
            'cvss': cvss_score,
            'nvd_url': f"https://nvd.nist.gov/vuln/detail/{urllib.parse.quote(cve_id)}"
        })
    return results
