"""CISA Known Exploited Vulnerabilities (KEV) catalog — lightweight in-process cache."""
import json
import urllib.request
from typing import Optional, Set

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_kev_ids: Optional[Set[str]] = None


def _load_kev_ids() -> Set[str]:
    global _kev_ids
    if _kev_ids is not None:
        return _kev_ids
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "Vul-Scanner/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.load(resp)
    except Exception:
        _kev_ids = set()
        return _kev_ids
    out: Set[str] = set()
    for row in data.get("vulnerabilities") or []:
        cid = row.get("cveID") or row.get("cveId")
        if cid:
            out.add(str(cid).upper())
    _kev_ids = out
    return _kev_ids


def is_known_exploited(cve_id: str) -> bool:
    if not cve_id:
        return False
    return cve_id.upper() in _load_kev_ids()
