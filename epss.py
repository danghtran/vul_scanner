"""
FIRST.org EPSS (Exploit Prediction Scoring System) — batch lookup via public API.
https://www.first.org/epss/api
"""
import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

EPSS_API = "https://api.first.org/data/v1/epss"
USER_AGENT = "Vul-Scanner/1.0 (epss)"
BATCH_SIZE = 50
TIMEOUT = 12

_cache: Dict[str, Dict[str, Any]] = {}


def _epss_enabled() -> bool:
    v = os.getenv("EPSS_ENABLED", "1").strip().lower()
    return v not in ("0", "false", "no", "off")


def _fetch_batch(cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    if not cve_ids:
        return {}
    joined = ",".join(cve_ids)
    q = urllib.parse.urlencode({"cve": joined})
    url = f"{EPSS_API}?{q}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            payload = json.load(resp)
    except Exception as e:
        return {"__error__": str(e)}

    out: Dict[str, Dict[str, Any]] = {}
    for row in payload.get("data") or []:
        cid = (row.get("cve") or "").upper()
        if not cid:
            continue
        try:
            score = float(row.get("epss", 0))
        except (TypeError, ValueError):
            score = None
        try:
            pct = float(row.get("percentile", 0))
        except (TypeError, ValueError):
            pct = None
        out[cid] = {
            "cve": cid,
            "epss": score,
            "percentile": pct,
            "date": row.get("date"),
        }
    return out


def fetch_epss_scores(cve_ids: List[str]) -> Dict[str, Any]:
    """
    Return map CVE_ID -> {epss, percentile, date} and metadata:
    {scores: {...}, status: ok|skipped|error, error?: str}
    """
    if not _epss_enabled():
        return {"scores": {}, "status": "skipped", "reason": "EPSS_ENABLED=0"}

    unique: List[str] = []
    seen = set()
    for cid in cve_ids:
        c = (cid or "").strip().upper()
        if not c or not c.startswith("CVE-"):
            continue
        if c in seen:
            continue
        seen.add(c)
        if c in _cache:
            continue
        unique.append(c)

    error_msg = None
    for i in range(0, len(unique), BATCH_SIZE):
        chunk = unique[i : i + BATCH_SIZE]
        batch = _fetch_batch(chunk)
        if "__error__" in batch:
            error_msg = batch["__error__"]
            break
        for cid, row in batch.items():
            _cache[cid] = row

    scores: Dict[str, Dict[str, Any]] = {}
    for cid in cve_ids:
        c = (cid or "").strip().upper()
        if c in _cache:
            scores[c] = _cache[c]

    result: Dict[str, Any] = {"scores": scores, "status": "ok"}
    if error_msg:
        result["status"] = "partial" if scores else "error"
        result["error"] = error_msg
    return result


def attach_epss_to_cve(cve: dict, epss_row: Optional[dict]) -> None:
    if not epss_row:
        cve["epss"] = None
        cve["epss_percentile"] = None
        cve["epss_date"] = None
        return
    cve["epss"] = epss_row.get("epss")
    cve["epss_percentile"] = epss_row.get("percentile")
    cve["epss_date"] = epss_row.get("date")
