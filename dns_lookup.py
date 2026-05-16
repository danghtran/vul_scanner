"""
Extended DNS context via Google Public DNS JSON API (stdlib urllib) plus local A/AAAA.
"""
import json
import re
import socket
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

DNS_API = "https://dns.google/resolve"
DNS_TIMEOUT = 6
USER_AGENT = "Vul-Scanner/1.0 (dns)"


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False


def _resolve_addresses(hostname: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ipv4": [], "ipv6": [], "error": None}
    if not hostname:
        out["error"] = "empty_host"
        return out
    seen4, seen6 = set(), set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            ip = sockaddr[0]
            if family == socket.AF_INET and ip not in seen4:
                seen4.add(ip)
                out["ipv4"].append(ip)
            elif family == socket.AF_INET6 and ip not in seen6:
                seen6.add(ip)
                out["ipv6"].append(ip)
    except socket.gaierror as e:
        out["error"] = str(e)
    except OSError as e:
        out["error"] = str(e)
    return out


def _dns_query(name: str, rtype: int) -> Dict[str, Any]:
    q = urllib.parse.urlencode({"name": name, "type": str(rtype)})
    url = f"{DNS_API}?{q}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=DNS_TIMEOUT) as resp:
            return json.load(resp)
    except Exception as e:
        return {"Status": -1, "error": str(e), "Answer": []}


def _answers(data: dict) -> List[str]:
    rows = []
    for ans in data.get("Answer") or []:
        if isinstance(ans, dict) and ans.get("data"):
            rows.append(str(ans["data"]).strip())
    return rows


def _parse_mx(records: List[str]) -> List[Dict[str, Any]]:
    out = []
    for r in records:
        parts = r.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            out.append({"priority": int(parts[0]), "host": parts[1].rstrip(".")})
        elif parts:
            out.append({"priority": None, "host": parts[-1].rstrip(".")})
    return sorted(out, key=lambda x: (x["priority"] if x["priority"] is not None else 9999))


def _parse_txt_records(name: str, raw: List[str]) -> List[Dict[str, str]]:
    out = []
    for r in raw:
        val = r.strip('"')
        out.append({"name": name, "value": val})
    return out


def _find_spf(txt_records: List[Dict[str, str]]) -> Optional[str]:
    for row in txt_records:
        v = (row.get("value") or "").strip()
        if v.lower().startswith("v=spf1"):
            return v
    return None


def _parse_dmarc(txt_records: List[Dict[str, str]]) -> Optional[Dict[str, Any]]:
    for row in txt_records:
        v = (row.get("value") or "").strip()
        if not v.upper().startswith("V=DMARC1"):
            continue
        policy = None
        m = re.search(r"\bp\s*=\s*(\w+)", v, re.I)
        if m:
            policy = m.group(1).lower()
        return {"record": v[:500], "policy": policy}
    return None


def _parse_caa(records: List[str]) -> List[Dict[str, str]]:
    out = []
    for r in records:
        # e.g. 0 issue "letsencrypt.org" or 0 issuewild "digicert.com"
        m = re.match(r"(\d+)\s+(\w+)\s+(.+)", r.strip())
        if m:
            val = m.group(3).strip().strip('"')
            out.append({"flags": m.group(1), "tag": m.group(2), "value": val})
        else:
            out.append({"raw": r[:200]})
    return out


def _build_asset_context(
    mx: List[dict], spf: Optional[str], dmarc: Optional[dict], caa: List[dict]
) -> Dict[str, Any]:
    has_mx = bool(mx)
    has_spf = spf is not None
    dmarc_policy = (dmarc or {}).get("policy") if dmarc else None
    return {
        "has_mx": has_mx,
        "has_spf": has_spf,
        "has_dmarc": dmarc is not None,
        "dmarc_policy": dmarc_policy,
        "has_caa": bool(caa),
        "mail_surface": has_mx,
        "email_auth_weak": has_mx and (not has_spf or dmarc is None or dmarc_policy in (None, "none")),
    }


def gather_dns_extended(hostname: str, query_delay: float = 0) -> Dict[str, Any]:
    """A/AAAA (local) plus MX, apex TXT (SPF), DMARC, CAA via DNS-over-HTTPS JSON."""
    host = (hostname or "").strip().rstrip(".")
    result: Dict[str, Any] = {
        "host": host,
        "ipv4": [],
        "ipv6": [],
        "mx": [],
        "txt": [],
        "spf": None,
        "dmarc": None,
        "caa": [],
        "asset_context": {},
        "dns_errors": [],
    }
    if not host:
        result["error"] = "empty_host"
        return result

    addrs = _resolve_addresses(host)
    result["ipv4"] = addrs["ipv4"]
    result["ipv6"] = addrs["ipv6"]
    if addrs.get("error"):
        result["error"] = addrs["error"]

    if _is_ip(host):
        result["asset_context"] = _build_asset_context([], None, None, [])
        result["note"] = "IP target: MX/TXT/DMARC/CAA skipped"
        return result

    mx_data = _dns_query(host, 15)
    if mx_data.get("error"):
        result["dns_errors"].append(f"MX: {mx_data['error']}")
    result["mx"] = _parse_mx(_answers(mx_data))
    if query_delay > 0:
        time.sleep(query_delay)

    txt_data = _dns_query(host, 16)
    if txt_data.get("error"):
        result["dns_errors"].append(f"TXT: {txt_data['error']}")
    apex_txt = _parse_txt_records(host, _answers(txt_data))
    result["txt"] = apex_txt
    result["spf"] = _find_spf(apex_txt)
    if query_delay > 0:
        time.sleep(query_delay)

    dmarc_name = f"_dmarc.{host}"
    dmarc_data = _dns_query(dmarc_name, 16)
    if dmarc_data.get("error"):
        result["dns_errors"].append(f"DMARC: {dmarc_data['error']}")
    dmarc_txt = _parse_txt_records(dmarc_name, _answers(dmarc_data))
    result["dmarc"] = _parse_dmarc(dmarc_txt)
    if query_delay > 0:
        time.sleep(query_delay)

    caa_data = _dns_query(host, 257)
    if caa_data.get("error"):
        result["dns_errors"].append(f"CAA: {caa_data['error']}")
    result["caa"] = _parse_caa(_answers(caa_data))

    result["asset_context"] = _build_asset_context(
        result["mx"], result["spf"], result["dmarc"], result["caa"]
    )
    return result
