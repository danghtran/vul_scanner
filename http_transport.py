"""
HTTP transport recon: redirect chains, HSTS parsing, cookie hardening audit.
"""
import re
from typing import Any, Dict, List, Optional
from urllib import error, request
from urllib.parse import urljoin, urlparse

from inventory_context import USER_AGENT, _parse_cookies, _tech_from_html, _uniq_keep_order, _server_tokens

MAX_REDIRECTS = 12
BODY_MAX = 65536
REDIRECT_CODES = frozenset((301, 302, 303, 307, 308))


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_hsts(header_value: Optional[str]) -> Optional[Dict[str, Any]]:
    if not header_value or not str(header_value).strip():
        return None
    raw = str(header_value).strip()
    parts: Dict[str, Any] = {}
    for seg in raw.split(";"):
        seg = seg.strip()
        if not seg:
            continue
        if "=" in seg:
            k, v = seg.split("=", 1)
            parts[k.strip().lower()] = v.strip()
        else:
            parts[seg.lower()] = True
    max_age = None
    if "max-age" in parts:
        try:
            max_age = int(parts["max-age"])
        except (TypeError, ValueError):
            max_age = None
    return {
        "raw": raw[:400],
        "max_age": max_age,
        "include_subdomains": "includesubdomains" in parts,
        "preload": "preload" in parts,
    }


def trace_redirects(start_url: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Follow redirects manually; record each hop (no auto-follow)."""
    chain: List[Dict[str, Any]] = []
    current = start_url
    opener = request.build_opener(_NoRedirect())
    final_headers = None
    final_status = None
    error_msg = None

    for _ in range(MAX_REDIRECTS):
        req = request.Request(current, headers={"User-Agent": USER_AGENT})
        hop: Dict[str, Any] = {"url": current, "status": None, "location": None}
        try:
            with opener.open(req, timeout=timeout) as resp:
                hop["status"] = resp.getcode()
                final_status = hop["status"]
                final_headers = resp.headers
                chain.append(hop)
                break
        except error.HTTPError as e:
            hop["status"] = e.code
            loc = e.headers.get("Location") or e.headers.get("location") if e.headers else None
            hop["location"] = loc
            chain.append(hop)
            if e.code in REDIRECT_CODES and loc:
                current = urljoin(current, loc)
                continue
            final_status = e.code
            final_headers = e.headers
            break
        except Exception as e:
            hop["error"] = str(e)
            chain.append(hop)
            error_msg = str(e)
            break

    final_url = current
    if chain and chain[-1].get("location") and chain[-1].get("status") in REDIRECT_CODES:
        final_url = urljoin(chain[-1]["url"], chain[-1]["location"])

    scheme_https = urlparse(final_url).scheme.lower() == "https"
    hsts = None
    if final_headers:
        hsts = parse_hsts(final_headers.get("Strict-Transport-Security"))

    return {
        "start_url": start_url,
        "final_url": final_url,
        "chain": chain,
        "hop_count": len(chain),
        "final_status": final_status,
        "final_scheme_https": scheme_https,
        "hsts": hsts,
        "error": error_msg,
    }


def audit_cookies(cookies: List[dict], https: bool) -> Dict[str, Any]:
    missing_secure: List[str] = []
    missing_httponly: List[str] = []
    missing_samesite: List[str] = []
    for c in cookies:
        name = c.get("name")
        if not name:
            continue
        if https and not c.get("secure"):
            missing_secure.append(name)
        if not c.get("httponly"):
            missing_httponly.append(name)
        if not c.get("samesite"):
            missing_samesite.append(name)
    return {
        "missing_secure": missing_secure,
        "missing_httponly": missing_httponly,
        "missing_samesite": missing_samesite,
        "cookies_missing_secure_on_https": bool(missing_secure),
        "cookies_missing_httponly": bool(missing_httponly),
        "cookies_missing_samesite": bool(missing_samesite),
    }


def fetch_final_response(
    url: str, timeout: float = 5.0, max_body: int = BODY_MAX
) -> Dict[str, Any]:
    """GET final URL (urllib may still follow redirects if any remain)."""
    out: Dict[str, Any] = {
        "url": url,
        "final_url": None,
        "http_status": None,
        "server": None,
        "x_powered_by": None,
        "cookies": [],
        "hsts": None,
        "error": None,
    }
    req = request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            out["final_url"] = resp.geturl()
            out["http_status"] = resp.getcode()
            out["server"] = resp.headers.get("Server")
            out["x_powered_by"] = resp.headers.get("X-Powered-By")
            out["cookies"] = _parse_cookies(resp.headers)
            out["hsts"] = parse_hsts(resp.headers.get("Strict-Transport-Security"))
            raw = resp.read(max_body + 1)
            if len(raw) > max_body:
                raw = raw[:max_body]
            out["html"] = raw.decode("utf-8", errors="replace")
    except error.HTTPError as e:
        out["http_status"] = e.code
        out["error"] = str(e.reason) if e.reason else str(e.code)
        if e.headers:
            out["server"] = e.headers.get("Server")
            out["x_powered_by"] = e.headers.get("X-Powered-By")
            out["cookies"] = _parse_cookies(e.headers)
            out["hsts"] = parse_hsts(e.headers.get("Strict-Transport-Security"))
    except Exception as e:
        out["error"] = str(e)
    return out


def probe_alternate_schemes(host: str, open_ports: List[int], timeout: float = 5.0) -> Dict[str, Any]:
    """Trace redirects for http:// and https:// when ports suggest availability."""
    probes: Dict[str, Any] = {}
    if 80 in open_ports:
        probes["http"] = trace_redirects(f"http://{host}/", timeout=timeout)
    if 443 in open_ports:
        probes["https"] = trace_redirects(f"https://{host}/", timeout=timeout)
    return probes


def merge_transport_into_inventory(
    inv: Dict[str, Any],
    host: str,
    open_ports: List[int],
    timeout: float = 5.0,
) -> None:
    """Augment web_inventory dict with redirect chains, HSTS, cookie audit."""
    entry = inv.get("entry_url")
    if entry:
        inv["redirect_trace"] = trace_redirects(entry, timeout=timeout)
        final = inv["redirect_trace"].get("final_url") or entry
    else:
        final = inv.get("final_url")
        inv["redirect_trace"] = None

    inv["scheme_probes"] = probe_alternate_schemes(host, open_ports, timeout=timeout)

    # Prefer HSTS from HTTPS probe, then redirect trace, then existing response
    hsts = inv.get("hsts")
    https_probe = (inv.get("scheme_probes") or {}).get("https")
    if https_probe and https_probe.get("hsts"):
        hsts = https_probe["hsts"]
    elif inv.get("redirect_trace") and inv["redirect_trace"].get("hsts"):
        hsts = inv["redirect_trace"]["hsts"]
    inv["hsts"] = hsts

    final_url = inv.get("final_url") or final or entry or ""
    https = urlparse(final_url).scheme.lower() == "https"
    cookies = inv.get("cookies") or []
    audit = audit_cookies(cookies, https)
    inv["cookie_audit"] = audit
    inv["cookies_missing_secure_on_https"] = audit["cookies_missing_secure_on_https"]
    inv["cookies_missing_httponly"] = audit["cookies_missing_httponly"]
    inv["cookies_missing_samesite"] = audit["cookies_missing_samesite"]

    chain = (inv.get("redirect_trace") or {}).get("chain") or []
    inv["redirect_summary"] = " -> ".join(
        f"{h.get('status', '?')} {h.get('url', '')}" for h in chain[:8]
    ) if chain else None
