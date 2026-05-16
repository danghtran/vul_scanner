"""
Passive inventory and context: DNS resolution, robots.txt, security.txt,
and light HTTP fingerprinting (headers, cookies, HTML hints).
Read-only; size- and time-bounded.
"""
import re
import socket
import time
from typing import Any, Dict, List, Optional
from urllib import error, request
from urllib.parse import urljoin, urlparse

USER_AGENT = "Vul-Scanner/1.0 (inventory)"
DEFAULT_TIMEOUT = 5
ROBOTS_MAX = 16384
SECURITY_MAX = 16384
BODY_MAX = 65536


def gather_dns_context(hostname: str) -> Dict[str, Any]:
    """IPv4/IPv6 addresses for hostname via getaddrinfo (stdlib)."""
    out: Dict[str, Any] = {"host": hostname, "ipv4": [], "ipv6": [], "error": None}
    if not hostname:
        out["error"] = "empty_host"
        return out
    seen4, seen6 = set(), set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            ip = sockaddr[0]
            if family == socket.AF_INET:
                if ip not in seen4:
                    seen4.add(ip)
                    out["ipv4"].append(ip)
            elif family == socket.AF_INET6:
                if ip not in seen6:
                    seen6.add(ip)
                    out["ipv6"].append(ip)
    except socket.gaierror as e:
        out["error"] = str(e)
    except OSError as e:
        out["error"] = str(e)
    return out


def _fetch_limited(
    url: str, max_bytes: int, timeout: float
) -> Dict[str, Any]:
    req = request.Request(url, headers={"User-Agent": USER_AGENT})
    result: Dict[str, Any] = {
        "url": url,
        "ok": False,
        "final_url": None,
        "status": None,
        "preview": None,
        "truncated": False,
        "error": None,
    }
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            result["final_url"] = resp.geturl()
            result["status"] = resp.getcode()
            raw = resp.read(max_bytes + 1)
            if len(raw) > max_bytes:
                result["truncated"] = True
                raw = raw[:max_bytes]
            text = raw.decode("utf-8", errors="replace")
            result["preview"] = text[:12000]
            result["ok"] = True
    except error.HTTPError as e:
        result["status"] = e.code
        try:
            raw = e.read(min(max_bytes, 8192))
            result["preview"] = raw.decode("utf-8", errors="replace")[:12000]
        except Exception:
            pass
        result["error"] = str(e.reason) if e.reason else str(e.code)
    except Exception as e:
        result["error"] = str(e)
    return result


def _parse_cookies(msg) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    raw_list = []
    if hasattr(msg, "get_all"):
        raw_list = msg.get_all("Set-Cookie", []) or []
    elif hasattr(msg, "get"):
        v = msg.get("Set-Cookie")
        if v:
            raw_list = [v]
    for chunk in raw_list:
        if not chunk:
            continue
        lower = chunk.lower()
        name = ""
        if "=" in chunk:
            name = chunk.split(";", 1)[0].split("=", 1)[0].strip()
        samesite = None
        m = re.search(r"samesite\s*=\s*([^;]+)", chunk, re.I)
        if m:
            samesite = m.group(1).strip()
        secure = bool(re.search(r"(^|;\s*)secure(\s|;|$)", chunk, re.I))
        httponly = bool(re.search(r"(^|;\s*)httponly(\s|;|$)", chunk, re.I))
        out.append(
            {
                "name": name or None,
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite,
                "preview": chunk[:240],
            }
        )
    return out


def _tech_from_html(html: str) -> Dict[str, Any]:
    hints: List[str] = []
    generator = ""
    m = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
        html,
        re.I,
    )
    if m:
        generator = m.group(1).strip()
        if generator:
            hints.append(generator)
    low = html.lower()
    markers = (
        ("WordPress", "wp-content" in low or "wp-includes" in low or "/wordpress/" in low),
        ("Drupal", "drupal" in low or "/sites/default/" in low),
        ("Joomla", "joomla!" in low or "/media/jui/" in low),
        ("React", "react-dom" in low or 'id="root"' in low and "react" in low),
        ("Next.js", "__next_data__" in low or "_next/static" in low),
        ("Vue.js", "__vue__" in low or "vue.js" in low),
        ("Angular", "ng-version" in low or "angular.js" in low),
        (
            "Django",
            "csrfmiddlewaretoken" in low or "__django" in low,
        ),
        ("Laravel", "laravel_session" in low or "xsrf-token" in low and "laravel" in low),
        ("Bootstrap", "bootstrap.min.css" in low or "bootstrap.min.js" in low),
        ("jQuery", "jquery.min.js" in low or "/jquery-" in low),
    )
    for label, cond in markers:
        if cond and label not in hints:
            hints.append(label)
    m2 = re.search(r"php/([\d.]+)", low)
    if m2:
        hints.append(f"PHP {m2.group(1)}")
    return {"generator": generator, "tech_hints": _uniq_keep_order(hints)}


def _uniq_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        k = x.strip()
        if not k or k.lower() in seen:
            continue
        seen.add(k.lower())
        out.append(k)
    return out


def _server_tokens(server_val: Optional[str]) -> List[str]:
    if not server_val:
        return []
    hints = [server_val.strip()]
    low = server_val.lower()
    m = re.search(r"nginx/([\d.]+)", low)
    if m:
        hints.extend(["nginx", f"nginx {m.group(1)}"])
    m = re.search(r"apache/([\d.]+)", low, re.I)
    if m:
        hints.extend(["apache", f"apache {m.group(1)}"])
    m = re.search(r"microsoft-iis/([\d.]+)", low, re.I)
    if m:
        hints.extend(["iis", f"iis {m.group(1)}"])
    m = re.search(r"cloudflare", low)
    if m:
        hints.append("cloudflare")
    return _uniq_keep_order(hints)


def _is_https_url(url: str) -> bool:
    try:
        return urlparse(url).scheme.lower() == "https"
    except Exception:
        return False


def gather_web_inventory(
    base_url: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_body: int = BODY_MAX,
    host: Optional[str] = None,
    open_ports: Optional[List[int]] = None,
    request_delay: float = 0,
) -> Optional[Dict[str, Any]]:
    """
    Fetch homepage (bounded body), Server / X-Powered-By, Set-Cookie flags,
    robots.txt and security.txt. base_url should end with / or be a full origin URL.
    """
    if not base_url or not base_url.startswith(("http://", "https://")):
        return None
    parsed = urlparse(base_url)
    if not parsed.netloc:
        return None
    if not base_url.endswith("/"):
        base_url = base_url + "/"
    origin = f"{parsed.scheme}://{parsed.netloc}"

    if request_delay > 0:
        time.sleep(request_delay)

    inv: Dict[str, Any] = {
        "entry_url": base_url,
        "final_url": None,
        "http_status": None,
        "server": None,
        "x_powered_by": None,
        "cookies": [],
        "cookies_missing_secure_on_https": False,
        "generator": None,
        "tech_hints": [],
        "robots_txt": None,
        "security_txt": None,
        "fetch_error": None,
        "redirect_trace": None,
        "scheme_probes": None,
        "hsts": None,
        "cookie_audit": None,
        "redirect_summary": None,
    }

    req = request.Request(base_url, headers={"User-Agent": USER_AGENT})
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            inv["final_url"] = resp.geturl()
            inv["http_status"] = resp.getcode()
            inv["server"] = resp.headers.get("Server")
            inv["x_powered_by"] = resp.headers.get("X-Powered-By")
            inv["cookies"] = _parse_cookies(resp.headers)
            inv["hsts"] = None
            try:
                from http_transport import parse_hsts

                inv["hsts"] = parse_hsts(resp.headers.get("Strict-Transport-Security"))
            except ImportError:
                pass
            raw = resp.read(max_body + 1)
            truncated = len(raw) > max_body
            if truncated:
                raw = raw[:max_body]
            html = raw.decode("utf-8", errors="replace")
            tech = _tech_from_html(html)
            inv["generator"] = tech.get("generator") or None
            inv["tech_hints"] = tech.get("tech_hints") or []
            http_hints = []
            if inv["server"]:
                http_hints.extend(_server_tokens(inv["server"]))
            if inv["x_powered_by"]:
                for part in re.split(r"[\s,]+", inv["x_powered_by"]):
                    p = part.strip()
                    if p and len(p) < 80:
                        http_hints.append(p)
            inv["tech_hints"] = _uniq_keep_order(inv["tech_hints"] + http_hints)

    except error.HTTPError as e:
        inv["http_status"] = e.code
        inv["fetch_error"] = str(e.reason) if e.reason else str(e.code)
        try:
            if e.headers:
                inv["server"] = e.headers.get("Server")
                inv["x_powered_by"] = e.headers.get("X-Powered-By")
                inv["cookies"] = _parse_cookies(e.headers)
                try:
                    from http_transport import parse_hsts

                    inv["hsts"] = parse_hsts(e.headers.get("Strict-Transport-Security"))
                except ImportError:
                    pass
        except Exception:
            pass
    except Exception as e:
        inv["fetch_error"] = str(e)

    inv["robots_txt"] = _fetch_limited(urljoin(origin + "/", "robots.txt"), ROBOTS_MAX, timeout)
    if request_delay > 0:
        time.sleep(request_delay)
    sec_paths = (
        urljoin(origin + "/", ".well-known/security.txt"),
        urljoin(origin + "/", "security.txt"),
    )
    inv["security_txt"] = None
    for sp in sec_paths:
        doc = _fetch_limited(sp, SECURITY_MAX, timeout)
        if doc.get("ok") or doc.get("status") == 200:
            doc["source_path"] = sp
            inv["security_txt"] = doc
            break
    if inv["security_txt"] is None:
        inv["security_txt"] = {"found": False, "attempted": list(sec_paths)}

    inv["cookie_count"] = len(inv.get("cookies") or [])

    if host and open_ports is not None:
        try:
            from http_transport import merge_transport_into_inventory

            merge_transport_into_inventory(inv, host, open_ports, timeout=timeout)
        except ImportError:
            https = _is_https_url(inv.get("final_url") or base_url)
            for c in inv.get("cookies") or []:
                if https and c.get("name") and not c.get("secure"):
                    inv["cookies_missing_secure_on_https"] = True
                    break
    else:
        https = _is_https_url(inv.get("final_url") or base_url)
        for c in inv.get("cookies") or []:
            if https and c.get("name") and not c.get("secure"):
                inv["cookies_missing_secure_on_https"] = True
                break

    return inv


def resolve_inventory_base_url(host: str, scheme: Optional[str], open_ports: List[int], target: str) -> Optional[str]:
    """Prefer HTTPS when 443 is open, else HTTP; honor full URL target when provided."""
    if scheme and target.startswith("http"):
        u = urlparse(target)
        path = u.path or "/"
        if not path.endswith("/"):
            path = path + "/"
        return f"{u.scheme}://{u.netloc}{path}"
    for p, scheme in ((443, "https"), (8443, "https"), (8080, "http"), (8000, "http"), (8888, "http"), (80, "http")):
        if p in open_ports:
            return f"{scheme}://{host}/"
    return None


def slim_web_inventory_evidence(web: Dict[str, Any]) -> Dict[str, Any]:
    """Trim large fields for observations / JSON readability."""
    r: Dict[str, Any] = {}
    for k in (
        "entry_url",
        "final_url",
        "http_status",
        "server",
        "x_powered_by",
        "generator",
        "tech_hints",
        "cookies_missing_secure_on_https",
        "cookies_missing_httponly",
        "cookies_missing_samesite",
        "redirect_summary",
        "hsts",
        "fetch_error",
    ):
        if k in web:
            r[k] = web[k]
    r["cookie_count"] = len(web.get("cookies") or [])
    ca = web.get("cookie_audit")
    if isinstance(ca, dict):
        r["cookie_audit"] = {
            "missing_secure": ca.get("missing_secure", [])[:5],
            "missing_httponly": ca.get("missing_httponly", [])[:5],
            "missing_samesite": ca.get("missing_samesite", [])[:5],
        }
    rt = web.get("robots_txt")
    if isinstance(rt, dict):
        r["robots_txt"] = {
            "ok": rt.get("ok"),
            "status": rt.get("status"),
            "preview": (rt.get("preview") or "")[:1200],
            "truncated": rt.get("truncated"),
        }
    st = web.get("security_txt")
    if isinstance(st, dict) and st.get("found") is False:
        r["security_txt"] = {"found": False}
    elif isinstance(st, dict):
        r["security_txt"] = {
            "ok": st.get("ok"),
            "status": st.get("status"),
            "source_path": st.get("source_path"),
            "preview": (st.get("preview") or "")[:1200],
            "truncated": st.get("truncated"),
        }
    return r
