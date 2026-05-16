"""Normalize raw scan artifacts into observations with NVD keyword provenance."""
import re
from typing import Any, Dict, List, Set, Tuple

from cve_keyword_extract import HEADER_TEMPLATES, PORT_PRODUCT_HINTS
from inventory_context import slim_web_inventory_evidence
from nvd_noise import (
    CDN_WAF_MARKERS,
    filter_banner_token,
    scan_target_host,
    stack_is_cdn_opaque,
)
from version_extract import parse_banner_version

# Best keyword source wins for dedupe: higher index = stronger signal for validation
_SOURCE_RANK = {"version": 4, "banner_token": 3, "inventory": 3, "port_hint": 2, "tls": 1, "header": 1}

_TLS_EVIDENCE_KEYS = frozenset(
    {
        "expires",
        "days_left",
        "self_signed",
        "tls_version",
        "cipher",
        "legacy_tls_enabled",
        "protocols_accepted",
        "hostname_matches_cert",
        "handshake_ok",
        "handshake_error",
        "san_dns",
        "subject",
        "issuer",
        "serial_number",
        "host",
        "port",
    }
)


def _merge_keyword_sources(items: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    best: Dict[str, str] = {}
    for kw, src in items:
        kw = (kw or "").strip()
        if not kw or len(kw) > 120:
            continue
        prev = best.get(kw)
        if not prev or _SOURCE_RANK.get(src, 0) > _SOURCE_RANK.get(prev, 0):
            best[kw] = src
    return [(k, best[k]) for k in sorted(best.keys())]


def _tls_keywords(tls: dict) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if not tls:
        return out
    days_left = tls.get("days_left")
    if isinstance(days_left, (int, float)):
        if days_left < 0:
            for tpl in ("expired tls", "expired certificate", "expired ssl"):
                out.append((tpl, "tls"))
        elif days_left < 30:
            for tpl in ("near expiry tls", "certificate near expiry", "soon-to-expire tls"):
                out.append((tpl, "tls"))
    if tls.get("self_signed"):
        for tpl in ("self-signed certificate", "self-signed tls"):
            out.append((tpl, "tls"))
    if tls.get("legacy_tls_enabled"):
        for tpl in ("tls 1.0", "tls 1.1", "deprecated tls protocol", "weak tls"):
            out.append((tpl, "tls"))
    if tls.get("hostname_matches_cert") is False:
        for tpl in ("certificate name mismatch", "hostname certificate mismatch"):
            out.append((tpl, "tls"))
    cipher = tls.get("cipher") if isinstance(tls.get("cipher"), dict) else {}
    name = (cipher.get("name") or "").upper()
    for bad in ("RC4", "DES", "MD5", "NULL", "EXPORT"):
        if bad in name:
            out.append(("weak tls cipher", "tls"))
            break
    if tls.get("handshake_error") and not tls.get("handshake_ok"):
        out.append(("tls handshake failure", "tls"))
    return out


def _header_keywords(headers: dict) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for header, val in (headers or {}).items():
        if val:
            continue
        for tpl in HEADER_TEMPLATES.get(header, ()):
            out.append((tpl, "header"))
    return out


_BANNER_NOISE = frozenset(
    {
        "ssh",
        "http",
        "https",
        "ssl",
        "tls",
        "ubuntu",
        "debian",
        "linux",
        "protocol",
        "openssh",
    }
)


def _port_keywords(
    port: int,
    banner: str,
    *,
    target_host: str = "",
    cdn_opaque: bool = False,
) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    pv = parse_banner_version(banner) if banner else None
    if pv:
        product = pv["product"]
        ver = pv["version_token"]
        out.append((f"{product} {ver}".strip(), "version"))
        out.append((product, "version"))
        m = re.match(r"(\d+\.\d+)", ver or "")
        if m:
            out.append((f"{product} {m.group(1)}", "version"))
    elif not cdn_opaque:
        hints = PORT_PRODUCT_HINTS.get(port, ())
        if hints:
            out.append((hints[0], "port_hint"))
        if banner:
            bl = banner.lower()
            for tok in re.findall(r"[a-z][a-z0-9+.-]{2,}", bl):
                if tok in _BANNER_NOISE:
                    continue
                if filter_banner_token(tok, target_host):
                    out.append((tok, "banner_token"))
    return _merge_keyword_sources(out)


def _inventory_keywords(web: dict) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if not web:
        return out
    seen_version: Set[str] = set()

    def add_versioned(product: str, ver: str) -> None:
        combo = f"{product} {ver}".strip()
        if combo.lower() not in seen_version:
            seen_version.add(combo.lower())
            out.append((combo, "inventory"))
        if product.lower() not in seen_version:
            seen_version.add(product.lower())
            out.append((product, "inventory"))
        m = re.match(r"(\d+\.\d+)", ver or "")
        if m:
            minor = f"{product} {m.group(1)}"
            if minor.lower() not in seen_version:
                seen_version.add(minor.lower())
                out.append((minor, "inventory"))

    if web.get("server"):
        pv = parse_banner_version(str(web["server"]))
        if pv:
            add_versioned(pv["product"], pv["version_token"])

    for h in web.get("tech_hints") or []:
        pv = parse_banner_version(str(h))
        if pv:
            add_versioned(pv["product"], pv["version_token"])
            continue
        t = str(h).strip()
        if not t or len(t) > 80:
            continue
        tl = t.lower()
        if tl in _BANNER_NOISE or tl in CDN_WAF_MARKERS or tl in seen_version:
            continue
        if "/" in t or re.search(r"\d+\.\d+", t):
            out.append((t, "inventory"))

    gen = web.get("generator")
    if gen:
        g = str(gen).strip()[:80]
        if g and g.lower() not in seen_version:
            out.append((g, "inventory"))

    return _merge_keyword_sources(out)


def build_observations(findings: dict) -> List[Dict[str, Any]]:
    """Structured observations: each carries nvd_keywords as list of {keyword, source}."""
    observations: List[Dict[str, Any]] = []
    target_host = scan_target_host(findings)
    cdn_opaque = stack_is_cdn_opaque(findings)
    banners = findings.get("port_banners") or {}

    for p in findings.get("open_ports") or []:
        port = int(p)
        raw = banners.get(port)
        if raw is None:
            raw = banners.get(str(port))
        banner = raw or ""
        pv = parse_banner_version(banner) if banner else None
        tuples_kw = _port_keywords(
            port, banner, target_host=target_host, cdn_opaque=cdn_opaque
        )
        nvd_keywords = [{"keyword": k, "source": s} for k, s in tuples_kw]
        observations.append(
            {
                "id": f"tcp-{port}",
                "category": "tcp_service",
                "port": port,
                "evidence": {"banner": banner[:2000]},
                "parsed_version": pv,
                "nvd_keywords": nvd_keywords,
            }
        )

    tls_by_port = findings.get("tls_by_port") or {}
    if not tls_by_port and findings.get("tls"):
        tls_by_port = {443: findings.get("tls")}
    for tls_port, tls in tls_by_port.items():
        if not tls:
            continue
        tls_tuples = _tls_keywords(tls)
        observations.append(
            {
                "id": f"tls-{tls_port}",
                "category": "tls_certificate",
                "port": int(tls_port),
                "evidence": {k: v for k, v in tls.items() if k in _TLS_EVIDENCE_KEYS},
                "parsed_version": None,
                "nvd_keywords": [{"keyword": k, "source": s} for k, s in _merge_keyword_sources(tls_tuples)],
            }
        )

    headers = findings.get("http_headers")
    if headers is not None:
        hdr_tuples = _header_keywords(headers)
        observations.append(
            {
                "id": "http-headers",
                "category": "http_headers",
                "port": None,
                "evidence": {"headers": headers},
                "parsed_version": None,
                "nvd_keywords": [{"keyword": k, "source": s} for k, s in _merge_keyword_sources(hdr_tuples)],
            }
        )

    dns = findings.get("dns_context")
    if dns:
        observations.append(
            {
                "id": "dns-host",
                "category": "dns_context",
                "port": None,
                "evidence": {
                    "host": dns.get("host"),
                    "ipv4": dns.get("ipv4"),
                    "ipv6": dns.get("ipv6"),
                    "error": dns.get("error"),
                    "mx": (dns.get("mx") or [])[:8],
                    "spf": dns.get("spf"),
                    "dmarc": dns.get("dmarc"),
                    "caa": (dns.get("caa") or [])[:6],
                    "asset_context": dns.get("asset_context"),
                },
                "parsed_version": None,
                "nvd_keywords": [],
            }
        )

    web = findings.get("web_inventory")
    if web:
        tuples = _inventory_keywords(web)
        web_pv = None
        if web.get("server"):
            web_pv = parse_banner_version(str(web["server"]))
        observations.append(
            {
                "id": "web-inventory",
                "category": "web_inventory",
                "port": None,
                "evidence": slim_web_inventory_evidence(web),
                "parsed_version": web_pv,
                "nvd_keywords": [
                    {"keyword": k, "source": s} for k, s in _merge_keyword_sources(tuples)
                ],
            }
        )

    return observations
