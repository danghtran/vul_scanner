"""
Filters for NVD keyword selection and CVE triage noise reduction.
"""
import re
from typing import Any, Dict, List, Optional, Set

# Reserved / demo host labels — never query NVD on these alone
_HOST_LABEL_BLOCKLIST = frozenset(
    {
        "example",
        "test",
        "demo",
        "localhost",
        "invalid",
        "local",
        "www",
        "mail",
        "ftp",
        "ns1",
        "ns2",
    }
)

# CDN/WAF-only stacks: no vendor product version to match CVEs against
CDN_WAF_MARKERS = frozenset(
    {
        "cloudflare",
        "akamai",
        "fastly",
        "incapsula",
        "imperva",
        "sucuri",
        "cloudfront",
        "varnish",
        "awselb",
    }
)

# Tokens scraped from HTTP error pages / headers — not products
_WEAK_BANNER_TOKENS = frozenset(
    {
        "cloudflare",
        "request",
        "html",
        "bad",
        "server",
        "content",
        "type",
        "connection",
        "close",
        "length",
        "date",
        "charset",
        "iso",
        "public",
        "title",
        "head",
        "body",
        "center",
        "address",
        "error",
        "document",
        "found",
        "not",
        "the",
        "requested",
        "url",
        "was",
        "on",
        "this",
        "port",
        "your",
        "browser",
        "sent",
        "that",
        "could",
        "understand",
        "additionally",
        "encountered",
        "while",
        "trying",
        "use",
        "handle",
        "hr",
        "ietf",
        "dtd",
        "en",
        "ray",
        "nginx",
        "apache",
        "httpd",
        "openssh",
        "ssh",
        "ubuntu",
        "debian",
        "linux",
        "http",
        "https",
        "ssl",
        "tls",
    }
)

# Single-word product names blocked when no versioned product keyword exists
_GENERIC_PRODUCT_BLOCKLIST = frozenset(
    {
        "ssh",
        "http",
        "https",
        "ssl",
        "tls",
        "httpd",
        "apache",
        "nginx",
        "openssh",
        "mysql",
        "mariadb",
        "postgres",
        "postgresql",
        "mongodb",
        "redis",
        "tomcat",
        "jetty",
        "iis",
        "openssl",
        "haproxy",
        "ubuntu",
        "debian",
        "linux",
        "cloudflare",
        "example",
        "admin",
        "server",
        "web",
        "site",
        "api",
        "app",
    }
)

# CVE summary markers that conflict with detected stack (product -> substrings)
_PRODUCT_CONFLICT_MARKERS: Dict[str, frozenset] = {
    "apache": frozenset(
        {
            "apache cxf",
            "cxf ",
            " cxf",
            "groovy",
            "windowmaker",
            "wmaker",
            "http server 1.3",
            "http server 1.2",
            "http server 1.1",
            "http server 1.0",
            "digi-news",
            "digi-ads",
            "wwwoffled",
        }
    ),
    "openssh": frozenset(
        {
            "groovy",
            "windowmaker",
            "internet explorer",
            "outlook express",
            "windowmaker",
        }
    ),
    "nginx": frozenset({"apache http server", "http server 1.", "internet explorer"}),
}

_VERSION_RE = re.compile(r"\d+\.\d+")


def scan_target_host(findings: Optional[dict]) -> str:
    if not findings:
        return ""
    raw = (findings.get("host") or findings.get("target") or "").strip()
    raw = raw.split("://", 1)[-1]
    raw = raw.split("/", 1)[0]
    raw = raw.split("@")[-1]
    if ":" in raw and not raw.startswith("["):
        host_part, maybe_port = raw.rsplit(":", 1)
        if maybe_port.isdigit():
            raw = host_part
    return raw.rstrip(".").lower()


def host_labels(host: str) -> Set[str]:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return set()
    labels = {host, host.split(":")[0]}
    parts = host.split(".")
    if parts:
        labels.add(parts[0])
    if len(parts) >= 2:
        labels.add(".".join(parts[-2:]))
    return {x for x in labels if x}


def is_hostname_noise_keyword(keyword: str, target_host: str) -> bool:
    kw = (keyword or "").strip().lower()
    if not kw:
        return True
    if kw in _HOST_LABEL_BLOCKLIST:
        return True
    labels = host_labels(target_host)
    if kw in labels:
        return True
    for label in labels:
        if label and len(label) >= 4 and kw == label.split(".")[0]:
            return True
    return False


def has_version_evidence(observations: List[dict]) -> bool:
    for obs in observations or []:
        if obs.get("parsed_version"):
            return True
        for entry in obs.get("nvd_keywords") or []:
            src = entry.get("source") or ""
            kw = (entry.get("keyword") or "").strip()
            if src in ("version", "inventory") and _VERSION_RE.search(kw):
                return True
    return False


def stack_is_cdn_opaque(findings: dict) -> bool:
    """True when front-end is CDN/WAF and no parsed service version exists."""
    if not findings:
        return False
    for obs in findings.get("observations") or []:
        if obs.get("parsed_version"):
            return False
    for _port, banner in (findings.get("port_banners") or {}).items():
        if parse_banner_version_hint(banner):
            return False
    blobs: List[str] = []
    for banner in (findings.get("port_banners") or {}).values():
        blobs.append(str(banner or "").lower())
    wi = findings.get("web_inventory") or {}
    if wi.get("server"):
        blobs.append(str(wi["server"]).lower())
    for h in wi.get("tech_hints") or []:
        blobs.append(str(h).lower())
    text = " ".join(blobs)
    if not text:
        return False
    if any(m in text for m in CDN_WAF_MARKERS):
        return True
    return False


def parse_banner_version_hint(banner: str) -> bool:
    try:
        from version_extract import parse_banner_version

        return parse_banner_version(banner or "") is not None
    except Exception:
        return False


def filter_banner_token(token: str, target_host: str) -> bool:
    """Return True if token is acceptable for NVD banner_token source."""
    tok = (token or "").strip().lower()
    if not tok or len(tok) < 3 or len(tok) > 48:
        return False
    if tok in _WEAK_BANNER_TOKENS:
        return False
    if is_hostname_noise_keyword(tok, target_host):
        return False
    if not re.match(r"^[a-z][a-z0-9+.-]*$", tok):
        return False
    return True


def should_skip_nvd_keyword(
    keyword: str,
    source: str,
    *,
    target_host: str = "",
    has_version_evidence: bool = False,
    cdn_opaque: bool = False,
) -> bool:
    kw = (keyword or "").strip()
    if not kw or len(kw) > 120:
        return True
    kl = kw.lower()
    src = source or ""

    if is_hostname_noise_keyword(kw, target_host):
        return True

    if cdn_opaque and src in ("port_hint", "banner_token", "inventory"):
        if src == "inventory" and _VERSION_RE.search(kw):
            return False
        if not _VERSION_RE.search(kw):
            return True

    if not has_version_evidence:
        if src in ("header", "tls"):
            return True
        if src == "port_hint":
            return True
        if kl in _GENERIC_PRODUCT_BLOCKLIST and " " not in kw:
            return True
        if src == "banner_token":
            return True

    if has_version_evidence and src in ("header", "tls"):
        return True

    if has_version_evidence and kl in _GENERIC_PRODUCT_BLOCKLIST and " " not in kw:
        if src in ("banner_token", "port_hint", "inventory"):
            return True

    return False


def summary_conflicts_with_products(summary: str, products: Set[str]) -> bool:
    if not summary or not products:
        return False
    s = summary.lower()
    for prod in products:
        markers = _PRODUCT_CONFLICT_MARKERS.get(prod)
        if not markers:
            continue
        for marker in markers:
            if marker in s:
                return True
    return False
