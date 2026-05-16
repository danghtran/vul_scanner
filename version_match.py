"""
Compare installed product versions (from banners/inventory) to version hints in CVE text.
Used to down-rank CVEs that clearly do not apply to the observed version.
"""
import re
from typing import Any, Dict, List, Optional, Tuple

from version_extract import parse_banner_version

# (regex, constraint kind) — kind defines comparison semantics
_MAX_EXCLUSIVE = [
    re.compile(r"\bbefore\s+([\d]+(?:\.[\d]+)*(?:p\d+)?)", re.I),
    re.compile(r"\bprior to\s+(?:version\s+)?([\d]+(?:\.[\d]+)*(?:p\d+)?)", re.I),
    re.compile(r"\bearlier than\s+([\d]+(?:\.[\d]+)*(?:p\d+)?)", re.I),
]
_MAX_INCLUSIVE = [
    re.compile(r"([\d]+(?:\.[\d]+)*(?:p\d+)?)\s+and earlier", re.I),
    re.compile(r"\bthrough\s+([\d]+(?:\.[\d]+)*(?:p\d+)?)", re.I),
    re.compile(r"\bup to and including\s+([\d]+(?:\.[\d]+)*(?:p\d+)?)", re.I),
    re.compile(r"\bversion[s]?\s+([\d]+(?:\.[\d]+)*(?:p\d+)?)\s+and earlier", re.I),
]

_PRODUCT_IN_SUMMARY = {
    "openssh": (r"openssh", r"\bssh\b", r"\bssh\s+\d", r"\bssh\s+client", r"\bssh\s+daemon"),
    "apache": (r"\bapache", r"httpd", r"\bwww server"),
    "nginx": (r"\bnginx",),
    "mysql": (r"\bmysql", r"\bmariadb"),
    "iis": (r"\biis\b", r"internet information services"),
    "openssl": (r"\bopenssl",),
}


def version_tuple(token: str) -> Tuple[int, ...]:
    """Numeric tuple for ordering; OpenSSH 6.6.1p1 -> (6, 6, 1, 1) (pN as extra segment)."""
    if not token:
        return (0,)
    t = token.strip().lower()
    m = re.match(r"^([\d]+(?:\.[\d]+)*)(p(\d+))?$", t)
    if m:
        base = m.group(1)
        parts = [int(x) for x in base.split(".") if x.isdigit()]
        if m.group(3):
            parts.append(int(m.group(3)))
        return tuple(parts) if parts else (0,)
    nums = [int(x) for x in re.findall(r"\d+", t)]
    return tuple(nums) if nums else (0,)


def _compare(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a_pad = a + (0,) * (n - len(a))
    b_pad = b + (0,) * (n - len(b))
    if a_pad < b_pad:
        return -1
    if a_pad > b_pad:
        return 1
    return 0


def _summary_mentions_product(summary: str, product: str) -> bool:
    s = summary.lower()
    for pat in _PRODUCT_IN_SUMMARY.get(product, (product,)):
        if re.search(pat, s):
            return True
    return False


def extract_version_constraint(summary: str, product: str) -> Optional[Dict[str, Any]]:
    """Parse a coarse upper-bound from CVE description text."""
    if not summary or not _summary_mentions_product(summary, product):
        return None
    for rx in _MAX_EXCLUSIVE:
        m = rx.search(summary)
        if m:
            ver = m.group(1)
            return {
                "bound": version_tuple(ver),
                "bound_token": ver,
                "kind": "max_exclusive",
                "text": f"before {ver}",
            }
    for rx in _MAX_INCLUSIVE:
        m = rx.search(summary)
        if m:
            ver = m.group(1)
            return {
                "bound": version_tuple(ver),
                "bound_token": ver,
                "kind": "max_inclusive",
                "text": f"{ver} and earlier",
            }
    return None


def compare_installed_to_constraint(
    installed: Tuple[int, ...], constraint: Dict[str, Any]
) -> str:
    """
    Return not_affected | likely_affected | unknown.
    max_exclusive: affected if installed < bound
    max_inclusive: affected if installed <= bound
    """
    bound = constraint.get("bound")
    if not bound:
        return "unknown"
    kind = constraint.get("kind")
    cmp = _compare(installed, bound)
    if kind == "max_exclusive":
        if cmp >= 0:
            return "not_affected"
        return "likely_affected"
    if kind == "max_inclusive":
        if cmp > 0:
            return "not_affected"
        return "likely_affected"
    return "unknown"


def collect_installed_versions(findings: dict) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: set = set()

    def add(product: str, token: str, observation_id: Optional[str] = None) -> None:
        product = (product or "").lower().strip()
        token = (token or "").strip()
        if not product or not token:
            return
        key = (product, token.lower())
        if key in seen:
            return
        seen.add(key)
        out.append(
            {
                "product": product,
                "version_token": token,
                "version_tuple": version_tuple(token),
                "observation_id": observation_id,
            }
        )

    for obs in findings.get("observations") or []:
        pv = obs.get("parsed_version")
        if pv:
            add(pv.get("product"), pv.get("version_token"), obs.get("id"))

    wi = findings.get("web_inventory") or {}
    for hint in wi.get("tech_hints") or []:
        pv = parse_banner_version(str(hint))
        if pv:
            add(pv["product"], pv["version_token"], "web-inventory")
    if wi.get("server"):
        pv = parse_banner_version(str(wi["server"]))
        if pv:
            add(pv["product"], pv["version_token"], "web-inventory")

    for _port, banner in (findings.get("port_banners") or {}).items():
        pv = parse_banner_version(banner or "")
        if pv:
            add(pv["product"], pv["version_token"], f"tcp-{_port}")

    return out


def assess_version_match(cve: dict, installed: List[Dict[str, Any]]) -> Tuple[str, str]:
    """
    Returns (version_match, reason).
    version_match: not_applicable | likely_affected | unknown
    """
    summary = cve.get("summary") or ""
    if not summary or not installed:
        return "unknown", ""

    not_applicable_reason = None
    likely_reason = None

    for inst in installed:
        product = inst["product"]
        if not _summary_mentions_product(summary, product):
            continue
        constraint = extract_version_constraint(summary, product)
        if not constraint:
            continue
        verdict = compare_installed_to_constraint(inst["version_tuple"], constraint)
        token = inst["version_token"]
        if verdict == "not_affected":
            not_applicable_reason = (
                f"installed {product} {token} is newer than CVE affected range ({constraint['text']})"
            )
            break
        if verdict == "likely_affected":
            likely_reason = (
                f"installed {product} {token} falls within CVE affected range ({constraint['text']})"
            )

    if not_applicable_reason:
        return "not_applicable", not_applicable_reason
    if likely_reason:
        return "likely_affected", likely_reason
    return "unknown", ""
