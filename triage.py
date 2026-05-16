"""
Triage: configuration findings, CVE relevance scoring, unified action queue.
"""
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from prioritize import build_rationale, compute_priority_score, tier_from_score

# Products seen in CVE text that conflict with detected stack (keyword noise)
_UNRELATED_PRODUCTS = frozenset(
    {
        "iis",
        "internet information services",
        "nginx",
        "microsoft-iis",
        "firefox",
        "zammad",
        "mantisbt",
        "mantis",
        "icq",
        "abb esoms",
        "esoms",
        "sendmail",
        "irc client",
        "ircii",
        "tcp wrappers",
        "wu-ftpd",
        "wuftpd",
        "util-linux",
    }
)

_PRODUCT_ALIASES = {
    "openssh": ("openssh", "ssh"),
    "ssh": ("openssh", "ssh"),
    "apache": ("apache", "httpd", "apache http"),
    "httpd": ("apache", "httpd"),
    "nginx": ("nginx",),
    "mysql": ("mysql", "mariadb"),
    "mariadb": ("mysql", "mariadb"),
    "openssl": ("openssl",),
    "iis": ("iis", "internet information services"),
}


def _detected_products(findings: dict) -> Set[str]:
    products: Set[str] = set()
    for obs in findings.get("observations") or []:
        pv = obs.get("parsed_version")
        if pv and pv.get("product"):
            products.add(str(pv["product"]).lower())
    wi = findings.get("web_inventory") or {}
    for h in wi.get("tech_hints") or []:
        hl = str(h).lower()
        if "apache" in hl:
            products.add("apache")
        if "nginx" in hl:
            products.add("nginx")
        if "openssh" in hl or hl.startswith("ssh"):
            products.add("openssh")
        if "iis" in hl:
            products.add("iis")
    for p, banner in (findings.get("port_banners") or {}).items():
        bl = (banner or "").lower()
        if "openssh" in bl:
            products.add("openssh")
        if "apache" in bl:
            products.add("apache")
        if "nginx" in bl:
            products.add("nginx")
    return products


def _summary_mentions_product(summary: str, products: Set[str]) -> bool:
    if not summary or not products:
        return False
    s = summary.lower()
    for prod in products:
        for alias in _PRODUCT_ALIASES.get(prod, (prod,)):
            if alias in s:
                return True
    return False


def _summary_mentions_unrelated(summary: str, products: Set[str]) -> bool:
    if not summary:
        return False
    s = summary.lower()
    for marker in _UNRELATED_PRODUCTS:
        if marker not in s:
            continue
        # nginx CVE on apache host is unrelated
        if marker == "nginx" and "nginx" in products:
            continue
        if marker in ("iis", "internet information services", "microsoft-iis") and "iis" in products:
            continue
        if marker in s:
            return True
    return False


def assess_cve_relevance(cve: dict, products: Set[str]) -> Tuple[str, str]:
    """
    Returns (relevance: high|medium|low, reason).
    """
    summary = (cve.get("summary") or "").lower()
    val = cve.get("validation_status") or "potential"
    sources = {h.get("source") for h in (cve.get("evidence_hits") or []) if h.get("source")}

    if not summary:
        return "low", "no CVE description to validate product match"

    if products and _summary_mentions_unrelated(summary, products):
        return "low", "CVE description targets a different product than observed on host"

    if val == "heuristic" and sources <= {"header", "tls"}:
        if not _summary_mentions_product(summary, products):
            return "low", "keyword match from header/TLS template; CVE text does not reference observed stack"

    if products and _summary_mentions_product(summary, products):
        if val == "corroborated":
            return "high", "banner or version evidence aligns with CVE affected product"
        return "medium", "CVE description references observed product; confirm version range"

    if val == "corroborated":
        return "medium", "strong keyword match; verify CVE applies to installed version"

    if "port_hint" in sources and not products:
        return "low", "generic port-based keyword only"

    return "low", "weak or generic NVD keyword association"


def _relevance_multiplier(relevance: str) -> float:
    return {"high": 1.0, "medium": 0.72, "low": 0.35}.get(relevance, 0.35)


def enrich_cve_triage(cve: dict, products: Set[str], ctx: dict) -> dict:
    relevance, rel_reason = assess_cve_relevance(cve, products)
    base = compute_priority_score(
        cve.get("cvss"),
        cve.get("known_exploited"),
        cve.get("validation_status"),
        ctx,
    )
    adjusted = round(base * _relevance_multiplier(relevance), 2)
    tier = tier_from_score(adjusted)
    rationale = build_rationale(
        cve.get("cvss"),
        cve.get("known_exploited"),
        cve.get("validation_status"),
        ctx,
    )
    rationale = f"{rationale}; relevance: {relevance} ({rel_reason})"
    out = {**cve}
    out["relevance"] = relevance
    out["relevance_reason"] = rel_reason
    out["priority_score"] = adjusted
    out["priority_tier"] = tier
    out["priority_rationale"] = rationale
    if relevance == "high" and cve.get("known_exploited"):
        out["recommended_action"] = "Patch or mitigate immediately; CISA KEV with strong product match"
    elif relevance == "high":
        out["recommended_action"] = "Validate affected component version, then patch per vendor advisory"
    elif relevance == "medium":
        out["recommended_action"] = "Confirm version in banner or inventory, then prioritize patch if in range"
    else:
        out["recommended_action"] = "Review manually; likely false positive from keyword search"
    return out


def _cfg_item(
    item_id: str,
    title: str,
    severity: str,
    score: float,
    action: str,
    observation_ids: List[str],
    evidence: dict,
) -> dict:
    tier = tier_from_score(score)
    return {
        "id": item_id,
        "item_type": "configuration",
        "category": "misconfiguration",
        "title": title,
        "severity": severity,
        "priority_score": score,
        "priority_tier": tier,
        "priority_rationale": f"configuration finding; severity {severity}",
        "recommended_action": action,
        "observation_ids": observation_ids,
        "evidence": evidence,
        "relevance": "confirmed",
        "relevance_reason": "direct observation from scan",
    }


def build_config_findings(findings: dict, ctx: dict) -> List[dict]:
    items: List[dict] = []
    boost = 28.0 if ctx.get("internet_facing") else 0.0
    prod_boost = 18.0 if (ctx.get("environment") or "").lower() == "prod" else 0.0
    extra = boost + prod_boost

    tls = findings.get("tls")
    if tls:
        if tls.get("handshake_error") and not tls.get("handshake_ok"):
            items.append(
                _cfg_item(
                    "cfg-tls-handshake-failed",
                    "TLS handshake failed or could not be assessed",
                    "high",
                    140.0 + extra,
                    "Verify port 443 reachability, certificate chain, and firewall path",
                    ["tls-443"],
                    {"error": tls.get("handshake_error")},
                )
            )
        if tls.get("handshake_ok"):
            if isinstance(tls.get("days_left"), (int, float)) and tls["days_left"] < 0:
                items.append(
                    _cfg_item(
                        "cfg-tls-expired",
                        "TLS certificate is expired",
                        "critical",
                        200.0 + extra,
                        "Renew certificate immediately",
                        ["tls-443"],
                        {"days_left": tls["days_left"], "expires": tls.get("expires")},
                    )
                )
            elif isinstance(tls.get("days_left"), (int, float)) and tls["days_left"] < 30:
                items.append(
                    _cfg_item(
                        "cfg-tls-expiring-soon",
                        "TLS certificate expires within 30 days",
                        "medium",
                        95.0 + extra,
                        "Plan certificate renewal before expiry",
                        ["tls-443"],
                        {"days_left": tls["days_left"]},
                    )
                )
            if tls.get("self_signed"):
                items.append(
                    _cfg_item(
                        "cfg-tls-self-signed",
                        "Self-signed TLS certificate in use",
                        "high",
                        130.0 + extra,
                        "Replace with CA-issued certificate for production",
                        ["tls-443"],
                        {},
                    )
                )
            if tls.get("legacy_tls_enabled"):
                items.append(
                    _cfg_item(
                        "cfg-tls-legacy-protocol",
                        "Server accepts deprecated TLS 1.0 or 1.1",
                        "high",
                        125.0 + extra,
                        "Disable TLS 1.0/1.1; require TLS 1.2+",
                        ["tls-443"],
                        {"protocols_accepted": tls.get("protocols_accepted")},
                    )
                )
            if tls.get("hostname_matches_cert") is False:
                items.append(
                    _cfg_item(
                        "cfg-tls-name-mismatch",
                        "Certificate hostname does not match scanned host",
                        "high",
                        120.0 + extra,
                        "Reissue certificate with correct CN/SAN for this hostname",
                        ["tls-443"],
                        {},
                    )
                )

    hh = findings.get("http_headers") or {}
    header_actions = {
        "Strict-Transport-Security": (
            "cfg-missing-hsts",
            "Strict-Transport-Security (HSTS) not set",
            "Enable HSTS with an appropriate max-age (e.g. includeSubDomains if suitable)",
        ),
        "Content-Security-Policy": (
            "cfg-missing-csp",
            "Content-Security-Policy not set",
            "Define a restrictive CSP appropriate for the application",
        ),
        "X-Frame-Options": (
            "cfg-missing-xfo",
            "X-Frame-Options not set",
            "Set X-Frame-Options or frame-ancestors in CSP to reduce clickjacking risk",
        ),
        "X-Content-Type-Options": (
            "cfg-missing-xcto",
            "X-Content-Type-Options not set",
            "Set X-Content-Type-Options: nosniff",
        ),
        "Referrer-Policy": (
            "cfg-missing-referrer",
            "Referrer-Policy not set",
            "Set Referrer-Policy to limit referrer leakage",
        ),
    }
    missing = [h for h, v in hh.items() if not v]
    if missing:
        base_score = 88.0 + extra if len(missing) >= 3 else 72.0 + extra
        if len(missing) >= 4:
            items.append(
                _cfg_item(
                    "cfg-http-headers-multiple",
                    f"Multiple security headers missing ({len(missing)})",
                    "medium",
                    base_score,
                    "Harden HTTP response headers per organizational baseline",
                    ["http-headers"],
                    {"missing": missing},
                )
            )
        else:
            for h in missing:
                meta = header_actions.get(h)
                if not meta:
                    continue
                items.append(
                    _cfg_item(
                        meta[0],
                        meta[1],
                        "medium",
                        70.0 + extra,
                        meta[2],
                        ["http-headers"],
                        {"header": h},
                    )
                )

    wi = findings.get("web_inventory") or {}
    if wi.get("cookies_missing_secure_on_https"):
        items.append(
            _cfg_item(
                "cfg-cookie-secure",
                "Session cookie missing Secure flag on HTTPS",
                "high",
                110.0 + extra,
                "Set Secure (and HttpOnly) on authentication cookies",
                ["web-inventory"],
                {"cookies": wi.get("cookies")},
            )
        )
    final = (wi.get("final_url") or "").lower()
    if final.startswith("http://") and 443 not in (findings.get("open_ports") or []):
        items.append(
            _cfg_item(
                "cfg-cleartext-http",
                "Site served over cleartext HTTP without HTTPS in scope",
                "high",
                115.0 + extra,
                "Enable HTTPS and redirect HTTP to HTTPS",
                ["web-inventory"],
                {"final_url": wi.get("final_url")},
            )
        )
    elif final.startswith("http://") and 443 in (findings.get("open_ports") or []):
        items.append(
            _cfg_item(
                "cfg-no-https-redirect",
                "HTTP service does not redirect to HTTPS (port 443 open)",
                "medium",
                85.0 + extra,
                "Redirect HTTP to HTTPS and enforce HSTS",
                ["web-inventory"],
                {"final_url": wi.get("final_url")},
            )
        )

    for obs in findings.get("observations") or []:
        pv = obs.get("parsed_version")
        if not pv:
            continue
        prod = (pv.get("product") or "").lower()
        ver = pv.get("version_token") or ""
        if prod == "openssh" and ver:
            m = re.match(r"(\d+)\.(\d+)", ver)
            if m and int(m.group(1)) < 7:
                items.append(
                    _cfg_item(
                        "cfg-eol-openssh",
                        f"OpenSSH {ver} is end-of-life / unsupported",
                        "high",
                        118.0 + extra,
                        "Upgrade OpenSSH to a vendor-supported release",
                        [obs.get("id", "tcp-22")],
                        {"product": prod, "version": ver, "banner": (obs.get("evidence") or {}).get("banner", "")[:200]},
                    )
                )

    return items


def build_triage(findings: dict, vulnerabilities: List[dict], ctx: dict) -> dict:
    products = _detected_products(findings)
    config_items = build_config_findings(findings, ctx)

    enriched: List[dict] = []
    high_med: List[dict] = []
    low_conf: List[dict] = []

    for cve in vulnerabilities:
        row = enrich_cve_triage(cve, products, ctx)
        row["item_type"] = "cve"
        enriched.append(row)
        if row["relevance"] == "low" and not row.get("known_exploited"):
            low_conf.append(row)
        else:
            high_med.append(row)

    enriched.sort(key=lambda x: (-x["priority_score"], x.get("cve_id", "")))
    high_med.sort(key=lambda x: (-x["priority_score"], x.get("cve_id", "")))

    action_queue: List[dict] = []
    for item in sorted(config_items, key=lambda x: -x["priority_score"]):
        action_queue.append(item)
    for item in high_med[:20]:
        action_queue.append(item)
    action_queue = action_queue[:25]

    tier_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "P5": 0}
    for item in action_queue:
        t = item.get("priority_tier") or "P5"
        tier_counts[t] = tier_counts.get(t, 0) + 1

    remediation_queue = []
    for item in action_queue:
        if item.get("item_type") == "cve":
            remediation_queue.append(
                {
                    k: item[k]
                    for k in (
                        "cve_id",
                        "cvss",
                        "cvss_vector",
                        "severity",
                        "validation_status",
                        "known_exploited",
                        "relevance",
                        "relevance_reason",
                        "priority_score",
                        "priority_tier",
                        "priority_rationale",
                        "recommended_action",
                        "nvd_url",
                        "summary",
                    )
                    if k in item
                }
            )
        else:
            remediation_queue.append(
                {
                    "configuration_id": item.get("id"),
                    "title": item.get("title"),
                    "severity": item.get("severity"),
                    "relevance": item.get("relevance"),
                    "priority_score": item.get("priority_score"),
                    "priority_tier": item.get("priority_tier"),
                    "recommended_action": item.get("recommended_action"),
                    "observation_ids": item.get("observation_ids"),
                }
            )

    return {
        "detected_products": sorted(products),
        "configuration_findings": config_items,
        "vulnerabilities": enriched,
        "cve_prioritized": high_med,
        "cve_low_confidence": low_conf,
        "action_queue": action_queue,
        "remediation_queue": remediation_queue,
        "tier_counts": tier_counts,
    }
