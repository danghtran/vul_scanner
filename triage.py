"""
Triage: configuration findings, CVE relevance scoring, unified action queue.
"""
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from nvd_noise import summary_conflicts_with_products
from prioritize import build_rationale, compute_priority_score, tier_from_score
from version_match import assess_version_match, collect_installed_versions

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
        "apache cxf",
        "cxf",
        "groovy",
        "windowmaker",
        "wmaker",
        "internet explorer",
        "outlook express",
        "microsoft jet",
        "digi-news",
        "digi-ads",
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


def assess_cve_relevance(
    cve: dict,
    products: Set[str],
    installed_versions: Optional[List[dict]] = None,
) -> Tuple[str, str]:
    """
    Returns (relevance: high|medium|low, reason).
    """
    summary = (cve.get("summary") or "").lower()
    val = cve.get("validation_status") or "potential"
    sources = {h.get("source") for h in (cve.get("evidence_hits") or []) if h.get("source")}

    v_match, v_reason = assess_version_match(cve, installed_versions or [])
    if v_match == "not_applicable":
        return "low", v_reason

    if not summary:
        return "low", "no CVE description to validate product match"

    if products and summary_conflicts_with_products(summary, products):
        return "low", "CVE description targets a different product line than observed on host"

    if not products:
        if v_match != "likely_affected":
            if sources <= {"header", "tls", "port_hint", "banner_token"} or val == "heuristic":
                return "low", "no product/version fingerprint; generic keyword association"
            if val == "corroborated":
                return "low", "keyword matched without observed product version on host"

    if "cpe" in sources and v_match == "likely_affected" and v_reason:
        return "high", f"NVD CPE match for installed version; {v_reason}"

    if v_match == "likely_affected" and v_reason:
        if val == "corroborated":
            return "high", v_reason
        if products and _summary_mentions_product(summary, products):
            return "medium", v_reason

    if products and _summary_mentions_unrelated(summary, products):
        return "low", "CVE description targets a different product than observed on host"

    if val == "heuristic" and sources <= {"header", "tls"}:
        if not _summary_mentions_product(summary, products):
            return "low", "keyword match from header/TLS template; CVE text does not reference observed stack"

    if products and _summary_mentions_product(summary, products):
        if val == "corroborated":
            return "high", "banner or version evidence aligns with CVE affected product"
        return "medium", "CVE description references observed product; confirm version range"

    if val == "corroborated" and products:
        return "medium", "strong keyword match; verify CVE applies to installed version"
    if val == "corroborated":
        return "low", "keyword matched without observed product version on host"

    if "port_hint" in sources and not products:
        return "low", "generic port-based keyword only"

    return "low", "weak or generic NVD keyword association"


def _relevance_multiplier(relevance: str) -> float:
    return {"high": 1.0, "medium": 0.72, "low": 0.35}.get(relevance, 0.35)


def _epss_promotes_despite_low_relevance(cve: dict, products: Optional[Set[str]] = None) -> bool:
    if cve.get("version_match") == "not_applicable" and not cve.get("known_exploited"):
        return False
    if cve.get("relevance") == "low":
        rr = (cve.get("relevance_reason") or "").lower()
        if any(
            x in rr
            for x in (
                "different product line",
                "generic keyword",
                "no product/version fingerprint",
                "false positive",
                "without observed product",
            )
        ):
            return bool(cve.get("known_exploited"))
    if not products and cve.get("version_match") != "likely_affected":
        if not cve.get("known_exploited"):
            return False
    if cve.get("known_exploited"):
        return True
    try:
        p = float(cve.get("epss_percentile"))
        return p >= 0.90
    except (TypeError, ValueError):
        pass
    try:
        s = float(cve.get("epss"))
        return s >= 0.65
    except (TypeError, ValueError):
        return False


def enrich_cve_triage(
    cve: dict,
    products: Set[str],
    ctx: dict,
    installed_versions: Optional[List[dict]] = None,
) -> dict:
    v_match, v_reason = assess_version_match(cve, installed_versions or [])
    relevance, rel_reason = assess_cve_relevance(cve, products, installed_versions)
    epss_score = cve.get("epss")
    epss_pct = cve.get("epss_percentile")
    base = compute_priority_score(
        cve.get("cvss"),
        cve.get("known_exploited"),
        cve.get("validation_status"),
        ctx,
        epss_score=epss_score,
        epss_percentile=epss_pct,
    )
    adjusted = round(base * _relevance_multiplier(relevance), 2)
    tier = tier_from_score(adjusted)
    rationale = build_rationale(
        cve.get("cvss"),
        cve.get("known_exploited"),
        cve.get("validation_status"),
        ctx,
        epss_score=epss_score,
        epss_percentile=epss_pct,
    )
    rationale = f"{rationale}; relevance: {relevance} ({rel_reason})"
    out = {**cve}
    out["version_match"] = v_match
    out["version_match_reason"] = v_reason or None
    out["relevance"] = relevance
    out["relevance_reason"] = rel_reason
    out["priority_score"] = adjusted
    out["priority_tier"] = tier
    out["priority_rationale"] = rationale
    if relevance == "high" and cve.get("known_exploited"):
        out["recommended_action"] = "Patch or mitigate immediately; CISA KEV with strong product match"
    elif epss_pct is not None and float(epss_pct) >= 0.85:
        out["recommended_action"] = (
            "High EPSS exploitation probability; validate applicability and patch urgently"
        )
    elif relevance == "high":
        out["recommended_action"] = "Validate affected component version, then patch per vendor advisory"
    elif relevance == "medium":
        out["recommended_action"] = "Confirm version in banner or inventory, then prioritize patch if in range"
    elif v_match == "not_applicable":
        out["recommended_action"] = (
            "Likely not applicable to installed version; confirm in vendor advisory before patching"
        )
    elif _epss_promotes_despite_low_relevance(cve, products):
        out["recommended_action"] = (
            "Weak product match but elevated EPSS/KEV; verify component before deprioritizing"
        )
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
                "Cookie missing Secure flag on HTTPS",
                "high",
                110.0 + extra,
                "Set Secure (and HttpOnly) on authentication cookies",
                ["web-inventory"],
                {"cookies": wi.get("cookies")},
            )
        )
    ca = wi.get("cookie_audit") or {}
    if ca.get("missing_httponly"):
        items.append(
            _cfg_item(
                "cfg-cookie-httponly",
                f"Cookie(s) missing HttpOnly: {', '.join(ca['missing_httponly'][:5])}",
                "medium",
                78.0 + extra,
                "Set HttpOnly on session and sensitive cookies",
                ["web-inventory"],
                {"names": ca["missing_httponly"][:10]},
            )
        )
    if ca.get("missing_samesite"):
        items.append(
            _cfg_item(
                "cfg-cookie-samesite",
                f"Cookie(s) missing SameSite: {', '.join(ca['missing_samesite'][:5])}",
                "medium",
                72.0 + extra,
                "Set SameSite=Lax or Strict on cookies",
                ["web-inventory"],
                {"names": ca["missing_samesite"][:10]},
            )
        )

    final_url = wi.get("final_url") or ""
    final = final_url.lower()
    https_final = final.startswith("https://")
    hsts = wi.get("hsts")
    if https_final and not hsts:
        items.append(
            _cfg_item(
                "cfg-hsts-missing",
                "HTTPS response without Strict-Transport-Security",
                "high",
                105.0 + extra,
                "Add HSTS with suitable max-age (consider includeSubDomains after testing)",
                ["web-inventory"],
                {"final_url": final_url},
            )
        )
    elif hsts and hsts.get("max_age") is not None and int(hsts["max_age"]) < 86400:
        items.append(
            _cfg_item(
                "cfg-hsts-weak",
                f"HSTS max-age is low ({hsts.get('max_age')} seconds)",
                "low",
                55.0 + extra,
                "Increase HSTS max-age (common baseline: 31536000)",
                ["web-inventory"],
                {"hsts": hsts},
            )
        )

    dns = findings.get("dns_context") or {}
    ac = dns.get("asset_context") or {}
    if ac.get("mail_surface"):
        if not ac.get("has_spf"):
            items.append(
                _cfg_item(
                    "cfg-dns-spf-missing",
                    "MX records present but no SPF TXT record found",
                    "medium",
                    80.0 + extra,
                    "Publish SPF (v=spf1) TXT at the domain apex",
                    ["dns-host"],
                    {"mx": dns.get("mx", [])[:5]},
                )
            )
        if not ac.get("has_dmarc"):
            items.append(
                _cfg_item(
                    "cfg-dns-dmarc-missing",
                    "MX records present but no DMARC record at _dmarc",
                    "medium",
                    82.0 + extra,
                    "Publish DMARC (v=DMARC1) at _dmarc.<domain>",
                    ["dns-host"],
                    {"mx": dns.get("mx", [])[:5]},
                )
            )
        elif ac.get("dmarc_policy") == "none":
            items.append(
                _cfg_item(
                    "cfg-dns-dmarc-none",
                    "DMARC policy is p=none (monitoring only)",
                    "low",
                    50.0 + extra,
                    "Tighten DMARC to quarantine or reject when ready",
                    ["dns-host"],
                    {"dmarc": dns.get("dmarc")},
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
    from epss import attach_epss_to_cve, fetch_epss_scores

    products = _detected_products(findings)
    installed_versions = collect_installed_versions(findings)
    config_items = build_config_findings(findings, ctx)

    cve_ids = [v.get("cve_id") for v in vulnerabilities if v.get("cve_id")]
    epss_result = fetch_epss_scores(cve_ids)
    epss_scores = epss_result.get("scores") or {}

    enriched: List[dict] = []
    high_med: List[dict] = []
    low_conf: List[dict] = []

    for cve in vulnerabilities:
        cid = (cve.get("cve_id") or "").upper()
        attach_epss_to_cve(cve, epss_scores.get(cid))
        row = enrich_cve_triage(cve, products, ctx, installed_versions)
        row["item_type"] = "cve"
        enriched.append(row)
        if row["relevance"] == "low" and not _epss_promotes_despite_low_relevance(row, products):
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
                        "epss",
                        "epss_percentile",
                        "epss_date",
                        "version_match",
                        "version_match_reason",
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
        "installed_versions": installed_versions,
        "configuration_findings": config_items,
        "vulnerabilities": enriched,
        "cve_prioritized": high_med,
        "cve_low_confidence": low_conf,
        "action_queue": action_queue,
        "remediation_queue": remediation_queue,
        "tier_counts": tier_counts,
        "epss_status": epss_result.get("status"),
        "epss_error": epss_result.get("error"),
    }
