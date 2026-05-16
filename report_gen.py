import json
from typing import List


def _cvss_line(c: dict) -> str:
    parts = []
    if c.get("cvss") is not None:
        parts.append(f"CVSS {c['cvss']}")
    if c.get("cvss_version"):
        parts.append(f"v{c['cvss_version']}")
    if c.get("severity"):
        parts.append(str(c["severity"]))
    if c.get("cvss_vector"):
        parts.append(c["cvss_vector"])
    return " | ".join(parts) if parts else "CVSS n/a"


def _queue_line(item: dict, index: int) -> List[str]:
    out = []
    kev = " [KEV]" if item.get("known_exploited") else ""
    tier = item.get("priority_tier", "")
    score = item.get("priority_score")
    rel = item.get("relevance", "")
    if item.get("item_type") == "cve":
        title = item.get("cve_id", "CVE")
        out.append(f" {index}. {title} — {tier} (score {score}){kev} [{rel}]")
    else:
        title = item.get("title") or item.get("id", "config")
        sev = item.get("severity", "")
        out.append(f" {index}. [CONFIG] {title} — {tier} ({sev}, score {score})")
    out.append(f"     {item.get('recommended_action', item.get('priority_rationale', ''))}")
    if item.get("nvd_url"):
        out.append(f"     {item['nvd_url']}")
    elif item.get("relevance_reason"):
        out.append(f"     {item['relevance_reason']}")
    return out


def generate_text_report(target, findings, out_path):
    lines = []
    lines.append(f"Scan report for {target}")
    lines.append("=" * 60)

    r = findings.get("risk") or {}
    lines.append("\nTriage summary:")
    lines.append(f" - Detected products: {', '.join(findings.get('detected_products') or []) or 'none'}")
    lines.append(f" - Configuration findings: {r.get('config_finding_count', 0)}")
    lines.append(f" - CVEs (prioritized): {r.get('cve_prioritized_count', 0)}")
    lines.append(f" - CVEs (low confidence): {r.get('cve_low_confidence_count', 0)}")
    if r.get("kev_count"):
        lines.append(f" - CISA KEV matches (prioritized): {r['kev_count']}")
    tc = r.get("tier_counts") or {}
    if tc:
        parts = [f"{k}: {v}" for k, v in sorted(tc.items()) if v]
        lines.append(f" - Action queue by tier: {', '.join(parts)}")

    lines.append("\nAction queue (config + high-value CVEs):")
    aq = findings.get("action_queue") or findings.get("remediation_queue") or []
    if aq:
        for i, item in enumerate(aq, 1):
            lines.extend(_queue_line(item, i))
    else:
        lines.append(" - None")

    cfg = findings.get("configuration_findings") or []
    if cfg:
        lines.append("\nConfiguration findings:")
        for c in cfg:
            lines.append(
                f" - [{c.get('priority_tier')}] {c.get('title')} ({c.get('severity')})"
            )
            lines.append(f"     {c.get('recommended_action', '')}")

    lines.append("\nObservations:")
    for obs in findings.get("observations") or []:
        cat = obs.get("category", "")
        oid = obs.get("id", "")
        lines.append(f" - [{oid}] {cat}")
        if obs.get("port") is not None:
            lines.append(f"     port: {obs['port']}")
        if obs.get("parsed_version"):
            pv = obs["parsed_version"]
            lines.append(f"     parsed: {pv.get('product')} {pv.get('version_token', '')}")
        ev = obs.get("evidence") or {}
        if cat == "tcp_service" and ev.get("banner"):
            b = str(ev["banner"]).replace("\n", " ")[:160]
            lines.append(f"     banner: {b}")
        if cat == "tls_certificate":
            if ev.get("tls_version"):
                cn = (ev.get("cipher") or {}).get("name") or ""
                lines.append(f"     {ev.get('tls_version')} {cn}".strip())
            if ev.get("legacy_tls_enabled"):
                lines.append("     legacy TLS 1.0/1.1 accepted")
            if ev.get("handshake_error"):
                lines.append(f"     error: {ev.get('handshake_error')}")
        if cat == "dns_context":
            if ev.get("ipv4"):
                lines.append(f"     IPv4: {', '.join(ev['ipv4'])}")
            if ev.get("ipv6"):
                lines.append(f"     IPv6: {', '.join(ev['ipv6'][:4])}")
            if ev.get("error"):
                lines.append(f"     error: {ev.get('error')}")
        if cat == "web_inventory":
            th = ev.get("tech_hints") or []
            if th:
                lines.append(f"     tech: {', '.join(str(x) for x in th[:10])}")

    lines.append("\nOpen ports:")
    for p, b in (findings.get("port_banners") or {}).items():
        lines.append(f" - {p}: open")
        if b:
            lines.append(f"   banner: {b}")

    lines.append("\nTLS:")
    tls = findings.get("tls")
    if tls:
        if tls.get("handshake_ok"):
            lines.append(f" - negotiated: {tls.get('tls_version', '?')}")
            ciph = tls.get("cipher") or {}
            if ciph:
                lines.append(
                    f" - cipher: {ciph.get('name')} ({ciph.get('protocol')}, {ciph.get('secret_bits')} bits)"
                )
            lines.append(f" - expires: {tls.get('expires')} (days left: {tls.get('days_left')})")
            if tls.get("subject"):
                lines.append(f" - subject: {str(tls.get('subject'))[:120]}")
            if tls.get("issuer"):
                lines.append(f" - issuer: {str(tls.get('issuer'))[:120]}")
            sans = tls.get("san_dns") or []
            if sans:
                lines.append(f" - SAN DNS: {', '.join(str(x) for x in sans[:8])}")
            hm = tls.get("hostname_matches_cert")
            if hm is False:
                lines.append(" - hostname does not match certificate CN/SAN")
            elif hm is True:
                lines.append(" - hostname matches certificate (CN/SAN)")
            if tls.get("self_signed"):
                lines.append(" - self-signed certificate (subject matches issuer)")
            pa = tls.get("protocols_accepted") or {}
            if pa:
                enabled = [k for k, v in pa.items() if v]
                lines.append(f" - legacy protocol probes accepted: {', '.join(enabled) or 'none'}")
            if tls.get("legacy_tls_enabled"):
                lines.append(" - warning: TLS 1.0 or 1.1 accepted (deprecated)")
        else:
            err = tls.get("handshake_error") or "unknown"
            lines.append(f" - handshake failed: {err}")
    else:
        lines.append(" - no TLS info")

    lines.append("\nHTTP headers:")
    hh = findings.get("http_headers") or {}
    for h, v in hh.items():
        lines.append(f" - {h}: {v}")

    dc = findings.get("dns_context") or {}
    lines.append("\nDNS (inventory):")
    if dc.get("host"):
        lines.append(f" - host: {dc.get('host')}")
    if dc.get("error"):
        lines.append(f" - error: {dc.get('error')}")
    if dc.get("ipv4"):
        lines.append(f" - IPv4: {', '.join(dc['ipv4'])}")
    if dc.get("ipv6"):
        lines.append(f" - IPv6: {', '.join(dc['ipv6'][:8])}")

    wi = findings.get("web_inventory")
    lines.append("\nWeb inventory (passive):")
    if wi is None:
        lines.append(" - skipped: no HTTP/HTTPS port in scope for default base URL")
    else:
        if wi.get("entry_url"):
            lines.append(f" - entry URL: {wi.get('entry_url')}")
        if wi.get("fetch_error") and wi.get("http_status") is None:
            lines.append(f" - fetch error: {wi.get('fetch_error')}")
        if wi.get("final_url"):
            lines.append(f" - final URL: {wi.get('final_url')}")
        if wi.get("http_status") is not None:
            lines.append(f" - HTTP status: {wi.get('http_status')}")
        if wi.get("server"):
            lines.append(f" - Server: {wi.get('server')}")
        if wi.get("x_powered_by"):
            lines.append(f" - X-Powered-By: {wi.get('x_powered_by')}")
        hints = wi.get("tech_hints") or []
        if hints:
            lines.append(f" - tech hints: {', '.join(str(x) for x in hints[:20])}")
        if wi.get("generator"):
            lines.append(f" - meta generator: {str(wi.get('generator'))[:160]}")
        cc = wi.get("cookie_count")
        if cc is not None:
            lines.append(f" - Set-Cookie count: {cc}")
        if wi.get("cookies_missing_secure_on_https"):
            lines.append(" - warning: cookie(s) without Secure flag on HTTPS")
        rt = wi.get("robots_txt") or {}
        if rt.get("ok"):
            prev = (rt.get("preview") or "").replace("\n", " ").strip()[:300]
            lines.append(f" - robots.txt: {prev}")
        elif rt.get("status") is not None:
            lines.append(f" - robots.txt: HTTP {rt.get('status')}")
        st = wi.get("security_txt")
        if isinstance(st, dict) and st.get("found") is False:
            lines.append(" - security.txt: not found at /.well-known/ or /")
        elif isinstance(st, dict) and (st.get("ok") or st.get("status") == 200):
            src = st.get("source_path") or "?"
            prev = (st.get("preview") or "").replace("\n", " ").strip()[:300]
            lines.append(f" - security.txt ({src}): {prev}")

    pri = findings.get("cve_prioritized") or []
    lines.append("\nCVE matches — prioritized (relevance high/medium or KEV):")
    if pri:
        for c in pri[:25]:
            kev = " [KEV]" if c.get("known_exploited") else ""
            val = c.get("validation_status", "")
            rel = c.get("relevance", "")
            tier = c.get("priority_tier", "")
            lines.append(
                f" - {c['cve_id']} [{tier}] rel={rel} val={val}{kev} — {_cvss_line(c)}"
            )
            lines.append(f"     {c.get('relevance_reason', '')}")
            lines.append(f"     {c.get('nvd_url', '')}")
            if c.get("summary"):
                s = str(c["summary"]).replace("\n", " ").strip()
                lines.append(f"     {s[:280]}")
    else:
        lines.append(" - None after relevance filtering.")

    low = findings.get("cve_low_confidence") or []
    lines.append(f"\nCVE matches — low confidence ({len(low)} total, showing up to 10):")
    if low:
        for c in low[:10]:
            lines.append(
                f" - {c['cve_id']} [{c.get('priority_tier')}] — {c.get('relevance_reason', '')[:120]}"
            )
        if len(low) > 10:
            lines.append(f" - ... and {len(low) - 10} more in JSON under cve_low_confidence")
    else:
        lines.append(" - None")

    ai = findings.get("ai_suggestions") or {}
    lines.append("\nAI suggestions (advisory only):")
    st = ai.get("status")
    if st == "ok":
        lines.append(f" - {ai.get('notice', '')}")
        lines.append(" - Full model output is in JSON under `ai_suggestions.data`.")
    else:
        lines.append(f" - status: {st} ({ai.get('reason', '')})")

    lines.append("\nSummary:")
    lines.append(f" - Total NVD keyword hits: {r.get('cve_count', 0)}")
    if r.get("highest_cvss") is not None:
        lines.append(f" - Highest CVSS (prioritized subset): {r['highest_cvss']}")
    if r.get("highest_tier"):
        lines.append(f" - Top action queue tier: {r['highest_tier']}")

    text = "\n".join(lines)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    return text


def save_json(out_path, data):
    with open(out_path, "w", encoding="utf-8") as jf:
        json.dump(data, jf, indent=2)
