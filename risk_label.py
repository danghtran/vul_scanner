import re
from typing import List

from cve_lookup import cpe_for_installed, find_cves, find_cves_by_cpe
from kev import is_known_exploited
from mistral_ai import cve_ai
from keyword_select import iter_nvd_keyword_queries
from observations import build_observations
from nvd_noise import scan_target_host, stack_is_cdn_opaque
from stealth import from_scan_context, nvd_pause
from triage import build_triage
from version_match import collect_installed_versions


def _safe_ai_suggestions(keywords: list) -> dict:
    if not keywords:
        return {"status": "skipped", "reason": "no_keywords"}
    try:
        data = cve_ai(keywords)
        return {
            "status": "ok",
            "data": data,
            "notice": "LLM output is advisory-only; not used for scoring or validation.",
        }
    except ValueError as e:
        return {"status": "skipped", "reason": str(e)}
    except Exception as e:
        return {"status": "error", "reason": str(e)}


def _merge_nvd_fields(dst: dict, src: dict) -> None:
    s = src.get("cvss")
    d = dst.get("cvss")
    if s is not None and (d is None or float(s) > float(d)):
        dst["cvss"] = s
        dst["cvss_vector"] = src.get("cvss_vector")
        dst["cvss_version"] = src.get("cvss_version")
        dst["severity"] = src.get("severity")


def _rollup_validation(sources: set, keywords_used: list = None) -> str:
    kws = keywords_used or []
    versionish = any(re.search(r"\d+\.\d+", k or "") for k in kws)
    if "cpe" in sources:
        return "corroborated"
    if "version" in sources:
        return "corroborated"
    if "inventory" in sources and versionish:
        return "corroborated"
    if "banner_token" in sources and versionish:
        return "corroborated"
    if sources & {"inventory", "banner_token", "port_hint"}:
        return "potential"
    if sources & {"tls", "header"}:
        return "heuristic"
    return "potential"


def risk_from_findings(findings: dict, scan_context=None):
    ctx = scan_context or {}
    observations = build_observations(findings)
    findings["observations"] = observations

    stealth_cfg = from_scan_context(ctx)
    scan_target = scan_target_host(findings)
    cdn_opaque = stack_is_cdn_opaque(findings)
    acc: dict = {}
    max_queries = stealth_cfg.max_nvd_queries if stealth_cfg.enabled else 40
    queries = 0
    max_cves = stealth_cfg.max_cves if stealth_cfg.enabled else 55
    max_cpe_queries = 3 if stealth_cfg.enabled else 6
    cpe_results_cap = 5 if stealth_cfg.enabled else 10

    installed = collect_installed_versions(findings)
    cpe_products: set = set()
    cpe_queries_done: List[str] = []

    for row in installed:
        if len(cpe_queries_done) >= max_cpe_queries or len(acc) >= max_cves:
            break
        cpe = cpe_for_installed(row)
        if not cpe or cpe in cpe_queries_done:
            continue
        cpe_queries_done.append(cpe)
        prod = (row.get("product") or "").lower()
        cpe_products.add(prod)
        nvd_pause(stealth_cfg)
        queries += 1
        try:
            batch = find_cves_by_cpe(cpe, max_results=cpe_results_cap, verbose=False)
        except Exception:
            batch = []
        obs_id = row.get("observation_id") or "cpe-enrichment"
        for c in batch:
            cid = c.get("cve_id")
            if not cid:
                continue
            if cid not in acc:
                acc[cid] = {**c, "hits": [], "sources": set()}
            else:
                _merge_nvd_fields(acc[cid], c)
            acc[cid]["hits"].append(
                {"observation_id": obs_id, "keyword": cpe, "source": "cpe"}
            )
            acc[cid]["sources"].add("cpe")
        if len(acc) >= max_cves:
            break

    findings["nvd_cpe_queries"] = list(cpe_queries_done)

    for obs_id, kw, src in iter_nvd_keyword_queries(
        observations,
        max_queries=max_queries,
        scan_target=scan_target,
        cdn_opaque=cdn_opaque,
    ):
        if len(acc) >= max_cves:
            break
        if src == "version" and cpe_products:
            lead = (kw.split(None, 1)[0] if kw else "").lower()
            if lead in cpe_products:
                continue
        nvd_pause(stealth_cfg)
        queries += 1
        try:
            max_results = 3 if stealth_cfg.enabled else 5
            batch = find_cves(kw, max_results=max_results, verbose=False)
        except Exception:
            batch = []
        for c in batch:
            cid = c.get("cve_id")
            if not cid:
                continue
            if cid not in acc:
                acc[cid] = {**c, "hits": [], "sources": set()}
            else:
                _merge_nvd_fields(acc[cid], c)
            acc[cid]["hits"].append(
                {"observation_id": obs_id, "keyword": kw, "source": src}
            )
            acc[cid]["sources"].add(src)
        if len(acc) >= max_cves:
            break

    raw_vulns = []
    for cid, row in acc.items():
        sources = row.pop("sources")
        hits = row.pop("hits")
        obs_ids = sorted({h["observation_id"] for h in hits})
        kws_used = sorted({h["keyword"] for h in hits})
        val = _rollup_validation(sources, kws_used)
        raw_vulns.append(
            {
                **row,
                "observation_ids": obs_ids,
                "keywords_used": kws_used[:40],
                "validation_status": val,
                "known_exploited": False,
                "evidence_hits": hits[:40],
            }
        )

    for v in raw_vulns:
        v["known_exploited"] = is_known_exploited(v.get("cve_id", ""))

    triage = build_triage(findings, raw_vulns, ctx)

    findings["configuration_findings"] = triage["configuration_findings"]
    findings["vulnerabilities"] = triage["vulnerabilities"]
    findings["cves"] = triage["vulnerabilities"]
    findings["cve_prioritized"] = triage["cve_prioritized"]
    findings["cve_low_confidence"] = triage["cve_low_confidence"]
    findings["action_queue"] = triage["action_queue"]
    findings["remediation_queue"] = triage["remediation_queue"]
    findings["detected_products"] = triage["detected_products"]
    findings["installed_versions"] = triage.get("installed_versions") or []
    findings["epss_status"] = triage.get("epss_status")
    if triage.get("epss_error"):
        findings["epss_error"] = triage.get("epss_error")

    ai_kw = []
    seen_ai: set = set()
    for _oid, kw, _src in iter_nvd_keyword_queries(
        observations,
        max_queries=20,
        scan_target=scan_target,
        cdn_opaque=cdn_opaque,
    ):
        if kw.lower() not in seen_ai:
            seen_ai.add(kw.lower())
            ai_kw.append(kw)
    ai_kw = ai_kw[:28]
    findings["ai_suggestions"] = _safe_ai_suggestions(ai_kw)

    vulnerabilities = triage["vulnerabilities"]
    prioritized = triage["cve_prioritized"]
    highest_cvss = None
    kev_count = 0
    high_epss_count = 0
    version_not_applicable_count = 0
    for v in vulnerabilities:
        if v.get("version_match") == "not_applicable":
            version_not_applicable_count += 1
    for v in prioritized:
        if v.get("known_exploited"):
            kev_count += 1
        try:
            if v.get("epss_percentile") is not None and float(v["epss_percentile"]) >= 0.85:
                high_epss_count += 1
        except (TypeError, ValueError):
            pass
        if v.get("cvss") is not None:
            try:
                f = float(v["cvss"])
                highest_cvss = f if highest_cvss is None else max(highest_cvss, f)
            except (TypeError, ValueError):
                pass

    top_tier = None
    if triage["action_queue"]:
        top_tier = triage["action_queue"][0].get("priority_tier")

    return {
        "highest_cvss": highest_cvss,
        "cve_count": len(vulnerabilities),
        "cve_prioritized_count": len(prioritized),
        "cve_low_confidence_count": len(triage["cve_low_confidence"]),
        "config_finding_count": len(triage["configuration_findings"]),
        "action_queue_count": len(triage["action_queue"]),
        "kev_count": kev_count,
        "high_epss_count": high_epss_count,
        "version_not_applicable_count": version_not_applicable_count,
        "epss_status": triage.get("epss_status"),
        "highest_tier": top_tier,
        "tier_counts": triage["tier_counts"],
        "detected_products": triage["detected_products"],
    }
