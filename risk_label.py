from cve_lookup import find_cves
from kev import is_known_exploited
from mistral_ai import cve_ai
from observations import build_observations
from triage import build_triage


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


def _rollup_validation(sources: set) -> str:
    if sources & {"version", "banner_token"}:
        return "corroborated"
    if "port_hint" in sources or "inventory" in sources:
        return "potential"
    if sources & {"tls", "header"}:
        return "heuristic"
    return "potential"


def risk_from_findings(findings: dict, scan_context=None):
    ctx = scan_context or {}
    observations = build_observations(findings)
    findings["observations"] = observations

    acc: dict = {}
    max_queries = 40
    queries = 0
    max_cves = 55

    for obs in observations:
        entries = (obs.get("nvd_keywords") or [])[:8]
        for entry in entries:
            if queries >= max_queries or len(acc) >= max_cves:
                break
            kw = entry.get("keyword")
            src = entry.get("source") or "port_hint"
            if not kw:
                continue
            # Header/TLS template keywords produce noisy NVD hits; triage scores them down.
            queries += 1
            try:
                batch = find_cves(kw, max_results=5, verbose=False)
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
                    {"observation_id": obs["id"], "keyword": kw, "source": src}
                )
                acc[cid]["sources"].add(src)
        if queries >= max_queries or len(acc) >= max_cves:
            break

    raw_vulns = []
    for cid, row in acc.items():
        sources = row.pop("sources")
        hits = row.pop("hits")
        obs_ids = sorted({h["observation_id"] for h in hits})
        kws_used = sorted({h["keyword"] for h in hits})
        val = _rollup_validation(sources)
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

    ai_kw = sorted(
        {e["keyword"] for obs in observations for e in (obs.get("nvd_keywords") or [])}
    )[:28]
    findings["ai_suggestions"] = _safe_ai_suggestions(ai_kw)

    vulnerabilities = triage["vulnerabilities"]
    prioritized = triage["cve_prioritized"]
    highest_cvss = None
    kev_count = 0
    for v in prioritized:
        if v.get("known_exploited"):
            kev_count += 1
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
        "highest_tier": top_tier,
        "tier_counts": triage["tier_counts"],
        "detected_products": triage["detected_products"],
    }
