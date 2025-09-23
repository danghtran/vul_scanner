from cve_lookup import find_cves
from cve_keyword_extract import generate_keywords
from mistral_ai import cve_ai

def risk_from_findings(findings):
    # collect keywords from banners and hostname
    #cve_keywords = set()
    # for b in (findings.get('port_banners') or {}).values():
    #     if b:
    #         cve_keywords.add(' '.join(b.split())[:80])  # trim long banners
    #         print(extract_keyword(b))
    # tgt = findings.get('target')
    # if tgt:
    #     cve_keywords.add(str(tgt))
    cve_keywords = generate_keywords(findings)

    aggregated_cves = []
    highest_cvss = 0.0
    for kw in cve_keywords:
        try:
            cves = find_cves(kw, max_results=5)
        except Exception:
            cves = []
        for c in cves:
            if not any(x['cve_id'] == c['cve_id'] for x in aggregated_cves):
                aggregated_cves.append(c)
                if c.get('cvss') is not None:
                    try:
                        highest_cvss = max(highest_cvss, float(c['cvss']))
                    except Exception:
                        pass
        if len(aggregated_cves) >= 10:
            break

    findings['cves'] = aggregated_cves
    findings['ai'] = cve_ai(cve_keywords)

    return {
        'highest_cvss': highest_cvss if aggregated_cves else None,
        'cve_count': len(aggregated_cves)
    }
