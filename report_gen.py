import json

def generate_text_report(target, findings, out_path):
    lines = []
    lines.append(f'Scan report for {target}')
    lines.append('=' * 60)

    # Ports
    lines.append('\nOpen ports:')
    for p, b in findings.get('port_banners', {}).items():
        lines.append(f' - {p}: open')
        if b:
            lines.append(f'   banner: {b}')

    # TLS
    lines.append('\nTLS:')
    tls = findings.get('tls')
    if tls:
        lines.append(f" - expires: {tls.get('expires')} (days left: {tls.get('days_left')})")
    else:
        lines.append(' - no TLS info')

    # HTTP Headers
    lines.append('\nHTTP headers:')
    hh = findings.get('http_headers') or {}
    for h, v in hh.items():
        lines.append(f' - {h}: {v}')

    # CVEs
    lines.append('\nCVE matches:')
    cves = findings.get('cves') or []
    if cves:
        for c in cves:
            cvss_str = f" (CVSS {c['cvss']})" if c.get('cvss') is not None else ''
            lines.append(f" - {c['cve_id']}{cvss_str}: {c['nvd_url']}")
            if c.get('summary'):
                s = c['summary'].replace('\n', ' ').strip()
                lines.append(f"     {s}")
    else:
        lines.append(' - No CVE matches found (keyword-based search).')

    # Simplified risk summary
    r = findings.get('risk')
    lines.append('\nSummary:')
    if r and r.get('cve_count'):
        lines.append(f" - {r['cve_count']} CVEs found")
        if r.get('highest_cvss') is not None:
            lines.append(f" - Highest CVSS: {r['highest_cvss']}")
    else:
        lines.append(" - No CVEs detected")

    text = '\n'.join(lines)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(text)
    return text
    

def save_json(out_path, data):
    with open(out_path, 'w', encoding='utf-8') as jf:
        json.dump(data, jf, indent=2)