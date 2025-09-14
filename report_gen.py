import json

def generate_text_report(target, findings, out_path):
    lines = []
    lines.append(f'Scan report for {target}')
    lines.append('=' * 40)
    lines.append('Open ports:')
    for p, b in findings.get('port_banners', {}).items():
        lines.append(f' - {p}: open')
        if b:
            lines.append(f' banner: {b}')
    lines.append('TLS:')
    tls = findings.get('tls')
    if tls:
        lines.append(f" - expires: {tls.get('expires')} (days left: {tls.get('days_left')})")
    else:
        lines.append(' - no TLS info')
    lines.append('HTTP headers:')
    hh = findings.get('http_headers') or {}
    for h, v in hh.items():
        lines.append(f' - {h}: {v}')
    lines.append('Risk:')
    r = findings.get('risk')
    lines.append(f" - level: {r.get('level')} (score {r.get('score')})")
    if r.get('notes'):
        lines.append(' - notes:')
        for n in r.get('notes'):
            lines.append(f' * {n}')

    text = ''.join(lines)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(text)
    return text




def save_json(out_path, data):
    with open(out_path, 'w', encoding='utf-8') as jf:
        json.dump(data, jf, indent=2)