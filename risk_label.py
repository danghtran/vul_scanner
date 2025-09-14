def risk_from_findings(findings):
    score = 0
    notes = []
    # open common service ports -> medium
    open_ports = findings.get('open_ports', [])
    if open_ports:
        score += min(len(open_ports), 3)
        notes.append(f'Open ports: {",".join(str(p) for p in open_ports)}')

    # expired or near-expiry cert -> +3
    cert = findings.get('tls')
    if cert:
        if cert.get('days_left') is not None:
            if cert['days_left'] < 0:
                score += 4
                notes.append('TLS certificate expired')
            elif cert['days_left'] < 30:
                score += 2
                notes.append(f'TLS certificate expires in {cert["days_left"]} days')


    # missing security headers -> +1 each
    headers = findings.get('http_headers') or {}
    missing = [h for h, v in headers.items() if not v]
    score += len(missing)
    if missing:
        notes.append('Missing headers: ' + ','.join(missing))

    # map numeric score to label
    if score >= 6:
        level = 'HIGH'
    elif score >= 3:
        level = 'MEDIUM'
    else:
        level = 'LOW'


    return {'level': level, 'score': score, 'notes': notes}