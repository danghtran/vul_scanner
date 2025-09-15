import re
from typing import List, Set

# port -> likely product hints
PORT_PRODUCT_HINTS = {
    22: ['openssh', 'ssh'],
    80: ['apache', 'nginx', 'httpd', 'iis'],
    443: ['nginx', 'apache', 'openssl', 'iis', 'haproxy'],
    3306: ['mysql', 'mariadb'],
    5432: ['postgresql', 'postgres'],
    27017: ['mongodb'],
    6379: ['redis'],
    8080: ['tomcat', 'jetty', 'nginx'],
    8443: ['tomcat', 'jetty', 'apache'],
}

TLS_STATE_TEMPLATES = [
    'expired tls', 'expired certificate', 'expired ssl',
    'self-signed certificate', 'self signed certificate', 'self-signed tls',
    'revoked certificate', 'weak tls', 'weak ciphers', 'tls 1.0', 'tls 1.1'
]

HEADER_TEMPLATES = {
    'Strict-Transport-Security': ['missing hsts', 'no hsts', 'hsts not set'],
    'Content-Security-Policy': ['missing csp', 'no csp', 'csp not set'],
    'X-Frame-Options': ['missing x-frame-options', 'no x-frame-options', 'clickjacking header missing'],
    'X-Content-Type-Options': ['missing x-content-type-options', 'no x-content-type-options'],
    'Referrer-Policy': ['missing referrer-policy', 'no referrer-policy']
}

def generate_keywords(findings: dict):
    kws = set()

    # 3) port -> product hints (based on open_ports if present)
    for p in (findings.get('open_ports') or []):
        hints = PORT_PRODUCT_HINTS.get(p, [])
        for h in hints:
            kws.add(h)

    # 4) TLS-based templates (expired / self-signed / near expiry)
    tls = findings.get('tls') or {}
    if tls:
        days_left = tls.get('days_left')
        if isinstance(days_left, (int, float)):
            if days_left < 0:
                for tpl in ['expired tls', 'expired certificate', 'expired ssl']:
                    kws.add(tpl)
            elif days_left < 30:
                for tpl in ['near expiry tls', 'certificate near expiry', 'soon-to-expire tls']:
                    kws.add(tpl)
        subj = tls.get('subject'); issuer = tls.get('issuer')
        if subj and issuer and subj == issuer:
            for tpl in ['self-signed certificate', 'self-signed tls']:
                kws.add(tpl)

    # 5) HTTP header signals (missing headers -> keywords)
    headers = findings.get('http_headers') or {}
    for header, val in headers.items():
        if not val:
            for tpl in HEADER_TEMPLATES.get(header, []):
                kws.add(tpl)

    # 6) protocol fallbacks
    for g in ['https', 'tls', 'ssl', 'http']:
        kws.add(g)

    return kws