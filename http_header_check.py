from urllib import request, error

HEADER_CHECKS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy'
]

def check_http_headers(url):
    try:
        req = request.Request(url, method='GET', headers={'User-Agent': 'MVP-Scanner/1.0'})
        with request.urlopen(req, timeout=4) as resp:
            
            headers = {k: v for k, v in resp.getheaders()}
            found = {h: headers.get(h) for h in HEADER_CHECKS}
            return found
    except error.HTTPError as he:
        headers = {k: v for k, v in he.headers.items()} if he.headers else {}
        found = {h: headers.get(h) for h in HEADER_CHECKS}
        return found
    except Exception:
        return {h: None for h in HEADER_CHECKS}