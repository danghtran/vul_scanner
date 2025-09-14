import socket
import ssl
from datetime import datetime

def check_tls_cert(host, port=443, timeout=3.0):
    # Returns dict with 'expires' ISO string and 'days_left' or None on failure
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                if not_after:
                    expires = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expires - datetime.utcnow()).days
                    return {'expires': expires.isoformat() + 'Z', 'days_left': days_left}
    except Exception:
        return None
    return None