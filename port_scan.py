import socket

def scan_port(host, port, timeout=1.0):
# Return (is_open: bool, banner: str)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        try:
            s.settimeout(0.8)
            banner = s.recv(1024)
            banner = banner.decode('utf-8', errors='ignore').strip()
            print(banner)
        except Exception:
            banner = ''
        s.close()
        return True, banner
    except Exception:
        return False, ''