"""TCP connect scan with optional service probes and parallel or stealth execution."""
import random
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from stealth import StealthConfig, jitter_sleep

DEFAULT_TIMEOUT = 1.0
BANNER_READ_TIMEOUT = 0.9
MAX_WORKERS = 32

_HTTP_PROBE_PORTS = frozenset({80, 81, 8000, 8008, 8080, 8888})

_SERVICE_PROBES: Dict[int, bytes] = {
    25: b"EHLO scanner.local\r\n",
    587: b"EHLO scanner.local\r\n",
    465: b"EHLO scanner.local\r\n",
    110: b"USER anonymous\r\n",
    143: b"a001 CAPABILITY\r\n",
    21: b"USER anonymous\r\n",
    6379: b"PING\r\n",
    11211: b"version\r\n",
}


def _http_get_probe(http_host: str) -> bytes:
    """HTTP/1.1 GET with Host header (virtual host aware)."""
    vhost = (http_host or "localhost").strip().split("/")[0]
    if ":" in vhost and not vhost.startswith("["):
        host_part, _, port_part = vhost.rpartition(":")
        if port_part.isdigit():
            vhost = host_part
    lines = [
        "GET / HTTP/1.1",
        f"Host: {vhost}",
        "User-Agent: Vul-Scanner/1.0",
        "Accept: */*",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii", errors="ignore")


def _probe_bytes(
    port: int, connect_host: str, http_host: Optional[str] = None
) -> Optional[bytes]:
    if port in _HTTP_PROBE_PORTS:
        return _http_get_probe(http_host or connect_host)
    tpl = _SERVICE_PROBES.get(port)
    if not tpl:
        return None
    try:
        return tpl.format(host=connect_host).encode("ascii", errors="ignore")
    except Exception:
        return tpl if isinstance(tpl, bytes) else None


def scan_port(
    host: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    use_probe: bool = True,
    http_host: Optional[str] = None,
) -> Tuple[bool, str]:
    """Return (is_open, banner)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        banner = ""
        probe = _probe_bytes(port, host, http_host) if use_probe else None
        try:
            s.settimeout(BANNER_READ_TIMEOUT)
            if probe:
                s.sendall(probe)
            chunk = s.recv(2048)
            banner = chunk.decode("utf-8", errors="ignore").strip()
        except Exception:
            banner = ""
        s.close()
        return True, banner
    except OSError:
        return False, ""
    finally:
        try:
            s.close()
        except Exception:
            pass


def _scan_ports_stealth(
    host: str,
    ports: List[int],
    cfg: StealthConfig,
    http_host: Optional[str] = None,
) -> Dict[int, Dict[str, Any]]:
    results: Dict[int, Dict[str, Any]] = {}
    order = list(ports)
    if cfg.shuffle_ports:
        random.shuffle(order)
    use_probe = not cfg.minimal_probes
    for p in order:
        ok, banner = scan_port(
            host,
            p,
            timeout=cfg.port_timeout,
            use_probe=use_probe,
            http_host=http_host,
        )
        results[p] = {"open": ok, "banner": banner if ok else ""}
        jitter_sleep(cfg.port_delay_min, cfg.port_delay_max)
    return results


def scan_ports(
    host: str,
    ports: List[int],
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = MAX_WORKERS,
    stealth: Optional[StealthConfig] = None,
    http_host: Optional[str] = None,
) -> Dict[int, Dict[str, Any]]:
    """
    Scan ports in parallel (default) or sequentially with jitter (stealth).
  """
    if not ports:
        return {}
    cfg = stealth or StealthConfig()
    if cfg.enabled:
        return _scan_ports_stealth(host, ports, cfg, http_host=http_host)

    results: Dict[int, Dict[str, Any]] = {}
    workers = min(max_workers, max(1, len(ports)))

    def _task(p: int) -> Tuple[int, bool, str]:
        ok, banner = scan_port(
            host, p, timeout=timeout, use_probe=True, http_host=http_host
        )
        return p, ok, banner

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_task, p): p for p in ports}
        for fut in as_completed(futures):
            port, ok, banner = fut.result()
            results[port] = {"open": ok, "banner": banner if ok else ""}
    return results
