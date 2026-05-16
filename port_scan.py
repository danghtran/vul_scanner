"""TCP connect scan with optional service probes and parallel or stealth execution."""
import random
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from stealth import StealthConfig, jitter_sleep

DEFAULT_TIMEOUT = 1.0
BANNER_READ_TIMEOUT = 0.9
MAX_WORKERS = 32

_SERVICE_PROBES: Dict[int, bytes] = {
    80: b"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    8000: b"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    8888: b"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    25: b"EHLO scanner.local\r\n",
    587: b"EHLO scanner.local\r\n",
    465: b"EHLO scanner.local\r\n",
    110: b"USER anonymous\r\n",
    143: b"a001 CAPABILITY\r\n",
    21: b"USER anonymous\r\n",
    6379: b"PING\r\n",
    11211: b"version\r\n",
}


def _probe_bytes(port: int, host: str) -> Optional[bytes]:
    tpl = _SERVICE_PROBES.get(port)
    if not tpl:
        return None
    try:
        return tpl.format(host=host).encode("ascii", errors="ignore")
    except Exception:
        return tpl if isinstance(tpl, bytes) else None


def scan_port(
    host: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    use_probe: bool = True,
) -> Tuple[bool, str]:
    """Return (is_open, banner)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        banner = ""
        probe = _probe_bytes(port, host) if use_probe else None
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
) -> Dict[int, Dict[str, Any]]:
    results: Dict[int, Dict[str, Any]] = {}
    order = list(ports)
    if cfg.shuffle_ports:
        random.shuffle(order)
    use_probe = not cfg.minimal_probes
    for p in order:
        ok, banner = scan_port(
            host, p, timeout=cfg.port_timeout, use_probe=use_probe
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
) -> Dict[int, Dict[str, Any]]:
    """
    Scan ports in parallel (default) or sequentially with jitter (stealth).
  """
    if not ports:
        return {}
    cfg = stealth or StealthConfig()
    if cfg.enabled:
        return _scan_ports_stealth(host, ports, cfg)

    results: Dict[int, Dict[str, Any]] = {}
    workers = min(max_workers, max(1, len(ports)))

    def _task(p: int) -> Tuple[int, bool, str]:
        ok, banner = scan_port(host, p, timeout=timeout, use_probe=True)
        return p, ok, banner

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_task, p): p for p in ports}
        for fut in as_completed(futures):
            port, ok, banner = fut.result()
            results[port] = {"open": ok, "banner": banner if ok else ""}
    return results
