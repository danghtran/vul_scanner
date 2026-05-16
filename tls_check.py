import ipaddress
import socket
import ssl
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


def _format_x509_name(name_tuple) -> str:
    if not name_tuple:
        return ""
    parts = []
    for rdn in name_tuple:
        for attr, val in rdn:
            parts.append(f"{attr}={val}")
    return ", ".join(parts)


def _peer_cert_dict(ssock: ssl.SSLSocket) -> Optional[dict]:
    try:
        return ssock.getpeercert()
    except Exception:
        return None


def _extract_san_dns(cert: dict) -> List[str]:
    out: List[str] = []
    san = cert.get("subjectAltName")
    if not san:
        return out
    for entry in san:
        if len(entry) >= 2 and entry[0].upper() == "DNS":
            out.append(str(entry[1]))
    return out


def _cn_from_subject(cert: dict) -> str:
    subj = cert.get("subject")
    if not subj:
        return ""
    for rdn in subj:
        for attr, val in rdn:
            if attr == "commonName":
                return str(val)
    return ""


def _hostname_matches_cert(host: str, cert: dict) -> Optional[bool]:
    """True if host matches CN or SAN; None if unable to decide (e.g. no cert data)."""
    if not cert:
        return None
    try:
        ipaddress.ip_address(host)
        # IP connect: Python verified IP in SAN if verification passed
        return True
    except ValueError:
        pass
    h = host.lower().rstrip(".")
    cn = _cn_from_subject(cert).lower().rstrip(".")
    if cn and (h == cn or _wildcard_match(cn, h)):
        return True
    for dns in _extract_san_dns(cert):
        d = dns.lower().rstrip(".")
        if h == d or _wildcard_match(d, h):
            return True
    return False


def _wildcard_match(pattern: str, host: str) -> bool:
    if not pattern.startswith("*."):
        return False
    suffix = pattern[1:].lower()  # .example.com
    h = host.lower()
    if not h.endswith(suffix):
        return False
    left = h[: -len(suffix)]
    return "." not in left


def _protocol_probe(
    host: str, port: int, timeout: float, min_ver: ssl.TLSVersion, max_ver: ssl.TLSVersion
) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = min_ver
        ctx.maximum_version = max_ver
    except (ValueError, AttributeError):
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host if host else None) as _:
                return True
    except OSError:
        return False
    except ssl.SSLError:
        return False


def scan_tls(
    host: str,
    port: int = 443,
    timeout: float = 3.0,
    probe_legacy_protocols: bool = True,
) -> Optional[Dict[str, Any]]:
    """
    Full TLS scan: verified handshake, negotiated version/cipher, certificate fields,
    SAN, hostname match heuristic, and optional legacy protocol acceptance probes.
    """
    if not host:
        return None

    ctx = ssl.create_default_context()
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "handshake_ok": False,
        "handshake_error": None,
        "tls_version": None,
        "cipher": None,
        "expires": None,
        "days_left": None,
        "self_signed": None,
        "subject": None,
        "issuer": None,
        "san_dns": [],
        "serial_number": None,
        "hostname_matches_cert": None,
        "protocols_accepted": {},
        "legacy_tls_enabled": False,
    }

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["handshake_ok"] = True
                ver = ssock.version()
                result["tls_version"] = ver
                ci = ssock.cipher()
                if ci:
                    result["cipher"] = {
                        "name": ci[0],
                        "protocol": ci[1],
                        "secret_bits": ci[2],
                    }

                cert = _peer_cert_dict(ssock)
                if cert:
                    not_after = cert.get("notAfter")
                    if not_after:
                        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        result["expires"] = expires.isoformat() + "Z"
                        result["days_left"] = (expires - datetime.utcnow()).days
                    subj = cert.get("subject")
                    iss = cert.get("issuer")
                    result["subject"] = _format_x509_name(subj)
                    result["issuer"] = _format_x509_name(iss)
                    result["self_signed"] = bool(subj and iss and subj == iss)
                    result["san_dns"] = _extract_san_dns(cert)
                    sn = cert.get("serialNumber")
                    if sn is not None:
                        result["serial_number"] = str(sn)
                    result["hostname_matches_cert"] = _hostname_matches_cert(host, cert)

    except ssl.SSLCertVerificationError as e:
        result["handshake_error"] = f"cert_verification: {e.reason}"
        return result
    except ssl.SSLError as e:
        result["handshake_error"] = f"ssl_error: {e!s}"
        return result
    except OSError as e:
        result["handshake_error"] = f"connection: {e!s}"
        return result
    except Exception as e:
        result["handshake_error"] = str(e)
        return result

    if probe_legacy_protocols and result["handshake_ok"]:
        for label, min_v, max_v in (
            ("TLSv1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
        ):
            try:
                ok = _protocol_probe(host, port, min(timeout, 2.5), min_v, max_v)
            except Exception:
                ok = False
            result["protocols_accepted"][label] = ok
        leg = result["protocols_accepted"].get("TLSv1.0") or result["protocols_accepted"].get(
            "TLSv1.1"
        )
        result["legacy_tls_enabled"] = bool(leg)

    return result


def check_tls_cert(host, port=443, timeout=3.0):
    """Entry point used by main: full TLS assessment including legacy protocol probes."""
    return scan_tls(host, port=port, timeout=timeout, probe_legacy_protocols=True)
