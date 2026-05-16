import argparse
from datetime import datetime, timezone

from banner_parse import parse_banner
from http_header_check import check_http_headers
from dns_lookup import gather_dns_extended
from inventory_context import gather_web_inventory, resolve_inventory_base_url
from port_profiles import DEFAULT_PROFILE, HTTP_PROBE_PORTS, TLS_PROBE_PORTS, ports_for_profile
from port_scan import scan_ports
from risk_label import risk_from_findings
from report_gen import generate_text_report, save_json
from stealth import StealthConfig, from_scan_context, phase_pause
from tls_check import check_tls_cert

from urllib.parse import urlparse

def normalize_target(target, ports):
    # If full URL, parse it
    if target.startswith("http"):
        parsed = urlparse(target)
        host = parsed.hostname
        scheme = parsed.scheme

        # If no custom ports given, pick from scheme
        if not ports:
            if scheme == "https":
                ports = [443]
            elif scheme == "http":
                ports = [80]
        return host, ports, scheme
    else:
        # Just a host/IP
        return target, ports, None


def _pick_http_url(host: str, scheme: str | None, open_ports: list) -> str | None:
    if scheme and str(scheme).startswith("http"):
        return f"{scheme}://{host}/"
    for port in HTTP_PROBE_PORTS:
        if port not in open_ports:
            continue
        if port in (443, 8443):
            return f"https://{host}/"
        if port in (80, 8080, 8000, 8888):
            return f"http://{host}/"
    return None


def run_scan(target, ports, scan_context=None, profile=None, port_timeout=1.0, stealth=None):
    host, ports, scheme = normalize_target(target, ports)
    ctx = scan_context or {}
    stealth_cfg = stealth if isinstance(stealth, StealthConfig) else from_scan_context(ctx)
    scan_profile = (profile or DEFAULT_PROFILE).strip().lower()
    if stealth_cfg.enabled and not ports and scan_profile == "full":
        scan_profile = "extended"
    if ports:
        ports_list = list(ports)
    else:
        ports_list = ports_for_profile(scan_profile)

    effective_timeout = stealth_cfg.port_timeout if stealth_cfg.enabled else port_timeout

    findings = {
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat() + "Z",
        "port_banners": {},
        "host": host,
        "scheme": scheme,
        "scan_profile": scan_profile,
        "ports_scanned": ports_list,
        "stealth_mode": stealth_cfg.enabled,
    }
    if stealth_cfg.enabled:
        findings["stealth_settings"] = stealth_cfg.to_dict()
    open_ports = []

    scan_results = scan_ports(
        host, ports_list, timeout=effective_timeout, stealth=stealth_cfg
    )
    for p in ports_list:
        row = scan_results.get(p) or {}
        if row.get("open"):
            findings["port_banners"][p] = parse_banner(row.get("banner") or "")
            open_ports.append(p)

    findings["open_ports"] = sorted(open_ports)
    phase_pause(stealth_cfg)

    tls_by_port = {}
    for p in TLS_PROBE_PORTS:
        if p in open_ports:
            try:
                tls_by_port[p] = check_tls_cert(host, port=p)
            except Exception:
                tls_by_port[p] = None
            phase_pause(stealth_cfg)
    findings["tls_by_port"] = tls_by_port
    findings["tls"] = tls_by_port.get(443)
    if findings["tls"] is None:
        for p in TLS_PROBE_PORTS:
            if tls_by_port.get(p):
                findings["tls"] = tls_by_port[p]
                break

    headers = None
    http_url = _pick_http_url(host, scheme, open_ports)
    if http_url:
        try:
            headers = check_http_headers(http_url)
        except Exception:
            headers = None
    findings["http_headers"] = headers
    findings["http_probe_url"] = http_url
    phase_pause(stealth_cfg)

    findings["dns_context"] = gather_dns_extended(
        host, query_delay=stealth_cfg.dns_query_delay if stealth_cfg.enabled else 0
    )
    phase_pause(stealth_cfg)
    inv_url = resolve_inventory_base_url(host, scheme, open_ports, target)
    if inv_url:
        try:
            findings["web_inventory"] = gather_web_inventory(
                inv_url,
                host=host,
                open_ports=open_ports,
                request_delay=stealth_cfg.http_delay if stealth_cfg.enabled else 0,
            )
        except Exception:
            findings["web_inventory"] = {
                "fetch_error": "inventory_gather_failed",
                "entry_url": inv_url,
            }
    else:
        findings["web_inventory"] = None

    findings["scan_context"] = scan_context or {}
    findings["risk"] = risk_from_findings(findings, scan_context)

    return findings


def parse_ports_list(ports_list):
    if not ports_list:
        return None
    return [int(p) for p in ports_list]

def main():
    parser = argparse.ArgumentParser(description='Vulnerability scanner')
    parser.add_argument('--target', required=True, help='Hostname or IP to scan (e.g. example.com)')
    parser.add_argument('--ports', nargs='*', type=int, help='Optional list of ports to scan (overrides --profile)')
    parser.add_argument(
        '--profile',
        choices=['common', 'extended', 'full'],
        default=DEFAULT_PROFILE,
        help='Port list: common (~10), extended (~30, default), full (~55)',
    )
    parser.add_argument(
        '--port-timeout',
        type=float,
        default=1.0,
        help='TCP connect timeout per port in seconds (default 1.0)',
    )
    parser.add_argument('--output', default='scan_report.json', help='JSON output path')
    parser.add_argument(
        '--internet-facing',
        action='store_true',
        help='Assume target is internet-exposed (raises priority scores)',
    )
    parser.add_argument(
        '--environment',
        default='',
        help='Context label for prioritization, e.g. prod or nonprod',
    )
    parser.add_argument(
        '--stealth',
        action='store_true',
        help='Low-and-slow scan: sequential ports with jitter, minimal probes, throttled NVD/DNS/HTTP',
    )
    args = parser.parse_args()

    scan_context = {
        'internet_facing': bool(args.internet_facing),
        'environment': (args.environment or '').strip(),
        'stealth': bool(args.stealth),
    }
    stealth_cfg = from_scan_context(scan_context)
    findings = run_scan(
        args.target,
        ports=args.ports,
        scan_context=scan_context,
        profile=args.profile,
        port_timeout=args.port_timeout,
        stealth=stealth_cfg,
    )

    save_json(args.output, findings)
    generate_text_report(args.target, findings, out_path='scan_report.txt')

    print('Scan complete.')
    print('JSON output ->', args.output)
    print('Text report -> scan_report.txt')

if __name__ == '__main__':
    main()