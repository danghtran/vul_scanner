import argparse
from datetime import datetime, timezone

from port_scan import scan_port
from banner_parse import parse_banner
from tls_check import check_tls_cert
from http_header_check import check_http_headers
from inventory_context import gather_dns_context, gather_web_inventory, resolve_inventory_base_url
from risk_label import risk_from_findings
from report_gen import generate_text_report, save_json

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


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]

def run_scan(target, ports, scan_context=None):
    host, ports, scheme = normalize_target(target, ports)
    ports = ports or COMMON_PORTS
    findings = {
        'target': target, 
        'scanned_at': datetime.now(timezone.utc).isoformat() + 'Z', 
        'port_banners': {},
        'host': host,
        'scheme': scheme
    }
    open_ports = []

    for p in ports:
            ok, banner = scan_port(host, p)
            if ok:
                findings['port_banners'][p] = parse_banner(banner)
                open_ports.append(p)

    findings['open_ports'] = open_ports

    if 443 in open_ports or 443 in ports:
        try:
            tls = check_tls_cert(host, port=443)
            findings['tls'] = tls
        except Exception:
            findings['tls'] = None
    else:
        findings['tls'] = None

    headers = None
    if any(p in open_ports for p in (80, 443)):
        if scheme is None:
            try:
                headers = check_http_headers(f'https://{host}/')
            except Exception:
                headers = check_http_headers(f'http://{host}/')
        else:
            headers = check_http_headers(target)
    findings['http_headers'] = headers

    findings["dns_context"] = gather_dns_context(host)
    inv_url = resolve_inventory_base_url(host, scheme, open_ports, target)
    if inv_url:
        try:
            findings["web_inventory"] = gather_web_inventory(inv_url)
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
    parser.add_argument('--ports', nargs='*', type=int, help='Optional list of ports to scan')
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
    args = parser.parse_args()

    scan_context = {
        'internet_facing': bool(args.internet_facing),
        'environment': (args.environment or '').strip(),
    }
    findings = run_scan(args.target, ports=args.ports, scan_context=scan_context)

    save_json(args.output, findings)
    generate_text_report(args.target, findings, out_path='scan_report.txt')

    print('Scan complete.')
    print('JSON output ->', args.output)
    print('Text report -> scan_report.txt')

if __name__ == '__main__':
    main()