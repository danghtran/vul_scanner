import argparse
from datetime import datetime

from port_scan import scan_port
from banner_parse import parse_banner
from tls_check import check_tls_cert
from http_header_check import check_http_headers
from risk_label import risk_from_findings
from report_gen import generate_text_report, save_json

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]

def run_scan(target, ports=None):
    ports = ports or COMMON_PORTS
    findings = {'target': target, 'scanned_at': datetime.utcnow().isoformat() + 'Z', 'port_banners': {}}
    open_ports = []
    for p in ports:
        ok, banner = scan_port(target, p)
        if ok:
            findings['port_banners'][p] = parse_banner(banner)
            open_ports.append(p)

    findings['open_ports'] = open_ports

    if 443 in open_ports or 443 in ports:
        try:
            tls = check_tls_cert(target, port=443)
            findings['tls'] = tls
        except Exception:
            findings['tls'] = None
    else:
        findings['tls'] = None

    # HTTP headers (try https then http)
    headers = None
    try:
        headers = check_http_headers(f'https://{target}/')
    except Exception:
        headers = check_http_headers(f'http://{target}/')
    findings['http_headers'] = headers

    findings['risk'] = risk_from_findings(findings)
    return findings

def parse_ports_list(ports_list):
    if not ports_list:
        return None
    return [int(p) for p in ports_list]

def main():
    parser = argparse.ArgumentParser(description='MVP modular vulnerability & misconfiguration scanner')
    parser.add_argument('--target', required=True, help='Hostname or IP to scan (e.g. example.com)')
    parser.add_argument('--ports', nargs='*', type=int, help='Optional list of ports to scan')
    parser.add_argument('--output', default='scan_report.json', help='JSON output path')
    args = parser.parse_args()

    findings = run_scan(args.target, ports=args.ports)

    save_json(args.output, findings)
    generate_text_report(args.target, findings, out_path='scan_report.txt')

    print('Scan complete.')
    print('JSON output ->', args.output)
    print('Text report -> scan_report.txt')

if __name__ == '__main__':
    main()