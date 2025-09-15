# Vulnerability Scanner

**Lightweight scanner in Python.**

This project quickly scan network security, TLS/HTTPS, and web security headers of target host.

---

## Key Highlights

- **Port Scanning & Banner Detection**: Identify open TCP ports and gather service banners.  
- **TLS Certificate Analysis**: Detect certificate validity and expiry on HTTPS hosts.  
- **HTTP Security Header Checks**: Identify missing security headers (HSTS, CSP, X-Frame-Options, etc.).  
- **Flexible Targeting**: Accepts hostnames, IPs, or full URL.
- **Safe Testing**: Supports testing on local machines or publicly allowed test servers.  
- **CVE/CVSS**: Reference to NVD NIST vulnerabilities database with related keywords.
- **Report**: Results are available and aggregated in JSON and .txt format.

---

## Quick Usage

### Scan a hostname/IP
```bash
python main.py --target example.com --ports 22 80 443