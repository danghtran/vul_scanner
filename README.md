# Vulnerability Scanner

Lightweight **external reconnaissance and triage** tool in Python. It probes open TCP ports and banners, runs a **TLS assessment**, checks HTTP security headers, gathers **DNS and passive web inventory**, then enriches findings from the **NVD** (keyword search), applies **match confidence**, **CISA KEV** context, and **relevance-aware prioritization**. Configuration issues and credible CVEs are merged into a single **action queue**. Results are written to JSON and a plain-text report.

Use only on systems you are **authorized** to assess. NVD and CISA feeds are subject to **rate limits** and terms of use—avoid aggressive scanning against production APIs.

---

## Key capabilities

| Area | What it does |
|------|----------------|
| **Discovery** | Parallel TCP scan with **port profiles** (`common` / `extended` / `full`), service **probes** (HTTP, SMTP, Redis, etc.), **TLS** on 443/8443/465/993/636 when open, HTTP checks on common web ports. |
| **Inventory / context** | **DNS**: A/AAAA, **MX**, apex **TXT/SPF**, **`_dmarc`**, **CAA** (Google Public DNS JSON API). **HTTP transport**: **redirect chain**, **HSTS** parsing, **cookie** Secure/HttpOnly/SameSite audit; passive web inventory (`Server`, tech hints, `robots.txt`, `security.txt`). |
| **Observations** | Normalizes probes into structured **observations** (TCP, TLS, HTTP headers, DNS, web inventory) with evidence and **keyword provenance** (`version`, `banner_token`, `port_hint`, `inventory`, `tls`, `header`). |
| **NVD enrichment** | **Version-first** keyword selection (`openssh 6.6.1` before generic `ssh`); skips header/TLS template NVD queries when product versions are known. |
| **Validation (confidence)** | Each CVE is labeled **`corroborated`**, **`potential`**, or **`heuristic`** from how the keyword was derived. |
| **Threat context** | **CISA KEV** flag per CVE; **FIRST EPSS** (exploit probability + percentile) via public API, folded into priority score and triage (`EPSS_ENABLED=0` to disable). |
| **Triage** | **Configuration findings** (TLS failures, missing headers, cleartext HTTP, EOL OpenSSH, etc.) ranked with CVEs. **Relevance** (`high` / `medium` / `low`) filters noisy NVD hits (wrong product, generic header matches). Unified **`action_queue`** in JSON and report. |
| **AI (optional)** | **Mistral** suggestions under `ai_suggestions` only—**advisory**, not used for scoring or validation. |

---

## Requirements

- **Python 3.10+** (stdlib: `urllib`, `json`, `ssl`, `socket`).
- Optional: **`requests`** for Mistral — `pip install requests`
- **Mistral API key** (optional): set **`MISTRAL_API_KEY`** in the environment, or in **`api_key.env`** as `MISTRAL_API_KEY=your_key` (ignored by git via `*.env`). Environment variable wins over the file.

---

## Quick usage

### Scan a hostname or IP

```bash
python main.py --target example.com --profile extended
python main.py --target example.com --profile full --port-timeout 1.5
python main.py --target example.com --stealth --profile common
python main.py --target example.com --ports 22 80 443
```

### Scan from a full URL (ports default from scheme if omitted)

```bash
python main.py --target https://example.com
```

### Prioritization context (internet-facing / production)

```bash
python main.py --target scanme.nmap.org --ports 22 80 --internet-facing --environment prod
```

### Custom JSON output path

```bash
python main.py --target example.com --output my_scan.json
```

### Outputs

| File | Description |
|------|-------------|
| **`--output`** (default `scan_report.json`) | Full structured JSON (see below). |
| **`scan_report.txt`** | Human-readable report: triage summary, **action queue**, config findings, prioritized CVEs, low-confidence CVE appendix. |

---

## CLI reference

| Argument | Description |
|----------|-------------|
| `--target` | **Required.** Hostname, IP, or `http(s)://` URL. |
| `--ports` | Optional space-separated TCP ports (overrides `--profile`). |
| `--profile` | `common` (~10), `extended` (~36, default), or `full` (~71) ports. |
| `--port-timeout` | TCP connect timeout per port in seconds (default `1.0`). |
| `--stealth` | Low-and-slow: sequential ports with random delays, minimal banners, fewer/throttled NVD queries. |
| `--output` | JSON output file path (default: `scan_report.json`). |
| `--internet-facing` | Raises priority scores when the asset is treated as internet-exposed. |
| `--environment` | Context label (e.g. `prod`); `prod` adds a production weight in scoring. |

---

## JSON output (main fields)

| Field | Purpose |
|-------|---------|
| `observations` | Normalized evidence per port, TLS, headers, DNS, web inventory. |
| `dns_context` | IPv4/IPv6, MX, SPF, DMARC, CAA, `asset_context`. |
| `web_inventory` | Passive HTTP fingerprint and discovery files. |
| `tls` | Full TLS assessment result. |
| `configuration_findings` | Actionable misconfigurations from the scan (not NVD). |
| `vulnerabilities` / `cves` | All NVD keyword matches with scores, relevance, and **`epss` / `epss_percentile`**. |
| `epss_status` | `ok`, `skipped`, `partial`, or `error` for the EPSS API batch. |
| `cve_prioritized` | High/medium relevance CVEs (and KEV). |
| `cve_low_confidence` | Likely false positives from generic keywords. |
| `action_queue` | **Top items to fix first** (config + prioritized CVEs). |
| `remediation_queue` | Same queue in a compact shape for export. |
| `detected_products` | Products used for CVE relevance (e.g. `openssh`, `apache`). |
| `risk` | Summary counts, tier breakdown, highest CVSS in prioritized set. |
| `ai_suggestions` | Optional Mistral output (advisory only). |
| `scan_context` | Flags passed on the CLI (`internet_facing`, `environment`). |

---

## How triage works

1. **Collect** — Ports, banners, TLS, headers, DNS, web inventory → **observations** with keyword provenance.
2. **Enrich** — NVD keyword search per observation; **KEV** check per CVE ID.
3. **Score** — CVSS, KEV, validation weight, and scan context (`--internet-facing`, `--environment prod`).
4. **Relevance** — Compare CVE text to **detected products**; **version-aware** down-rank when installed banner version is newer than the CVE’s “before X” / “X and earlier” range.
5. **EPSS** — [FIRST EPSS](https://www.first.org/epss/) scores boost priority; CVEs with **EPSS percentile >= 0.90** can stay in the prioritized set even when relevance is low (verify manually).
6. **Queue** — **Configuration findings** ranked **before** high-relevance / high-EPSS CVEs in **`action_queue`**.

---

## Limitations

- **Non-intrusive**: no authenticated scanning, fuzzing, or OWASP Top 10–style active testing.
- **CVE linkage** is **keyword-driven** against NVD, not a full CPE/version matrix or credentialed scanner replacement.
- **Tech hints** and **relevance** are heuristics—always validate before patching.
- **NVD**, **KEV**, and inventory HTTP fetches need outbound HTTPS; failures degrade gracefully.
- **`--stealth`** spaces out ports, DNS, HTTP, and NVD calls to reduce burst traffic; it is **not** IDS/WAF evasion and still performs active probes on authorized targets only.

---

## Project layout

| Module | Role |
|--------|------|
| `main.py` | CLI and scan orchestration. |
| `port_profiles.py` | Port lists per scan profile. |
| `port_scan.py` / `banner_parse.py` | Parallel TCP scan, service probes, banners. |
| `tls_check.py` | TLS handshake, cert fields, legacy protocol probes. |
| `http_header_check.py` | Security header probes. |
| `dns_lookup.py` | Extended DNS (MX, SPF, DMARC, CAA). |
| `http_transport.py` | Redirect chains, HSTS, cookie audit. |
| `inventory_context.py` | Passive web inventory (uses `http_transport`). |
| `observations.py` / `version_extract.py` | Observation model and banner version parsing. |
| `cve_lookup.py` | NVD CVE 2.0 keyword search. |
| `kev.py` | CISA KEV catalog lookup. |
| `epss.py` | FIRST EPSS batch lookup (in-process cache). |
| `prioritize.py` | Base priority score and P1–P5 tiers (CVSS, KEV, EPSS). |
| `risk_label.py` | Observations → NVD merge → triage pipeline. |
| `triage.py` | Configuration findings, CVE relevance, action queue. |
| `version_match.py` | Version-aware CVE applicability (banner vs CVE text). |
| `keyword_select.py` | Priority ordering and filtering for NVD keyword queries. |
| `stealth.py` | Low-and-slow timing options for `--stealth` scans. |
| `report_gen.py` | JSON and text report writers. |
| `mistral_ai.py` | Optional LLM helper (loads `api_key.env` if needed). |
