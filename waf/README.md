# Bastion WAF & Apex Global Bank Security Portal

A high-performance Web Application Firewall (WAF) reverse proxy, real-time security dashboard, management REST API, and vulnerable banking application with interactive staff security toggles.

---

## Quick Start

```bash
# Start all 3 services concurrently
./start.sh
# or
python3 main.py
```

### Active Service Endpoints

| Component | URL | Description |
|---|---|---|
| **WAF Security Dashboard** | `http://127.0.0.1:8000` | Real-time SOC dashboard, live charts, rule toggles, site proxy manager, and payload inspector. |
| **Protected Bank Portal** | `http://127.0.0.1:8080` | Client banking interface routed through the Bastion WAF reverse proxy. |
| **Staff & Security Center** | `http://127.0.0.1:8080/staff` | Staff dashboard with live toggles for vulnerability and remediation modes. |
| **Direct Bank Target** | `http://127.0.0.1:5000` | Upstream bank server (bypasses WAF proxy for direct vulnerability testing). |

---

## OWASP Core Rule Set (CRS) Coverage

1. **SQL Injection Shield (Rule 942100)**: Detects UNION queries, boolean tautologies, stacked queries, `SLEEP()` / `BENCHMARK()`, and schema enumeration.
2. **Cross-Site Scripting Filter (Rule 941100)**: Blocks `<script>`, event handlers (`onload=`, `onerror=`), `javascript:` URIs, SVG execution, and DOM manipulation.
3. **Path Traversal / LFI Guard (Rule 930120)**: Intercepts `../`, `/etc/passwd`, `/proc/self/`, and Windows `win.ini` file reads.
4. **Remote Code Execution Engine (Rule 932100)**: Mitigates chained shell commands (`; whoami`, `| cat`), subshells `$(...)`, and backticks.
5. **SSRF Guard (Rule 934100)**: Restricts loopbacks (`127.0.0.1`, `localhost`), private RFC 1918 subnets, and AWS/GCP cloud metadata queries (`169.254.169.254`).

---

## 8 Banking Vulnerability Simulation Labs

- **SQLi**: `/search?q=...` (Ledger search)
- **Reflected XSS**: `/comment?msg=...` (Customer inquiry)
- **Stored XSS**: `/tickets` & `/ticket/new` (Support tickets)
- **RCE**: `/exec?cmd=...` (Server diagnostic)
- **Path Traversal / LFI**: `/file?name=...` (Statement downloader)
- **SSRF**: `/webhook?url=...` (FX exchange rate webhook)
- **IDOR**: `/account/view?id=...` (Account record viewer)
- **CSRF**: `/transfer?to_account=...&amount=...` (Fund wire transfer)
- **SSTI**: `/receipt?name=...` (Branded receipt generator)

---

## Running Automated Tests

```bash
/home/abrham/bastion/venv/bin/pytest -v tests
```
