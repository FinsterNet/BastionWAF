# Bastion WAF — Next-Gen Security Gateway & SOC

A high-performance Web Application Firewall (WAF) reverse proxy featuring a SafeLine-inspired Semantic Analysis Engine (AST Tokenizer & Grammar Parsers), categorized threat protection (OWASP Top 10, API Security, Bot Protection), and real-time SOC management dashboard.

---

## Quick Start

```bash
# Start WAF Gateway and SOC Dashboard concurrently
./start.sh
# or
python3 main.py
```

### Active Service Endpoints

| Component | URL | Description |
|---|---|---|
| **WAF Security Dashboard** | `http://127.0.0.1:8000` | Real-time SOC dashboard, live traffic charts, 28 categorized rule toggles, site manager, and payload inspector. |
| **Protected Proxy Gateway** | `http://127.0.0.1:8080` | High-performance WAF reverse proxy filtering and forwarding traffic to your upstream web applications. |

---

## SafeLine-Inspired Semantic Detection Engine

Bastion WAF uses a **context-aware lexical tokenizer and AST grammar analysis engine** to eliminate false positives on natural language, mathematics, and legitimate user text while catching zero-day evasions:
- **SQL Lexer & AST Validator**: Evaluates true tautologies, stacked DDL/DML, and dangerous function calls in query contexts rather than blind keyword matching.
- **Context-Aware HTML/JS Lexer**: Analyzes HTML tag structures, DOM event handlers, and pseudo-protocol URIs without blocking math comparisons or standard dialogue words.
- **Shell Grammar Analyzer**: Validates shell chaining operators and subshells preceding executable command binaries.
- **Canonical Path Resolver**: Evaluates directory breakout bounds and critical OS file access.
- **Multi-Format IP Decoder**: Decodes decimal integer, hex, octal, and IPv6 SSRF attempts to enforce strict CIDR boundary policies.

---

## 🧩 Adaptive Risk-Based Slider CAPTCHA Challenge

Bastion WAF features a **3-Tier Adaptive Response Policy**:
1. **Tier 1 (Critical Exploits - SQLi, RCE, LFI, Webshells)**: Instant **HTTP 403 Hard Block**.
2. **Tier 2 (Suspicious Anomalies / Traffic Surges / Bot Scanners)**: Intercepts and serves an interactive, dark-themed **Slider CAPTCHA Challenge**.
3. **Tier 3 (Verified Human / Clean Traffic)**: Issues a cryptographically signed HMAC clearance cookie (`bastion_waf_clearance`, 15-min TTL) and forwards seamless traffic to your upstream service.

---

## Categorized Attack Coverage (28 Active Rules)

### 🛡️ Category 1: OWASP Top 10 Web Application Security
1. **SQL Injection Shield (Rule 942100)**: Semantic AST detection of UNION queries, boolean tautologies, stacked queries, `SLEEP()`, and schema enumeration.
2. **Cross-Site Scripting Filter (Rule 941100)**: Context-aware blocking of `<script>`, event handlers (`onload=`, `onerror=`), `javascript:` URIs, and SVG vectors.
3. **Path Traversal / LFI Guard (Rule 930120)**: Intercepts `../`, `/etc/passwd`, `/proc/self/`, and Windows `win.ini` file reads.
4. **Remote Code Execution Engine (Rule 932100)**: Mitigates chained shell commands (`; whoami`, `| cat`), subshells `$(...)`, and backticks.
5. **SSRF Guard (Rule 934100)**: Restricts loopbacks, private RFC 1918 subnets, cloud metadata queries (`169.254.169.254`), and multi-format IP evasions.
6. **Server-Side Template Injection Guard (Rule 933100)**: Detects template expressions (`{{...}}`, `${...}`) and Jinja2/Spring sandbox escapes.
7. **XML External Entity Shield (Rule 933200)**: Mitigates DTD external entity declarations (`SYSTEM "file://..."`) and parameter entity inclusions.
8. **Insecure Deserialization Shield (Rule 933300)**: Detects Java serialized objects (`rO0AB...`), PHP `O:4:"User"...`, and Python pickle opcodes.
9. **Malicious File Upload & Webshell Guard (Rule 933400)**: Blocks executable extensions (`.php`, `.jsp`, `.sh`), double extensions, and inline webshells (`eval($_POST)`).
10. **JNDI / Log4j Lookup Shield (Rule 933500)**: Mitigates Log4Shell (`${jndi:ldap://...}`), Spring4Shell, and nested lookup evasions.
11. **JavaScript Prototype Pollution Filter (Rule 933600)**: Blocks `__proto__`, `constructor.prototype`, and accessor method pollution.
12. **CRLF Injection & Request Smuggling Shield (Rule 921100)**: Blocks header injection `\r\n` and conflicting Transfer-Encoding / Content-Length headers.
13. **Open Redirect & Host Header Injection Guard (Rule 935100)**: Intercepts protocol-relative `//evil.com` and user-info credential redirect bypasses.
14. **LDAP & XPath Injection Shield (Rule 942200)**: Mitigates LDAP filter tautologies `(&(attr=*))` and XPath injection queries.
15. **Sensitive Config & Backup Snooping Guard (Rule 930200)**: Blocks automated probing for `.env`, `.git`, cloud keys, and database dumps (`dump.sql`).

### 🔌 Category 2: API Security & Abuse Protection
16. **API Mass Assignment Guard (Rule 950100)**: Prevents unauthorized privilege escalation fields (`"role": "admin"`, `"is_admin": true`) in JSON bodies.
17. **GraphQL Introspection & Depth Abuse Guard (Rule 950200)**: Blocks full schema extraction (`__schema`, `__type`) and deep recursive queries (>8 levels).
18. **Secret Key & Token URI Leakage Guard (Rule 950300)**: Detects sensitive API keys and access tokens exposed in GET query parameters.
19. **HTTP Verb & Method Tampering Shield (Rule 950400)**: Disallows diagnostic/insecure HTTP methods (`TRACE`, `TRACK`, `DEBUG`, `CONNECT`) and method override bypasses.
20. **JSON/XML Payload Bomb Guard (Rule 950500)**: Mitigates deeply nested JSON/XML payloads (>15 levels) designed to exhaust server CPU/RAM.
21. **CORS Origin Abuse & Null Origin Guard (Rule 950600)**: Intercepts sandboxed `Origin: null` exploitation on state-modifying requests.
22. **JWT None-Algorithm & Signature Tampering Guard (Rule 950700)**: Blocks unsigned `"alg": "none"` tokens, stripped signatures, and `kid` directory traversal.

### 🤖 Category 3: Bot Protection & Automated Threat Management
23. **Vulnerability Scanner Signatures Shield (Rule 960100)**: Identifies security scanners (`sqlmap`, `nikto`, `masscan`, `nuclei`, `gobuster`, `burpcollaborator`).
24. **Headless Automation Framework Guard (Rule 960200)**: Detects headless scraping browsers (`HeadlessChrome`, `Puppeteer`, `Selenium`, `Playwright`).
25. **Sliding-Window CC Flood & Rate Limiter (Rule 960300)**: In-memory sliding window rate limiter per client IP mitigating HTTP flood surges.
26. **Credential Stuffing & Default Credentials Guard (Rule 960400)**: Blocks default credentials (`admin/admin`, `root/toor`) on login authentication endpoints.
27. **HTTP Header Anomaly & Protocol Violation Guard (Rule 960500)**: Intercepts missing or empty `User-Agent` headers and malformed protocol headers.
28. **Cryptomining Script & Stratum Blocker (Rule 960600)**: Blocks in-browser WebAssembly cryptocurrency miners and Stratum pool connections.

---

## Running Automated Tests

```bash
pytest -v
# or
python3 -m pytest -v
```
