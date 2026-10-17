# BASTION WAF
## An Inline Reverse-Proxy Web Application Firewall for Local Digital Systems

* **Target Incubation Center:** Business Incubation and Techno-Entrepreneurship Center (BiTec), Poly Campus
* **Institution:** Bahir Dar Institute of Technology (BiT), Bahir Dar University
* **Applicant:** Robel Shitahun
* **Academic Level:** 3rd Year Cybersecurity Student, Faculty of Computing
* **Project Status:** Functional Working MVP (~0.42 ms Local Inspection Latency, 2 Months Active Development)
* **Date:** September 2026

---

## 1. Executive Summary

Every public-facing website, university portal, and web application is continuously targeted by automated scanners, botnets, and vulnerability fuzzers. While federal institutions and major commercial banks have the financial resources for enterprise security appliances, our local digital ecosystem—university services, student projects, regional startups, and healthcare providers—faces two practical dead ends:

1. **Foreign Currency Deadlock:** Leading commercial cloud WAFs (such as Cloudflare, AWS WAF, and Akamai) require recurring subscriptions billed strictly in US Dollars via international credit cards. With severe domestic forex restrictions in Ethiopia, local developers and small businesses cannot legally or reliably pay for these services.
2. **Operational Complexity of Open-Source Tools:** The standard open-source alternative, ModSecurity, lacks an integrated graphical user interface and requires manual terminal-based rule maintenance across dozens of complex Apache/Nginx configuration files. Small IT teams and independent developers routinely misconfigure or abandon it, leaving critical endpoints completely unprotected.

Over the past two months, I designed and built **Bastion WAF** to solve this exact gap. Bastion is a lightweight, inline reverse-proxy Web Application Firewall built to run directly on standard commodity hardware. 

The software is not a theoretical concept; it is an active, functional prototype. Benchmarking on my local machine shows an average inspection latency of **~0.42 milliseconds per payload**, meaning it filters traffic without introducing perceptible lag to legitimate end users. The engine actively mitigates primary OWASP Top 10 vectors—including SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal / Local File Inclusion (LFI), Server-Side Request Forgery (SSRF), and Remote Code Execution (RCE)—while streaming live telemetry to a centralized web dashboard. 

I am applying to BiTec to take Bastion from an individual development project on my laptop into a production-tested, hardened network security platform evaluated under real campus network traffic.

---

## 2. Problem Statement

Web services deployed across our regional and national tech ecosystem are routinely deployed with zero perimeter inspection. This stems from three specific barriers:

* **The Foreign Exchange Barrier:** International cloud security providers demand monthly USD credit card transactions. Even when regional developers have budget in Ethiopian Birr (ETB), they have no direct mechanism to convert or pay for foreign subscriptions.
* **The Usability and Maintenance Deficit:** Existing self-hosted tools (ModSecurity with OWASP Core Rule Set) require deep Linux systems engineering and manual regex tuning. When a false positive blocks a valid user, sysadmins are forced to parse raw log files and craft custom exclusion rules by hand. Most small organizations lack the dedicated security personnel to sustain this.
* **The Institutional Security Divide:** While high-tier federal infrastructure receives specialized protection, regional departmental platforms, student records portals, and local clinic management platforms remain exposed to script kiddies and automated crawlers probing for trivial vulnerabilities.

---

## 3. Market Fit & Competitive Comparison

Bastion targets the neglected **middle tier** of web infrastructure: systems that process real user data in Ethiopia but cannot access foreign enterprise firewalls.

### Target Beneficiaries
1. **Academic & Departmental Portals (BiT / Bahir Dar University):** Student grading portals, departmental registration tools, and faculty research sites that endure constant network scanning but lack dedicated SOC staff.
2. **Local SMEs & Regional Startups:** Regional software houses, e-commerce stores, and healthcare platforms that operate entirely in Ethiopian Birr and need turnkey security.
3. **Public Regional Institutions:** Municipal administrative offices and regional educational bureaus that are legally or policy-bound to keep all traffic data and audit logs strictly on physical, on-premises servers within national borders.

### Competitive Matrix

| Evaluation Criteria | International Cloud WAFs (Cloudflare / AWS) | Open-Source Legacy (ModSecurity / Coraza) | **Bastion WAF (Proposed Solution)** |
| :--- | :--- | :--- | :--- |
| **Billing & Currency** | Recurring USD via International Visa/Mastercard | Free, but high human labor cost | **100% Ethiopian Birr (Telebirr & CBE Birr)** |
| **Data Sovereignty** | Traffic routes through foreign edge nodes | On-Premises | **Strictly On-Premises / Local Infrastructure** |
| **Management UX** | Commercial Cloud Console | Command-line text files (`.conf`) | **Self-Contained Real-Time Web Dashboard** |
| **Detection Method** | Proprietary cloud heuristics | Static regular expression matching | **Deterministic Semantic AST Lexer + CRS Signatures** |
| **Bot & Scanner Defense** | Cloudflare Turnstile (Cloud-dependent) | Basic connection rate limits | **3-Tier Adaptive Slider CAPTCHA (Self-Hosted)** |
| **Resource Footprint** | Massive cloud infrastructure | Moderate to high CPU spikes | **Sub-millisecond on Standard Commodity PCs** |

---

## 4. Project Objectives

### General Objective
To develop, validate, and deploy a low-latency, self-hosted inline Web Application Firewall that automates web application security on commodity computing hardware, backed by a local payment model suited to Ethiopia's digital economy.

### Specific Objectives
1. **Low-Latency Inline Interception:** Intercept HTTP/HTTPS requests at the reverse-proxy boundary, maintaining an average payload inspection latency below **1.0 millisecond** under sustained concurrency.
2. **Multi-Pass Payload Normalization:** De-obfuscate incoming requests across recursive URL encoding, HTML entity mapping, Unicode NFKC normalization, and comment injection techniques before rule evaluation.
3. **Hybrid Detection Engine:** Combine static OWASP Core Rule Set signatures with deterministic Abstract Syntax Tree (AST) grammar tokenizers to accurately distinguish malicious execution syntax from benign text.
4. **Adaptive Challenge Policy:** Implement a 3-tier action response (Block, Challenge, Allow) utilizing an interactive, self-hosted Slider CAPTCHA for suspicious requests to drastically minimize false-positive friction.
5. **Operational Telemetry Dashboard:** Provide an accessible, browser-based management interface for real-time audit logging, rule toggles, and live system health monitoring without requiring terminal commands.
6. **Commercialization Integration:** Implement recurring domestic subscription licensing and turnkey hardware appliance delivery billed via Telebirr and CBE Birr.

---

## 5. Technical Architecture & Defense Pipeline

Bastion is positioned inline as a reverse proxy directly in front of the origin web server or container cluster.

```
Incoming Request
      │
      ▼
┌────────────────────────────────────────────────────────┐
│  Bastion Reverse Proxy (FastAPI / HTTPX Gateway :8080) │
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Stage 1: Multi-Pass Recursive Normalizer              │
│  - URL Decode • HTML Entity Translation • NFKC Unicode │
│  - Comment Stripping (UNI/**/ON -> UNION)              │
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Stage 2: Hybrid Inspection & Semantic AST Lexer       │
│  - 28 Active Rules (OWASP Top 10, API, Bot Protection) │
│  - SQL Grammar & Tautology Tokenizer (AST Evaluation)  │
│  - Shell Command Chaining & Path Traversal Canonicalizer│
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Stage 3: 3-Tier Adaptive Risk Decision                │
│                                                        │
│  ├─ Score ≥ 70: Tier 1 ──> 403 Forbidden Blocked       │
│  │                                                     │
│  ├─ 40 ≤ Score < 70: Tier 2 ──> Interactive CAPTCHA    │
│  │   (Validated with mouse trajectory & signed HMAC)   │
│  │                                                     │
│  └─ Score < 40: Tier 3 ──> 200 Forward Upstream        │
└─────────────────────────────┬──────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────┐
│  Origin Web Application / Internal Department Service  │
└────────────────────────────────────────────────────────┘
```

### Core Pipeline Components

1. **Multi-Pass Normalization Layer:** Attackers routinely bypass simple pattern matching by nesting encodings (e.g., double URL encoding `%2527` or inserting SQL comments `UN/**/ION`). Bastion recursively unwraps payloads, applies Unicode NFKC normalization to collapse homoglyphs, and constructs dual internal representations (Raw vs. Canonical) before running any evaluation.
2. **Context-Aware Semantic AST Lexer:** Traditional regex fails when a user submits normal text that happens to contain SQL keywords (e.g., searching for *"select goods from inventory"* or entering mathematical comparisons *"1 < 2"*). Bastion analyzes payloads using an Abstract Syntax Tree (AST) grammar tokenizer. It looks for genuine structural syntax—such as boolean tautologies (`'1'='1'`), unauthorized syntax breaks, or shell redirection sequences (`|`, `&&`, `;`)—eliminating the false positives that plague regex-only firewalls.
3. **Categorized 28-Rule Suite:** Covers three distinct operational domains:
   * **OWASP Top 10:** SQL Injection, Cross-Site Scripting, Path Traversal/LFI, Remote Code Execution, SSRF, SSTI, XML External Entities (XXE), and Insecure Deserialization.
   * **API Security:** Parameter tampering, mass assignment, GraphQL abuse, token leakage, and CORS origin validation.
   * **Automated Scanners & Bots:** Signatures for automated recon tools (Nikto, SQLMap, Nuclei), HTTP protocol anomalies, and rapid-fire flood limiting.
4. **3-Tier Adaptive Response Policy:**
   * **Tier 1 (Critical Exploits):** Immediate `HTTP 403 Forbidden` hard drop and SQLite event logging.
   * **Tier 2 (Suspicious Anomaly / Medium Risk):** Intercepts the request with an interactive, dark-themed **Slider CAPTCHA Challenge**. The client's browser validates mouse trajectory smoothness and movement duration against automated bots. Upon success, Bastion issues a cryptographically signed HMAC clearance cookie (`bastion_waf_clearance`, 15-minute TTL) and resumes the user's session without data loss.
   * **Tier 3 (Verified / Clean Requests):** Forwards seamlessly upstream to the backend application.
5. **Operational Modes & Fail-Safe Protection:**
   * **Active Defense Mode:** Full inspection, rate limiting, and real-time blocking.
   * **Passive Monitor (Bypass) Mode:** Inspects and logs threats to the database without dropping packets. This allows operators to test Bastion on active production servers and verify false-positive rates with zero risk.
   * **Fail-Open Safety Switch:** If the proxy process encounters a fatal exception or CPU starvation, the gateway automatically routes clean requests through to maintain backend uptime rather than crashing departmental services.

---

## 6. Current MVP Validation & Benchmark Data

The Bastion prototype has undergone initial local stress testing to verify real-world feasibility:

* **Testing Environment:**
  * Host Machine: Intel Core i5 (quad-core), 8 GB RAM, Linux x86_64
  * Benchmark Harness: Multi-threaded load generator executing over 10,000 mixed HTTP requests (clean requests, nested SQLi strings, encoded XSS payloads, and path traversals)
* **Observed Metrics:**
  * **Average Inspection Latency:** **0.42 ms** per request
  * **Memory Footprint:** Under **140 MB RAM** running proxy and telemetry API concurrently
  * **Automated Rule Suite:** 103 test cases passing with zero regressions across all 28 detection rules
* **Target Production Benchmark (BiTec Incubation Goal):**
  * Sustain **1,000 requests per second (RPS)** with a 99th-percentile latency under 1.5 ms on a standalone commodity desktop PC.

---

## 7. Operational Dashboard & Management Interface

Bastion features a fully responsive, self-contained dashboard built without heavy external cloud dependencies:

* **Real-Time SOC Overview:** Displays total requests, blocked attacks, challenged bot sessions, live threat category distributions, and top targeted endpoints.
* **Authentic Threat Analytics:** Tracks genuine database-persisted incident vectors (targeted URLs, triggered rule IDs, source IP frequencies) without relying on unreliable third-party geolocation services.
* **One-Click Rule Engine:** Allows administrators to enable or disable individual rules instantly via the browser, updating proxy behavior in memory without needing server restarts or configuration edits.
* **Integrated Threat Sandbox:** Lets developers test custom query parameters and request bodies against Bastion's semantic engine in real time to verify inspection scores before rolling rules into production.
* **On-Demand Site Manager:** Enables routing rules and defense modes for multiple host domains on demand, while allowing Bastion to operate as a standalone inspection gateway when no upstream site is bound.

*(Insert Dashboard Overview and Rule Engine screenshots here)*

---

## 8. Technology Roadmap: AI-Assisted Security Operations

While current protection relies on the high-speed Semantic AST lexer and deterministic rules, the next phases of development leverage machine learning for background analysis:

* **Stage 1 (Current MVP Completed):** High-speed reverse proxy, sub-millisecond AST parser, 28-rule CRS suite, 3-tier Slider CAPTCHA, and centralized dashboard.
* **Stage 2 (Months 1–3 at BiTec):** Request-frequency profiling and statistical sliding-window baselining to detect slow-rate brute force attacks and credential stuffing tools that bypass static thresholds.
* **Stage 3 (Months 4–6 at BiTec):** Lightweight local clustering to identify polymorphic injection mutations and obfuscated payloads without adding latency to the synchronous request pipeline.
* **Stage 4 (Months 7–9 at BiTec):** Automated plain-language incident reporting. Converts complex hex-encoded attack payloads and regex logs into clear, actionable vulnerability remediation advice tailored for local junior developers.

---

## 9. Commercial Model & Domestic Revenue Strategy

Bastion is structured around domestic billing in **Ethiopian Birr (ETB)**, fully integrated with local mobile payment APIs (**Telebirr, CBE Birr**):

### 1. Tiered Recurring SaaS Subscriptions
* **Academic & Developer Tier (0 ETB / Free):** Free license for student graduation projects, campus labs, and open-source contributors, building adoption and generating real testing data.
* **Commercial SME Tier (1,500 – 2,500 ETB / month):** Tailored for regional business websites, e-commerce shops, and private clinics. Includes automatic rule database updates, managed proxy routing, and direct SMS/Telegram incident alerts.
* **Agency Multi-Domain Tier (4,000 – 6,000 ETB / month):** For local web design agencies and software houses managing up to 10 client websites through a single multi-tenant console.

### 2. On-Premise Enterprise Licensing
* **Self-Hosted Enterprise License (20,000 – 35,000 ETB / year):** Targeted at regional banks, microfinance institutions, and municipal offices that demand complete physical isolation and local data residency.
* **Hardened Appliance Delivery (30,000 – 50,000 ETB one-time + annual service):** Pre-configured mini-PC hardware appliance running a hardened Bastion image, delivered ready for direct server-room deployment.

### 3. Domestic B2B Distribution Partnerships
* **Local Hosting Provider Add-on (300 – 500 ETB / domain / month):** Wholesale integration with domestic hosting providers (e.g., local web hosts) offering one-click firewall protection during checkout.
* **Software House Bundling:** Regional development teams pre-installing Bastion as the baseline security layer on custom client web portals.

---

## 10. Incubation Workspace Justification & Resource Request

To transition Bastion from an isolated project on a single laptop into an enterprise-ready network security solution, I request incubation support at **BiTec (Poly Campus)**:

1. **Dedicated Workstation Space & Uninterrupted Power:** Continuous electrical power and dependable internet connectivity are critical to run continuous 48-hour traffic stress tests, fuzzing pipelines, and proxy benchmarking without unexpected shutdown interruptions.
2. **Isolated Security Testing Subnet:** A closed physical/virtual laboratory network where security tools (such as SQLMap, Nuclei, and custom fuzzers) can attack test targets through Bastion without triggering alarms or risking campus network stability.
3. **Faculty Mentorship & Advisory Input:** Guidance from BiT computing faculty specializing in socket programming, concurrent network architectures, and statistical anomaly detection to refine socket pooling and high-concurrency throughput.
4. **Campus Staging Pilot Authorization:** Permission to deploy Bastion in **Passive Monitor / Bypass Mode** in front of an internal BiT departmental or student testing service. This will allow the system to ingest real-world traffic patterns, validate stability under daily campus operations, and prove zero false-positive disruption before public release.

---

## 11. Conclusion

Bastion WAF is a practical response to a real economic and technical constraint in Ethiopia's digital infrastructure. By eliminating foreign exchange dependency and replacing cryptic configuration files with an intelligent, self-contained semantic firewall, Bastion makes enterprise-grade perimeter protection accessible to local institutions.

With the workspace, laboratory testing infrastructure, and faculty mentorship provided by BiTec, I will refine this working prototype into a battle-tested, commercially viable cybersecurity appliance built by and for our local computing community.
