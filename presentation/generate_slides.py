"""
Generator for Bastion WAF 13-Slide Presentation Deck matching user's PDF design.
"""
from pathlib import Path

OUT_DIR = Path("/home/jr/Desktop/BastionWAF/presentation")
OUT_DIR.mkdir(parents=True, exist_ok=True)

SHARED_CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  width: 1920px;
  height: 1080px;
  background-color: #FFFFFF;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  color: #1A1A1A;
  padding: 80px 120px 70px 120px;
  position: relative;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.slide-header {
  margin-bottom: 36px;
}

.slide-title {
  font-size: 54px;
  font-weight: 800;
  letter-spacing: -0.015em;
  color: #1A1A1A;
  margin-bottom: 12px;
}

.slide-subtitle {
  font-size: 24px;
  font-weight: 400;
  color: #4A5568;
  letter-spacing: -0.005em;
  line-height: 1.4;
  max-width: 1400px;
}

.card {
  background-color: #EEF7F2;
  border-radius: 14px;
  padding: 28px 32px;
  transition: transform 0.2s ease;
}

.card-title {
  font-size: 22px;
  font-weight: 700;
  color: #1A1A1A;
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 12px;
}

.card-desc {
  font-size: 17px;
  color: #4A5568;
  line-height: 1.55;
}

.footer {
  position: absolute;
  bottom: 40px;
  left: 120px;
  right: 120px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 16px;
  color: #718096;
  border-top: 1px solid #EDF2F7;
  padding-top: 18px;
}

.footer-brand {
  display: flex;
  align-items: center;
  gap: 8px;
}
"""

slides_content = {
    1: """
<!DOCTYPE html>
<html>
<head><style>""" + SHARED_CSS + """
.center-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding-left: 20px;
  margin-top: -30px;
}
.hero-title {
  font-size: 88px;
  font-weight: 800;
  color: #1A1A1A;
  margin-bottom: 18px;
  letter-spacing: -0.02em;
}
.hero-sub {
  font-size: 32px;
  color: #4A5568;
  margin-bottom: 48px;
  max-width: 1300px;
  line-height: 1.35;
}
.presenter-card {
  display: flex;
  align-items: center;
  gap: 32px;
  background: #EEF7F2;
  border-radius: 18px;
  padding: 24px 36px;
  width: fit-content;
}
.avatar {
  width: 90px;
  height: 90px;
  border-radius: 50%;
  border: 3px solid #2F855A;
  background: #FFFFFF;
  color: #2F855A;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 34px;
  font-weight: 700;
}
.p-name { font-size: 28px; font-weight: 700; color: #1A1A1A; margin-bottom: 4px; }
.p-role { font-size: 20px; font-weight: 600; color: #2F855A; margin-bottom: 2px; }
.p-inst { font-size: 17px; color: #4A5568; }
.status-pill {
  margin-top: 36px;
  display: inline-flex;
  align-items: center;
  gap: 10px;
  background: #FFFFFF;
  border: 1.5px solid #2F855A;
  color: #2F855A;
  padding: 8px 20px;
  border-radius: 30px;
  font-size: 17px;
  font-weight: 600;
  width: fit-content;
}
.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #2F855A;
}
</style></head>
<body>
  <div class="center-content">
    <div class="status-pill"><div class="status-dot"></div> Functional Working MVP (~0.42 ms Inspection Latency)</div>
    <h1 class="hero-title" style="margin-top: 24px;">BASTION WAF</h1>
    <p class="hero-sub">High-Performance Inline Web Application Firewall for Local Digital Systems</p>
    
    <div class="presenter-card">
      <div class="avatar">RS</div>
      <div>
        <div class="p-name">Robel Shitahun</div>
        <div class="p-role">3rd Year Cybersecurity Student, Faculty of Computing</div>
        <div class="p-inst">Bahir Dar Institute of Technology (BiT), Bahir Dar University • Target Center: BiTec</div>
      </div>
    </div>
  </div>
  <div class="footer">
    <span class="footer-brand">Bahir Dar Institute of Technology (BiT) • BiTec</span>
    <span>1</span>
  </div>
</body>
</html>
""",

    2: """
<!DOCTYPE html>
<html>
<head><style>""" + SHARED_CSS + """
.cards-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 32px;
  margin-top: 20px;
}
.problem-card {
  background: #FFF5F5;
  border-top: 6px solid #E53E3E;
  border-radius: 14px;
  padding: 36px 32px;
  display: flex;
  flex-direction: column;
  height: 480px;
}
.icon-badge {
  width: 52px;
  height: 52px;
  border-radius: 12px;
  background: #FED7D7;
  color: #C53030;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
  font-weight: 800;
  margin-bottom: 24px;
}
.p-title {
  font-size: 24px;
  font-weight: 700;
  color: #1A1A1A;
  margin-bottom: 18px;
  line-height: 1.3;
}
.p-desc {
  font-size: 18px;
  color: #4A5568;
  line-height: 1.6;
}
</style></head>
<body>
  <div class="slide-header">
    <h1 class="slide-title">The Problem: Web Defense in Ethiopia</h1>
    <p class="slide-subtitle">Local web platforms operate with zero baseline perimeter protection due to three structural barriers.</p>
  </div>
  <div class="cards-grid">
    <div class="problem-card">
      <div class="icon-badge">1</div>
      <div class="p-title">The Foreign Currency Barrier</div>
      <div class="p-desc">Commercial cloud firewalls (Cloudflare, AWS WAF) demand recurring subscriptions billed strictly in US Dollars via international credit cards. Severe domestic forex restrictions legally cut off local developers, startups, and academic platforms.</div>
    </div>
    <div class="problem-card">
      <div class="icon-badge">2</div>
      <div class="p-title">The Operational Complexity Deficit</div>
      <div class="p-desc">Open-source alternatives like raw ModSecurity lack an intuitive graphical UI, requiring continuous manual terminal configuration and complex regex tuning. Small teams and regional developers routinely misconfigure or abandon them.</div>
    </div>
    <div class="problem-card">
      <div class="icon-badge">3</div>
      <div class="p-title">The Institutional Defense Divide</div>
      <div class="p-desc">While federal agencies have specialized enterprise solutions, ordinary university portals, student platforms, and growing regional enterprises are left completely unshielded against automated botnets and vulnerability fuzzers.</div>
    </div>
  </div>
  <div class="footer">
    <span class="footer-brand">Bahir Dar Institute of Technology (BiT) • BiTec</span>
    <span>2</span>
  </div>
</body>
</html>
""",

    3: """
<!DOCTYPE html>
<html>
<head><style>""" + SHARED_CSS + """
.cols-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 32px;
  margin-top: 20px;
}
.target-col {
  background: #EEF7F2;
  border-top: 6px solid #2F855A;
  border-radius: 14px;
  padding: 36px 32px;
  display: flex;
  flex-direction: column;
  height: 480px;
}
.col-num {
  font-size: 16px;
  font-weight: 700;
  color: #2F855A;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 16px;
}
.col-title {
  font-size: 24px;
  font-weight: 700;
  color: #1A1A1A;
  margin-bottom: 18px;
  line-height: 1.3;
}
.col-desc {
  font-size: 18px;
  color: #4A5568;
  line-height: 1.6;
}
</style></head>
<body>
  <div class="slide-header">
    <h1 class="slide-title">The Target Market: The "Missing Middle"</h1>
    <p class="slide-subtitle">Bastion protects the critical tier of institutions that handle real user data locally but cannot access foreign firewalls.</p>
  </div>
  <div class="cols-grid">
    <div class="target-col">
      <div class="col-num">Sector 01</div>
      <div class="col-title">Campus Networks & Departmental Services</div>
      <div class="col-desc">BiT student portals, grading platforms, and faculty research tools facing 24/7 automated network scanning without dedicated security staff or enterprise security operations centers.</div>
    </div>
    <div class="target-col">
      <div class="col-num">Sector 02</div>
      <div class="col-title">Regional SMEs & Software Houses</div>
      <div class="col-desc">Local tech startups, e-commerce shops, and private clinics processing customer transactions entirely in Ethiopian Birr (ETB) and needing a turnkey, zero-headache perimeter firewall.</div>
    </div>
    <div class="target-col">
      <div class="col-num">Sector 03</div>
      <div class="col-title">Public Regional Platforms</div>
      <div class="col-desc">Municipal and educational bureaus legally or policy-bound to keep all traffic data, inspection telemetry, and audit logs strictly on physical, on-premises local servers within national borders.</div>
    </div>
  </div>
  <div class="footer">
    <span class="footer-brand">Bahir Dar Institute of Technology (BiT) • BiTec</span>
    <span>3</span>
  </div>
</body>
</html>
""",

    4: """
<!DOCTYPE html>
<html>
<head><style>""" + SHARED_CSS + """
.layout-split {
  display: grid;
  grid-template-columns: 1.15fr 0.85fr;
  gap: 40px;
  margin-top: 10px;
  align-items: stretch;
}
.pillars-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.pillar-card {
  background: #EEF7F2;
  border-radius: 12px;
  padding: 22px 26px;
}
.p-head {
  font-size: 20px;
  font-weight: 700;
  color: #1A1A1A;
  margin-bottom: 6px;
  display: flex;
  align-items: center;
  gap: 10px;
}
.dot { width: 10px; height: 10px; border-radius: 50%; background: #2F855A; }
.p-text { font-size: 16px; color: #4A5568; line-height: 1.5; }
.diag-card {
  background: #F8FAFC;
  border: 2px dashed #CBD5E0;
  border-radius: 14px;
  padding: 30px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  text-align: center;
}
.diag-flow {
  display: flex;
  flex-direction: column;
  gap: 16px;
  width: 100%;
}
.flow-box {
  background: #FFFFFF;
  border: 1.5px solid #E2E8F0;
  border-radius: 10px;
  padding: 16px;
  font-weight: 700;
  font-size: 17px;
  color: #1A1A1A;
  box-shadow: 0 2px 4px rgba(0,0,0,0.02);
}
.flow-arrow { font-size: 20px; color: #2F855A; }
.flow-highlight { background: #EEF7F2; border-color: #2F855A; color: #2F855A; }
</style></head>
<body>
  <div class="slide-header">
    <h1 class="slide-title">The Solution: Bastion WAF Overview</h1>
    <p class="slide-subtitle">A high-throughput, self-hosted inline reverse proxy providing sub-millisecond perimeter protection.</p>
  </div>
  <div class="layout-split">
    <div class="pillars-list">
      <div class="pillar-card">
        <div class="p-head"><div class="dot"></div> Inline Reverse-Proxy Gateway</div>
        <div class="p-text">Intercepts incoming HTTP/HTTPS traffic at the network edge before it can touch backend databases or application logic.</div>
      </div>
      <div class="pillar-card">
        <div class="p-head"><div class="dot"></div> Runs on Standard Commodity Hardware</div>
        <div class="p-text">Engineered for high throughput on standard quad-core desktop PCs without demanding expensive specialized hardware.</div>
      </div>
      <div class="pillar-card">
        <div class="p-head"><div class="dot"></div> Autonomous Protection Suite</div>
        <div class="p-text">28 active defense rules protecting across OWASP Top 10, API Security, and Automated Bot Scanners.</div>
      </div>
      <div class="pillar-card">
        <div class="p-head"><div class="dot"></div> 100% Domestic Billing</div>
        <div class="p-text">Fully commercialized in Ethiopian Birr (ETB) with native Telebirr and CBE Birr payment integrations.</div>
      </div>
    </div>
    <div class="diag-card">
      <div class="diag-flow">
        <div class="flow-box">Public Web Clients / Untrusted Internet</div>
        <div class="flow-arrow">▼</div>
        <div class="flow-box flow-highlight">Bastion WAF Gateway (:8080)<br><span style="font-size: 14px; font-weight: 400; color: #4A5568;">Normalization • AST Lexer • 3-Tier Policy</span></div>
        <div class="flow-arrow">▼</div>
        <div class="flow-box">Origin Web Application / Database Backend</div>
      </div>
    </div>
  </div>
  <div class="footer">
    <span class="footer-brand">Bahir Dar Institute of Technology (BiT) • BiTec</span>
    <span>4</span>
  </div>
</body>
</html>
""",

    5: """
<!DOCTYPE html>
<html>
<head><style>""" + SHARED_CSS + """
.steps-list {
  display: flex;
  flex-direction: column;
  gap: 18px;
  margin-top: 10px;
}
.step-card {
  background: #EEF7F2;
  border-radius: 12px;
  padding: 22px 28px;
  display: flex;
  align-items: center;
  gap: 24px;
}
.step-badge {
  width: 100px;
  height: 54px;
  background: #2F855A;
  color: #FFFFFF;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 800;
  font-size: 18px;
  flex-shrink: 0;
  letter-spacing: 0.05em;
}
.step-content { flex: 1; }
.step-name { font-size: 22px; font-weight: 700; color: #1A1A1A; margin-bottom: 4px; }
.step-desc { font-size: 17px; color: #4A5568; line-height: 1.45; }
</style></head>
<body>
  <div class="slide-header">
    <h1 class="slide-title">Core Defense Pipeline (How It Works)</h1>
    <p class="slide-subtitle">A multi-stage inspection flow engineered for deep payload de-obfuscation and sub-millisecond execution.</p>
  </div>
  <div class="steps-list">
    <div class="step-card">
      <div class="step-badge">STEP 1</div>
      <div class="step-content">
        <div class="step-name">Multi-Pass Normalization Layer</div>
        <div class="step-desc">Recursively resolves multi-stage URL encoding, HTML entities, Unicode NFKC homoglyphs, and comment injection techniques (e.g. <code>UNI/**/ON</code>) before any rule evaluation.</div>
      </div>
    </div>
    <div class="step-card">
      <div class="step-badge">STEP 2</div>
      <div class="step-content">
        <div class="step-name">Hybrid Inspection Suite</div>
        <div class="step-desc">Dual raw and canonical payload representations evaluated concurrently against 28 Core Rule Set (CRS) signatures across OWASP Top 10, API, and Bot threats.</div>
      </div>
    </div>
    <div class="step-card">
      <div class="step-badge">STEP 3</div>
      <div class="step-content">
        <div class="step-name">Context-Aware Semantic AST Lexer</div>
        <div class="step-desc">Parses structural grammar tokens to evaluate true execution intent and boolean tautologies, rather than relying on flawed blind keyword matching.</div>
      </div>
    </div>
    <div class="step-card">
      <div class="step-badge">STEP 4</div>
      <div class="step-content">
        <div class="step-name">Fail-Safe Operation Engine</div>
        <div class="step-desc">Configurable Passive Monitor (Bypass) Mode for safe staging, alongside a Fail-Open safety switch to guarantee continuous application availability.</div>
      </div>
    </div>
  </div>
  <div class="footer">
    <span class="footer-brand">Bahir Dar Institute of Technology (BiT) • BiTec</span>
    <span>5</span>
  </div>
</body>
</html>
""",

    6: """
<!DOCTYPE html>
<html>
<head><style>""" + SHARED_CSS + """
.compare-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 32px;
  margin-top: 10px;
}
.comp-card {
  border-radius: 14px;
  padding: 32px;
  display: flex;
  flex-direction: column;
}
.legacy-card { background: #FFF5F5; border-top: 6px solid #E53E3E; }
.bastion-card { background: #EEF7F2; border-top: 6px solid #2F855A; }
.comp-title { font-size: 24px; font-weight: 700; margin-bottom: 16px; color: #1A1A1A; }
.comp-body { font-size: 18px; color: #4A5568; line-height: 1.6; margin-bottom: 20px; }
.sample-code {
  background: rgba(0,0,0,0.05);
  padding: 12px 16px;
  border-radius: 8px;
  font-family: monospace;
  font-size: 15px;
  color: #1A1A1A;
}
.bottom-banner {
  margin-top: 24px;
  background: #F8FAFC;
  border: 1.5px solid #E2E8F0;
  border-radius: 12px;
  padding: 18px 24px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.banner-item { font-size: 16px; color: #2D3748; font-weight: 600; display: flex; align-items: center; gap: 8px; }
.b-dot { width: 8px; height: 8px; border-radius: 50%; background: #2F855A; }
</style></head>
<body>
  <div class="slide-header">
    <h1 class="slide-title">Key Innovation: Semantic AST vs. Legacy RegEx</h1>
    <p class="slide-subtitle">How Bastion eliminates false positives on normal human text while stopping evasive zero-day attacks.</p>
  </div>
  <div class="compare-grid">
    <div class="comp-card legacy-card">
      <div class="comp-title" style="color: #C53030;">The Failure of RegEx Firewalls</div>
      <div class="comp-body">Static keyword filters trigger false alarms on normal human language, breaking legitimate application features when words match attack patterns.</div>
      <div class="sample-code">Blocks: "select goods from shop"<br>Blocks: "1 &lt; 2 in math class"<br>Bypassed by: "UN/**/ION SELECT"</div>
    </div>
    <div class="comp-card bastion-card">
      <div class="comp-title" style="color: #2F855A;">Bastion's AST Lexical Tokenizer</div>
      <div class="comp-body">Parses code syntax into Abstract Syntax Trees, evaluating boolean tautologies (<code>'1'='1'</code>) and genuine command execution chains (<code>|</code>, <code>&amp;&amp;</code>, <code>;</code>).</div>
      <div class="sample-code">Allows: "select goods from shop"<br>Allows: "1 &lt; 2 in math class"<br>Blocks: "' OR '1'='1 --" (True Tautology)</div>
    </div>
  </div>
  <div class="bottom-banner">
    <div class="banner-item"><div class="b-dot"></div> Zero False Positives on Conversational Queries</div>
    <div class="banner-item"><div class="b-dot"></div> Ultra-Low Overhead: Sub-Millisecond Deterministic Parsing</div>
    <div class="banner-item"><div class="b-dot"></div> Explainable Token Scores Without Heavy Machine Models</div>
  </div>
  <div class="footer">
    <span class="footer-brand">Bahir Dar Institute of Technology (BiT) • BiTec</span>
    <span>6</span>
  </div>
</body>
</html>
""",

    7: """
<!DOCTYPE html>
<html>
<head><style>""" + SHARED_CSS + """
.tiers-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 32px;
  margin-top: 20px;
}
.tier-card {
  border-radius: 14px;
  padding: 36px 30px;
  display: flex;
  flex-direction: column;
  height: 480px;
}
.t1 { background: #FFF5F5; border-top: 6px solid #E53E3E; }
.t2 { background: #FFFBEB; border-top: 6px solid #D97706; }
.t3 { background: #EEF7F2; border-top: 6px solid #2F855A; }
.t-tag {
  font-size: 15px;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 12px;
}
.t1 .t-tag { color: #C53030; }
.t2 .t-tag { color: #D97706; }
.t3 .t-tag { color: #2F855A; }
.t-title { font-size: 24px; font-weight: 700; color: #1A1A1A; margin-bottom: 16px; line-height: 1.3; }
.t-desc { font-size: 17px; color: #4A5568; line-height: 1.6; }
.t-action {
  margin-top: auto;
  padding-top: 16px;
  border-top: 1px solid rgba(0,0,0,0.06);
  font-weight: 700;
  font-size: 16px;
}
.t1 .t-action { color: #C53030; }
.t2 .t-action { color: #D97706; }
.t3 .t-action { color: #2F855A; }
</style></head>
<body>
  <div class="slide-header">
    <h1 class="slide-title">3-Tier Adaptive Bot & Threat Mitigation</h1>
    <p class="slide-subtitle">Replacing blunt "block-or-allow" walls with human-centric adaptive verification.</p>
  </div>
  <div class="tiers-grid">
    <div class="tier-card t1">
      <div class="t-tag">Tier 1 • High Risk</div>
      <div class="t-title">High-Confidence Exploits (Score ≥ 70)</div>
      <div class="t-desc">Confirmed attacks (SQLi, RCE, Webshells) are dropped instantly at the gateway boundary. No backend application execution occurs, saving origin server compute.</div>
      <div class="t-action">Action: Immediate HTTP 403 Forbidden Drop</div>
    </div>
    <div class="tier-card t2">
      <div class="t-tag">Tier 2 • Suspicious</div>
      <div class="t-title">Suspicious Anomalies (Score 40–69)</div>
      <div class="t-desc">Suspicious traffic and automated bot scrapers are served an in-house interactive Slider CAPTCHA, verifying human mouse trajectory smoothness and velocity without third-party cloud APIs.</div>
      <div class="t-action">Action: Interactive Slider CAPTCHA Challenge</div>
    </div>
    <div class="tier-card t3">
      <div class="t-tag">Tier 3 • Verified Clean</div>
      <div class="t-title">Clean / Human Traffic (Score &lt; 40)</div>
      <div class="t-desc">Legitimate users and CAPTCHA-cleared clients receive a cryptographically signed HMAC token (15-min TTL) and are forwarded seamlessly to upstream application servers.</div>
      <div class="t-action">Action: HTTP 200 Forward Upstream</div>
    </div>
  </div>
  <div class="footer">
    <span class="footer-brand">Bahir Dar Institute of Technology (BiT) • BiTec</span>
    <span>7</span>
  </div>
</body>
</html>
""",

    8: """
<!DOCTYPE html>
<html>
<head><style>""" + SHARED_CSS + """
.metrics-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 32px;
  margin-top: 10px;
}
.metric-box {
  background: #EEF7F2;
  border-radius: 14px;
  padding: 36px 40px;
  display: flex;
  flex-direction: column;
}
.m-value {
  font-size: 58px;
  font-weight: 800;
  color: #2F855A;
  margin-bottom: 8px;
  letter-spacing: -0.02em;
}
.m-label {
  font-size: 22px;
  font-weight: 700;
  color: #1A1A1A;
  margin-bottom: 8px;
}
.m-desc {
  font-size: 17px;
  color: #4A5568;
  line-height: 1.5;
}
</style></head>
<body>
  <div class="slide-header">
    <h1 class="slide-title">Current MVP Status & Benchmark Results</h1>
    <p class="slide-subtitle">Empirical performance metrics measured on standard commodity desktop hardware.</p>
  </div>
  <div class="metrics-grid">
    <div class="metric-box">
      <div class="m-value">~0.42 ms</div>
      <div class="m-label">Average Inspection Latency</div>
      <div class="m-desc">Verified locally across 10,000+ concurrent mixed HTTP requests (clean traffic, nested SQLi, encoded XSS, path traversal).</div>
    </div>
    <div class="metric-box">
      <div class="m-value">&lt; 140 MB</div>
      <div class="m-label">RAM Footprint</div>
      <div class="m-desc">Highly optimized async engine running on standard Linux x86_64 commodity hardware alongside the telemetry server.</div>
    </div>
    <div class="metric-box">
      <div class="m-value">103 / 103</div>
      <div class="m-label">Passing Automated Tests</div>
      <div class="m-desc">Full test suite verifying zero false negatives across all 28 active OWASP, API, and bot detection rules.</div>
    </div>
    <div class="metric-box">
      <div class="m-value">1,000 RPS</div>
      <div class="m-label">Incubation Target Metric</div>
      <div class="m-desc">Scaling to sustain 1,000 Requests Per Second with a 99th-percentile latency under 1.5 ms on a standalone commodity desktop PC.</div>
    </div>
  </div>
  <div class="footer">
    <span class="footer-brand">Bahir Dar Institute of Technology (BiT) • BiTec</span>
    <span>8</span>
  </div>
</body>
</html>
""",

    9: """
<!DOCTYPE html>
<html>
<head><style>""" + SHARED_CSS + """
.layout-split {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 36px;
  margin-top: 10px;
  align-items: center;
}
.preview-stack {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.img-frame {
  background: #1A1A1A;
  border-radius: 10px;
  overflow: hidden;
  box-shadow: 0 8px 24px rgba(0,0,0,0.12);
  border: 1px solid #E2E8F0;
}
.img-frame img {
  width: 100%;
  display: block;
}
.features-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.feature-card {
  background: #EEF7F2;
  border-radius: 12px;
  padding: 18px 24px;
}
.f-title {
  font-size: 19px;
  font-weight: 700;
  color: #1A1A1A;
  margin-bottom: 4px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.f-dot { width: 8px; height: 8px; border-radius: 50%; background: #2F855A; }
.f-desc { font-size: 15px; color: #4A5568; line-height: 1.45; }
</style></head>
<body>
  <div class="slide-header">
    <h1 class="slide-title">Operational Telemetry & Management Dashboard</h1>
    <p class="slide-subtitle">A self-contained web console replacing terminal configuration with intuitive real-time visibility.</p>
  </div>
  <div class="layout-split">
    <div class="preview-stack">
      <div class="img-frame">
        <img src="extracted_img-000.png" alt="Live Traffic View">
      </div>
      <div class="img-frame">
        <img src="extracted_img-001.png" alt="Rule Engine">
      </div>
    </div>
    <div class="features-list">
      <div class="feature-card">
        <div class="f-title"><div class="f-dot"></div> Real-Time SOC Telemetry</div>
        <div class="f-desc">Visualizes live traffic throughput, mitigation percentages, challenge distributions, and host system health vitals (CPU/RAM/Uptime).</div>
      </div>
      <div class="feature-card">
        <div class="f-title"><div class="f-dot"></div> Authentic Threat Analytics</div>
        <div class="f-desc">Tracks real database-persisted attack vectors (targeted URL endpoints, triggered rule IDs, source IP frequencies) without fake external cloud lookups.</div>
      </div>
      <div class="feature-card">
        <div class="f-title"><div class="f-dot"></div> One-Click Rule Management</div>
        <div class="f-desc">Toggle any of the 28 security rules on/off dynamically in memory via the browser with zero server restarts required.</div>
      </div>
      <div class="feature-card">
        <div class="f-title"><div class="f-dot"></div> Interactive Threat Sandbox</div>
        <div class="f-desc">Test custom request payloads and inspect AST scores before deploying rules into live production traffic.</div>
      </div>
    </div>
  </div>
  <div class="footer">
    <span class="footer-brand">Bahir Dar Institute of Technology (BiT) • BiTec</span>
    <span>9</span>
  </div>
</body>
</html>
""",

    10: """
<!DOCTYPE html>
<html>
<head><style>""" + SHARED_CSS + """
.table-wrap {
  margin-top: 14px;
  background: #FFFFFF;
  border-radius: 12px;
  overflow: hidden;
  border: 1px solid #E2E8F0;
  box-shadow: 0 4px 6px rgba(0,0,0,0.02);
}
table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
}
th {
  background: #1A1A1A;
  color: #FFFFFF;
  padding: 18px 24px;
  font-size: 17px;
  font-weight: 700;
  letter-spacing: 0.02em;
}
th.highlight {
  background: #2F855A;
}
td {
  padding: 16px 24px;
  font-size: 16px;
  color: #4A5568;
  border-bottom: 1px solid #EDF2F7;
}
tr:nth-child(even) td {
  background: #F8FAFC;
}
td.highlight-col {
  background: #EEF7F2 !important;
  font-weight: 700;
  color: #1A1A1A;
}
</style></head>
<body>
  <div class="slide-header">
    <h1 class="slide-title">Competitive Advantage</h1>
    <p class="slide-subtitle">Comparing Bastion against international cloud providers and legacy open-source tools.</p>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Evaluation Feature</th>
          <th>Cloudflare / AWS WAF</th>
          <th>ModSecurity / Coraza</th>
          <th class="highlight">Bastion WAF (Proposed)</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>Billing & Currency</strong></td>
          <td>Monthly USD (Credit Card)</td>
          <td>Free (High Labor Cost)</td>
          <td class="highlight-col">100% Ethiopian Birr (Telebirr / CBE)</td>
        </tr>
        <tr>
          <td><strong>Data Residency</strong></td>
          <td>Overseas Cloud Servers</td>
          <td>Local / Self-Hosted</td>
          <td class="highlight-col">Strictly On-Premises Sovereignty</td>
        </tr>
        <tr>
          <td><strong>Management Interface</strong></td>
          <td>Cloud Console</td>
          <td>Command-Line Files (.conf)</td>
          <td class="highlight-col">Interactive Real-Time Web UI</td>
        </tr>
        <tr>
          <td><strong>Detection Engine</strong></td>
          <td>Proprietary Heuristics</td>
          <td>Static Regex Matching</td>
          <td class="highlight-col">Semantic AST Lexer + CRS Rules</td>
        </tr>
        <tr>
          <td><strong>Bot Challenge</strong></td>
          <td>Cloudflare Turnstile</td>
          <td>Basic Rate Limits</td>
          <td class="highlight-col">Self-Hosted Adaptive Slider CAPTCHA</td>
        </tr>
        <tr>
          <td><strong>Hardware Overhead</strong></td>
          <td>Cloud Infrastructure</td>
          <td>Moderate / High CPU Spikes</td>
          <td class="highlight-col">Sub-millisecond on Commodity PCs</td>
        </tr>
      </tbody>
    </table>
  </div>
  <div class="footer">
    <span class="footer-brand">Bahir Dar Institute of Technology (BiT) • BiTec</span>
    <span>10</span>
  </div>
</body>
</html>
""",

    11: """
<!DOCTYPE html>
<html>
<head><style>""" + SHARED_CSS + """
.pricing-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 32px;
  margin-top: 10px;
}
.price-card {
  background: #EEF7F2;
  border-radius: 14px;
  padding: 32px 28px;
  display: flex;
  flex-direction: column;
  height: 490px;
}
.p-tag {
  font-size: 15px;
  font-weight: 800;
  text-transform: uppercase;
  color: #2F855A;
  letter-spacing: 0.08em;
  margin-bottom: 12px;
}
.p-name { font-size: 24px; font-weight: 700; color: #1A1A1A; margin-bottom: 18px; }
.p-items {
  display: flex;
  flex-direction: column;
  gap: 14px;
  font-size: 16px;
  color: #4A5568;
}
.p-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  line-height: 1.45;
}
.bullet { color: #2F855A; font-weight: 700; flex-shrink: 0; }
</style></head>
<body>
  <div class="slide-header">
    <h1 class="slide-title">Business Model & Revenue Strategy</h1>
    <p class="slide-subtitle">Sustainable domestic monetization billed via local mobile money (Telebirr, CBE Birr).</p>
  </div>
  <div class="pricing-grid">
    <div class="price-card">
      <div class="p-tag">Channel 01</div>
      <div class="p-name">Tiered Subscriptions (SaaS)</div>
      <div class="p-items">
        <div class="p-item"><span class="bullet">•</span><span><strong>Academic Tier (0 ETB / Free):</strong> Free for student projects & campus research labs.</span></div>
        <div class="p-item"><span class="bullet">•</span><span><strong>Commercial SME Tier (1,500 – 2,500 ETB / mo):</strong> Automated rule updates, managed proxy routing, and direct alerts.</span></div>
        <div class="p-item"><span class="bullet">•</span><span><strong>Agency Multi-Domain Tier (4,000 – 6,000 ETB / mo):</strong> Up to 10 client domains managed in a unified console.</span></div>
      </div>
    </div>
    <div class="price-card">
      <div class="p-tag">Channel 02</div>
      <div class="p-name">On-Premise Enterprise</div>
      <div class="p-items">
        <div class="p-item"><span class="bullet">•</span><span><strong>Self-Hosted Enterprise License (20,000 – 35,000 ETB / yr):</strong> For regional banks and public municipal offices requiring air-gapped data residency.</span></div>
        <div class="p-item"><span class="bullet">•</span><span><strong>Turnkey Appliance Delivery (30,000 – 50,000 ETB one-time):</strong> Pre-hardened mini-PC appliance delivered for direct server-room deployment.</span></div>
      </div>
    </div>
    <div class="price-card">
      <div class="p-tag">Channel 03</div>
      <div class="p-name">Domestic Partnerships</div>
      <div class="p-items">
        <div class="p-item"><span class="bullet">•</span><span><strong>Hosting Provider Add-on (300 – 500 ETB / domain / mo):</strong> Wholesale integration with domestic hosting providers during checkout.</span></div>
        <div class="p-item"><span class="bullet">•</span><span><strong>Software Agency Bundling:</strong> Regional software houses pre-installing Bastion as the baseline security layer on custom client portals.</span></div>
      </div>
    </div>
  </div>
  <div class="footer">
    <span class="footer-brand">Bahir Dar Institute of Technology (BiT) • BiTec</span>
    <span>11</span>
  </div>
</body>
</html>
""",

    12: """
<!DOCTYPE html>
<html>
<head><style>""" + SHARED_CSS + """
.roadmap-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
  margin-top: 10px;
}
.roadmap-card {
  background: #EEF7F2;
  border-radius: 12px;
  padding: 22px 28px;
  display: flex;
  align-items: center;
  gap: 24px;
}
.r-badge {
  width: 120px;
  height: 52px;
  background: #2F855A;
  color: #FFFFFF;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 800;
  font-size: 16px;
  flex-shrink: 0;
  letter-spacing: 0.04em;
}
.r-content { flex: 1; }
.r-name { font-size: 21px; font-weight: 700; color: #1A1A1A; margin-bottom: 4px; }
.r-desc { font-size: 16px; color: #4A5568; line-height: 1.45; }
</style></head>
<body>
  <div class="slide-header">
    <h1 class="slide-title">Phased Development Roadmap</h1>
    <p class="slide-subtitle">Clear engineering milestones to advance from a working prototype to an enterprise appliance.</p>
  </div>
  <div class="roadmap-list">
    <div class="roadmap-card">
      <div class="r-badge">STAGE 1</div>
      <div class="r-content">
        <div class="r-name">Current Working Prototype (Completed)</div>
        <div class="r-desc">Fast reverse proxy, sub-millisecond AST parser, 28-rule CRS suite, Slider CAPTCHA, and centralized dashboard.</div>
      </div>
    </div>
    <div class="roadmap-card">
      <div class="r-badge">STAGE 2</div>
      <div class="r-content">
        <div class="r-name">Months 1–3 @ BiTec: Traffic Baselining &amp; Rate Limiting</div>
        <div class="r-desc">Implementing sliding-window rate limiting, client connection frequency tracking, and behavioral scanning baselining.</div>
      </div>
    </div>
    <div class="roadmap-card">
      <div class="r-badge">STAGE 3</div>
      <div class="r-content">
        <div class="r-name">Months 4–6 @ BiTec: Zero-Day Anomaly Detection</div>
        <div class="r-desc">Adding lightweight local classification models to recognize polymorphic injection mutations and automated parameter fuzzing.</div>
      </div>
    </div>
    <div class="roadmap-card">
      <div class="r-badge">STAGE 4</div>
      <div class="r-content">
        <div class="r-name">Months 7–9 @ BiTec: Plain-Language AI Summaries</div>
        <div class="r-desc">Automated incident reporting that converts raw request dumps and regex logs into plain-language incident explanations and patch advice.</div>
      </div>
    </div>
  </div>
  <div class="footer">
    <span class="footer-brand">Bahir Dar Institute of Technology (BiT) • BiTec</span>
    <span>12</span>
  </div>
</body>
</html>
""",

    13: """
<!DOCTYPE html>
<html>
<head><style>""" + SHARED_CSS + """
.asks-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 28px;
  margin-top: 10px;
}
.ask-card {
  background: #EEF7F2;
  border-radius: 14px;
  padding: 32px 36px;
  display: flex;
  flex-direction: column;
}
.ask-badge {
  width: 44px;
  height: 44px;
  border-radius: 10px;
  background: #2F855A;
  color: #FFFFFF;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
  font-weight: 800;
  margin-bottom: 16px;
}
.ask-title {
  font-size: 22px;
  font-weight: 700;
  color: #1A1A1A;
  margin-bottom: 10px;
}
.ask-desc {
  font-size: 17px;
  color: #4A5568;
  line-height: 1.55;
}
</style></head>
<body>
  <div class="slide-header">
    <h1 class="slide-title">Incubation Ask: Why BiTec?</h1>
    <p class="slide-subtitle">Four essential incubator resources requested to transition Bastion into production.</p>
  </div>
  <div class="asks-grid">
    <div class="ask-card">
      <div class="ask-badge">1</div>
      <div class="ask-title">Workstation &amp; Continuous Electrical Power</div>
      <div class="ask-desc">Dedicated workstation access with dependable electrical power and network connectivity to conduct sustained 48-hour traffic stress tests, fuzzing pipelines, and proxy benchmarking.</div>
    </div>
    <div class="ask-card">
      <div class="ask-badge">2</div>
      <div class="ask-title">Isolated Security Testing Subnet</div>
      <div class="ask-desc">A closed virtual lab environment to safely execute attack tools (SQLMap, Nuclei) against test targets through Bastion without risking campus network stability.</div>
    </div>
    <div class="ask-card">
      <div class="ask-badge">3</div>
      <div class="ask-title">Faculty Technical Mentorship</div>
      <div class="ask-desc">Advisory guidance from BiT computing professors on socket pooling, high-throughput concurrency, and statistical anomaly modeling.</div>
    </div>
    <div class="ask-card">
      <div class="ask-badge">4</div>
      <div class="ask-title">Campus Staging Pilot Authorization</div>
      <div class="ask-desc">Permission to test Bastion in Passive Monitor (Bypass) Mode in front of an internal departmental test service to validate real-world reliability with zero downtime risk.</div>
    </div>
  </div>
  <div class="footer">
    <span class="footer-brand">Bahir Dar Institute of Technology (BiT) • BiTec</span>
    <span>13</span>
  </div>
</body>
</html>
"""
}

for num, content in slides_content.items():
    file_path = OUT_DIR / f"slide_{num:02d}.html"
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content.strip())
    print(f"Generated {file_path.name}")

print("All 13 HTML slides generated successfully!")
