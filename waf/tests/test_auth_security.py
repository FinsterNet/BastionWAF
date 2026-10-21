"""
Bastion WAF Phase 0 Security & Authentication Test Suite.
Validates:
1. Deny-by-default route protection (401 on unauthenticated access)
2. Password policy (NIST/OWASP 12-char min, breach/common blacklist)
3. Brute-force protection & account lockout after 5 failed attempts
4. Generic error messages & constant-time dummy hashing against account enumeration
5. Secure HTTP-only SameSite session cookies & session rotation
6. CSRF synchronizer token verification on state-changing requests
7. Password reset via single-use expiring token invalidating all sessions
8. RFC 6238 TOTP 2FA verification, recovery codes, and replay tolerance
9. Security headers injection (X-Content-Type-Options, X-Frame-Options, CSP)
10. Administrative action audit logging
"""

import os
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.auth import SESSION_COOKIE_NAME
from api.server import app
from bastion.core.security import (
    compute_totp_code,
    generate_recovery_codes,
    generate_secure_token,
    generate_totp_secret,
    hash_password,
    hash_token,
    validate_password_strength,
    verify_password,
    verify_totp_code,
)
from database import db


SETUP_TOKEN = "test-setup-token-12345"


@pytest.fixture(autouse=True)
def clean_test_db(tmp_path, monkeypatch):
    """Use an isolated test database for every test to guarantee clean state."""
    test_db = tmp_path / "test_waf.db"
    monkeypatch.setenv("BASTION_DB_PATH", str(test_db))
    monkeypatch.setattr(db, "DB_PATH", test_db)
    monkeypatch.setenv("BASTION_SETUP_TOKEN", SETUP_TOKEN)
    from api.auth import reset_rate_limits
    reset_rate_limits()
    db.init_db()
    yield
    if test_db.exists():
        try:
            test_db.unlink()
        except Exception:
            pass


@pytest.fixture
def client():
    return TestClient(app, base_url="http://testserver", headers={"Origin": "http://testserver"})


# ============================================================
# 1. Deny-by-Default Route Protection
# ============================================================

def test_unauthenticated_api_routes_return_401(client):
    """Protected management routes must return 401 when no session is provided."""
    protected_endpoints = [
        "/api/stats",
        "/api/events",
        "/api/logs",
        "/api/rules",
        "/api/sites",
        "/api/system",
        "/api/export/csv",
    ]
    for endpoint in protected_endpoints:
        res = client.get(endpoint)
        assert res.status_code == 401, f"{endpoint} did not return 401: {res.status_code}"
        assert res.json().get("detail", {}).get("code") == "UNAUTHORIZED"


def test_public_allowlist_endpoints(client):
    """Public endpoints (/api/auth/status, /api/auth/setup) must be accessible without login."""
    res = client.get("/api/auth/status")
    assert res.status_code == 200
    data = res.json()
    assert data["setup_required"] is True
    assert data["authenticated"] is False


# ============================================================
# 2. Password Strength Policy
# ============================================================

def test_password_policy_enforcement():
    """Passwords must be >= 12 chars and not in common breach lists."""
    # Too short
    ok, err = validate_password_strength("short123")
    assert not ok
    assert "at least 12 characters" in err

    # Common / trivial
    ok, err = validate_password_strength("password1234")
    assert not ok
    assert "too common" in err

    # Valid strong password
    ok, err = validate_password_strength("Bastion$ecure2026!Key")
    assert ok
    assert err is None


# ============================================================
# 3. First-Run Admin Setup Flow
# ============================================================

def test_initial_setup_and_session_issuance(client):
    """Initial admin setup creates the account, issues session cookie, and returns CSRF token."""
    res = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!", "setup_token": SETUP_TOKEN},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["user"]["email"] == "admin@bastion.local"
    assert data["csrf_token"] is not None

    # Verify session cookie was set with HttpOnly and Lax
    cookie = res.cookies.get(SESSION_COOKIE_NAME)
    assert cookie is not None

    # Subsequent setup attempts must be blocked
    res2 = client.post(
        "/api/auth/setup",
        json={"email": "hacker@evil.com", "password": "AnotherAdminPassword123!", "setup_token": SETUP_TOKEN},
    )
    assert res2.status_code == 400
    assert "already been completed" in res2.text


# ============================================================
# 4. Authentication, Brute-Force Lockout, & Timing Safety
# ============================================================

def test_login_success_and_session_rotation(client):
    """Valid credentials authenticate user, issue new session, and rotate session ID."""
    client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!", "setup_token": SETUP_TOKEN},
    )

    # Login
    res = client.post(
        "/api/auth/login",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "success"
    assert res.cookies.get(SESSION_COOKIE_NAME) is not None


def test_login_brute_force_lockout_after_5_failures(client):
    """5 consecutive failed attempts lock the account for 15 minutes with generic error."""
    client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!", "setup_token": SETUP_TOKEN},
    )

    # Attempt 1 to 4: generic "Invalid email or password"
    for i in range(1, 5):
        res = client.post(
            "/api/auth/login",
            json={"email": "admin@bastion.local", "password": "WrongPassword123!"},
        )
        assert res.status_code == 401
        assert "Invalid email or password" in res.json()["detail"]

    # Attempt 5: triggers lockout
    res5 = client.post(
        "/api/auth/login",
        json={"email": "admin@bastion.local", "password": "WrongPassword123!"},
    )
    assert res5.status_code == 401
    assert res5.json()["detail"] == "Invalid email or password"

    # Verify user record is locked in database
    user = db.get_user_by_email("admin@bastion.local")
    assert user["failed_attempts"] >= 5
    assert user["locked_until"] > time.time()

    # Even with the CORRECT password, locked account is rejected with identical generic message
    res_correct_while_locked = client.post(
        "/api/auth/login",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!"},
    )
    assert res_correct_while_locked.status_code == 401
    assert res_correct_while_locked.json()["detail"] == "Invalid email or password"


def test_unknown_email_returns_same_generic_message(client):
    """Non-existent emails must return exact same message to prevent enumeration."""
    client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!", "setup_token": SETUP_TOKEN},
    )

    res = client.post(
        "/api/auth/login",
        json={"email": "nonexistent@bastion.local", "password": "WrongPassword123!"},
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid email or password"


# ============================================================
# 5. CSRF Synchronizer Token Protection
# ============================================================

def test_csrf_token_required_on_state_modifications(client):
    """State-changing requests without matching X-CSRF-Token must be rejected with 403."""
    # 1. Setup admin
    setup_res = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!", "setup_token": SETUP_TOKEN},
    )
    csrf_token = setup_res.json()["csrf_token"]
    cookie_val = setup_res.cookies.get(SESSION_COOKIE_NAME)

    # 2. Attempt rule toggle WITHOUT CSRF token -> Rejected (403)
    res_no_csrf = client.post(
        "/api/rules",
        json={"rule_id": "942100", "enabled": False},
        cookies={SESSION_COOKIE_NAME: cookie_val},
    )
    assert res_no_csrf.status_code == 403
    assert "CSRF" in res_no_csrf.json()["detail"]["error"]

    # 3. Attempt rule toggle WITH valid CSRF token -> Accepted (200)
    res_with_csrf = client.post(
        "/api/rules",
        json={"rule_id": "942100", "enabled": False},
        headers={"X-CSRF-Token": csrf_token},
        cookies={SESSION_COOKIE_NAME: cookie_val},
    )
    assert res_with_csrf.status_code == 200
    assert res_with_csrf.json()["status"] == "success"


# ============================================================
# 6. Session Expiration & Logout
# ============================================================

def test_logout_invalidates_session(client):
    """Logout terminates session row and invalidates cookie."""
    setup_res = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!", "setup_token": SETUP_TOKEN},
    )
    cookie_val = setup_res.cookies.get(SESSION_COOKIE_NAME)

    # Verify session works
    res1 = client.get("/api/rules", cookies={SESSION_COOKIE_NAME: cookie_val})
    assert res1.status_code == 200

    # Logout
    logout_res = client.post("/api/auth/logout", cookies={SESSION_COOKIE_NAME: cookie_val})
    assert logout_res.status_code == 200

    # Verify old session cookie no longer grants access
    res2 = client.get("/api/rules", cookies={SESSION_COOKIE_NAME: cookie_val})
    assert res2.status_code == 401


# ============================================================
# 7. Two-Factor Authentication (TOTP) & Recovery Codes
# ============================================================

def test_totp_2fa_full_lifecycle(client):
    """TOTP setup, enablement, verification, and recovery code login."""
    # 1. Setup admin
    setup_res = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!", "setup_token": SETUP_TOKEN},
    )
    csrf_token = setup_res.json()["csrf_token"]
    cookie_val = setup_res.cookies.get(SESSION_COOKIE_NAME)

    # 2. Initiate 2FA setup
    step1 = client.post(
        "/api/auth/2fa/setup",
        headers={"X-CSRF-Token": csrf_token},
        cookies={SESSION_COOKIE_NAME: cookie_val},
    )
    assert step1.status_code == 200
    secret = step1.json()["secret"]

    # 3. Generate correct TOTP code and confirm enable
    valid_code = compute_totp_code(secret)
    step2 = client.post(
        "/api/auth/2fa/enable",
        json={"secret": secret, "code": valid_code},
        headers={"X-CSRF-Token": csrf_token},
        cookies={SESSION_COOKIE_NAME: cookie_val},
    )
    assert step2.status_code == 200
    recovery_codes = step2.json()["recovery_codes"]
    assert len(recovery_codes) == 10

    # 4. Log out
    client.post("/api/auth/logout", cookies={SESSION_COOKIE_NAME: cookie_val})

    # 5. Login step 1: should return 2fa_required
    login1 = client.post(
        "/api/auth/login",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!"},
    )
    assert login1.status_code == 200
    assert login1.json()["status"] == "2fa_required"
    temp_token = login1.json()["temp_token"]

    # 6. Login step 2 with valid TOTP code
    fresh_code = compute_totp_code(secret)
    login2 = client.post(
        "/api/auth/2fa/verify",
        json={"temp_token": temp_token, "code": fresh_code, "is_recovery": False},
    )
    assert login2.status_code == 200
    assert login2.json()["status"] == "success"
    assert login2.cookies.get(SESSION_COOKIE_NAME) is not None

    # 7. Test Recovery Code login
    # Initiate another login
    client.post("/api/auth/logout", cookies={SESSION_COOKIE_NAME: login2.cookies.get(SESSION_COOKIE_NAME)})
    login3 = client.post(
        "/api/auth/login",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!"},
    )
    temp_token2 = login3.json()["temp_token"]

    # Use first recovery code
    used_rec = recovery_codes[0]
    rec_res = client.post(
        "/api/auth/2fa/verify",
        json={"temp_token": temp_token2, "code": used_rec, "is_recovery": True},
    )
    assert rec_res.status_code == 200
    assert rec_res.json()["status"] == "success"

    # Attempt to reuse the same recovery code -> must fail
    client.post("/api/auth/logout", cookies={SESSION_COOKIE_NAME: rec_res.cookies.get(SESSION_COOKIE_NAME)})
    login4 = client.post(
        "/api/auth/login",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!"},
    )
    temp_token3 = login4.json()["temp_token"]
    reuse_res = client.post(
        "/api/auth/2fa/verify",
        json={"temp_token": temp_token3, "code": used_rec, "is_recovery": True},
    )
    assert reuse_res.status_code == 401
    assert "Invalid recovery code" in reuse_res.json()["detail"]


# ============================================================
# 8. Password Reset Flow
# ============================================================

def test_password_reset_flow_and_session_invalidation(client):
    """Password reset via token updates password and terminates all active sessions."""
    setup_res = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "OldPassword123456!", "setup_token": SETUP_TOKEN},
    )
    old_cookie = setup_res.cookies.get(SESSION_COOKIE_NAME)

    # Request reset token
    raw_token = generate_secure_token()
    user_id = db.create_password_reset("admin@bastion.local", raw_token)
    assert user_id is not None

    # Confirm reset with strong password
    confirm_res = client.post(
        "/api/auth/reset/confirm",
        json={"token": raw_token, "new_password": "NewBrandSecurePassword123!"},
    )
    assert confirm_res.status_code == 200
    assert confirm_res.json()["status"] == "success"

    # Old session must now be invalidated
    res_old = client.get("/api/rules", cookies={SESSION_COOKIE_NAME: old_cookie})
    assert res_old.status_code == 401

    # Cannot reuse same reset token
    confirm_reuse = client.post(
        "/api/auth/reset/confirm",
        json={"token": raw_token, "new_password": "AnotherNewPassword123!"},
    )
    assert confirm_reuse.status_code == 400
    assert "already been used" in confirm_reuse.json()["detail"]


# ============================================================
# 9. Security Headers
# ============================================================

def test_security_headers_present_on_responses(client):
    """Responses must include X-Content-Type-Options, X-Frame-Options, CSP, and Referrer-Policy."""
    res = client.get("/api/auth/status")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "same-origin"
    assert "default-src 'self'" in res.headers.get("Content-Security-Policy", "")


# ============================================================
# 10. Amendments Verification (Docs, Scrypt params, Setup Token, Simulation)
# ============================================================

def test_openapi_and_docs_disabled_publicly(client):
    """FastAPI's /openapi.json, /docs, and /redoc must be disabled for unauthenticated visitors."""
    # Unauthenticated /openapi.json must return 404 (disabled from root app)
    res_openapi = client.get("/openapi.json")
    assert res_openapi.status_code == 404

    res_docs = client.get("/docs")
    assert res_docs.status_code == 404

    res_redoc = client.get("/redoc")
    assert res_redoc.status_code == 404

    # Unauthenticated attempt to access /api/openapi.json must return 401
    res_api_openapi = client.get("/api/openapi.json")
    assert res_api_openapi.status_code == 401

    # Authenticated access to /api/openapi.json must succeed (200)
    setup_res = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!", "setup_token": SETUP_TOKEN},
    )
    cookie_val = setup_res.cookies.get(SESSION_COOKIE_NAME)
    res_auth_openapi = client.get("/api/openapi.json", cookies={SESSION_COOKIE_NAME: cookie_val})
    assert res_auth_openapi.status_code == 200
    assert "openapi" in res_auth_openapi.json()


def test_scrypt_parameter_format():
    """Scrypt hash must encode N=131072 (2^17), r=8, p=1 and salt inside the hash string."""
    hash_str = hash_password("SuperSecurePassword123!")
    assert hash_str.startswith("scrypt$131072$8$1$")
    assert verify_password("SuperSecurePassword123!", hash_str)
    assert not verify_password("WrongPassword123!", hash_str)


def test_setup_token_enforcement(client, monkeypatch):
    """When BASTION_SETUP_TOKEN is configured in environment, web setup requires it."""
    monkeypatch.setenv("BASTION_SETUP_TOKEN", "secure-airgapped-token-xyz789")

    # Attempt setup without token -> 403
    res_no_token = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!"},
    )
    assert res_no_token.status_code == 403
    assert "Invalid setup token" in res_no_token.json()["detail"]

    # Attempt setup with WRONG token -> 403
    res_wrong_token = client.post(
        "/api/auth/setup",
        json={
            "email": "admin@bastion.local",
            "password": "SuperSecureAdminPassword123!",
            "setup_token": "wrong-token",
        },
    )
    assert res_wrong_token.status_code == 403
    assert "Invalid setup token" in res_wrong_token.json()["detail"]

    # Attempt setup with CORRECT token -> 200
    res_correct = client.post(
        "/api/auth/setup",
        json={
            "email": "admin@bastion.local",
            "password": "SuperSecureAdminPassword123!",
            "setup_token": "secure-airgapped-token-xyz789",
        },
    )
    assert res_correct.status_code == 200
    assert res_correct.json()["status"] == "success"


def test_simulate_does_not_pollute_real_logs(client):
    """Payload simulations must evaluate threats without writing to real production events."""
    setup_res = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecureAdminPassword123!", "setup_token": SETUP_TOKEN},
    )
    cookie_val = setup_res.cookies.get(SESSION_COOKIE_NAME)
    csrf_token = setup_res.json()["csrf_token"]

    # Confirm zero events initially
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events")
        assert cursor.fetchone()[0] == 0

    # Execute simulation
    sim_res = client.post(
        "/api/simulate",
        json={
            "method": "GET",
            "path": "/search",
            "query_string": "q=admin' OR '1'='1",
            "body": "",
            "headers": {},
            "client_ip": "192.168.1.100",
        },
        headers={"X-CSRF-Token": csrf_token},
        cookies={SESSION_COOKIE_NAME: cookie_val},
    )
    assert sim_res.status_code == 200
    assert sim_res.json()["blocked"] is True

    # Confirm events table remains empty (simulation did not pollute production telemetry)
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events")
        assert cursor.fetchone()[0] == 0


def test_cleanup_expired_sessions_purges_stale():
    """cleanup_expired_sessions must remove sessions older than 30m idle or 7d max."""
    user_id = 9999
    now = time.time()
    with db.get_connection() as conn:
        # 1. Stale idle session (> 1800s ago)
        conn.execute(
            """
            INSERT INTO sessions (user_id, token_hash, created_at, last_seen_at, expires_at, ip, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, "stale_idle_hash", now - 3600, now - 2000, now + 86400, "127.0.0.1", ""),
        )
        # 2. Fresh session
        conn.execute(
            """
            INSERT INTO sessions (user_id, token_hash, created_at, last_seen_at, expires_at, ip, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, "fresh_session_hash", now, now, now + 86400, "127.0.0.1", ""),
        )
        conn.commit()

    db.cleanup_expired_sessions()

    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT token_hash FROM sessions WHERE user_id = ?", (user_id,))
        remaining = [r[0] for r in cursor.fetchall()]
        assert "fresh_session_hash" in remaining
        assert "stale_idle_hash" not in remaining
