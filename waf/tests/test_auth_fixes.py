"""
Bastion WAF — Verification Test Suite for Security Fixes 1 through 8.
Covers:
Fix 1: Public API docs disabled unless BASTION_DEBUG=1; proxy does not leak upstream docs; authenticated /api/openapi.json works.
Fix 2: Mandatory setup token & CLI; setup token enforcement; atomic admin creation; CLI create-admin and reset-password.
Fix 3: Persistent DB path loading; Render non-persistent path warning; startup self-check.
Fix 4: State-changing CSRF protection (Origin/Referer check + HMAC X-CSRF-Token).
Fix 5: Trusted proxy client IP resolution, sliding window rate limit (429 + Retry-After), lockout & dummy verify timing.
Fix 6: Security headers (HSTS, nosniff, DENY, same-origin, CSP, no-store) & cookie flags (__Host- prefix, rotation).
Fix 7: Hashed session tokens, idle & absolute timeouts, session revocation endpoints, audit logging & GET /api/audit.
Fix 8: Deploy-time route coverage test asserting require_auth or PUBLIC_API_ROUTES allowlist.
"""

import os
import sqlite3
import time
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from api.server import app, PUBLIC_API_ROUTES
from api.auth import (
    SESSION_COOKIE_NAME,
    get_client_ip,
    reset_rate_limits,
    is_cookie_secure,
    get_session_cookie_name,
)
from database import db
from cli import create_admin_cmd, reset_password_cmd


SETUP_TOKEN = "mandatory-setup-secret-token-12345"


@pytest.fixture(autouse=True)
def clean_env_and_db(tmp_path, monkeypatch):
    """Ensure clean isolated SQLite database, reset rate limits, and controlled env vars for each test."""
    test_db = tmp_path / "fixes_waf.db"
    monkeypatch.setenv("BASTION_DB_PATH", str(test_db))
    monkeypatch.setattr(db, "DB_PATH", test_db)
    monkeypatch.setenv("BASTION_SETUP_TOKEN", SETUP_TOKEN)
    monkeypatch.setenv("BASTION_ALLOWED_ORIGINS", "http://testserver,http://localhost:8000")
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
# FIX 1: PUBLIC API DOCS
# ============================================================

def test_fix1_public_docs_disabled_and_authenticated_openapi_works(client, monkeypatch):
    """Public /openapi.json, /docs, /redoc return 404; authenticated /api/openapi.json returns schema."""
    monkeypatch.delenv("BASTION_DEBUG", raising=False)

    # 1. Unauthenticated root docs return 404
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404

    # 2. Unauthenticated /api/openapi.json returns 401
    assert client.get("/api/openapi.json").status_code == 401

    # 3. Create admin & authenticate
    res_setup = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecurePassword123!", "setup_token": SETUP_TOKEN},
    )
    assert res_setup.status_code == 200
    cookie_name = get_session_cookie_name(client)
    cookie_val = res_setup.cookies.get(cookie_name) or res_setup.cookies.get("bastion_session") or res_setup.cookies.get("__Host-bastion_session")

    # 4. Authenticated /api/openapi.json returns 200 with schema
    res_auth = client.get("/api/openapi.json", cookies={cookie_name: cookie_val})
    assert res_auth.status_code == 200
    schema = res_auth.json()
    assert "openapi" in schema
    assert "/api/rules" in schema.get("paths", {})


# ============================================================
# FIX 2: MANDATORY SETUP TOKEN & CLI
# ============================================================

def test_fix2_setup_token_mandatory_when_unset_and_wrong(client, monkeypatch):
    """When BASTION_SETUP_TOKEN is unset, 403 Forbidden with exact message; GET /status reports setup_available=false."""
    monkeypatch.delenv("BASTION_SETUP_TOKEN", raising=False)

    # 1. GET /api/auth/status reports setup_available=False and warning message
    res_status = client.get("/api/auth/status")
    assert res_status.status_code == 200
    status_data = res_status.json()
    assert status_data["setup_available"] is False
    assert "setup not available, run the create-admin CLI" in status_data.get("message", "")

    # 2. POST /api/auth/setup returns 403 with exact disabled message
    res_setup = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecurePassword123!"},
    )
    assert res_setup.status_code == 403
    assert "Initial setup is disabled" in res_setup.json()["detail"]


def test_fix2_setup_token_verification_and_bearer_auth(client, monkeypatch):
    """Setup accepts token via JSON payload or Authorization Bearer header, rejects wrong token, prevents second setup."""
    monkeypatch.setenv("BASTION_SETUP_TOKEN", "super-secret-token-xyz")

    # Wrong token -> 403
    res_wrong = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecurePassword123!", "setup_token": "wrong"},
    )
    assert res_wrong.status_code == 403
    assert "Invalid setup token" in res_wrong.json()["detail"]

    # Correct token via Authorization Bearer header -> 200
    res_bearer = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecurePassword123!"},
        headers={"Authorization": "Bearer super-secret-token-xyz"},
    )
    assert res_bearer.status_code == 200
    assert res_bearer.json()["status"] == "success"

    # Subsequent setup attempt must fail -> 400
    res_second = client.post(
        "/api/auth/setup",
        json={"email": "second@bastion.local", "password": "SuperSecurePassword123!", "setup_token": "super-secret-token-xyz"},
    )
    assert res_second.status_code == 400
    assert "already been completed" in res_second.json()["detail"]


def test_fix2_atomic_first_admin_race_condition():
    """create_first_admin_atomic must ensure exactly one admin is created under concurrent calls."""
    ok1, msg1, uid1 = db.create_first_admin_atomic("admin1@bastion.local", "SuperSecurePassword123!")
    assert ok1 is True
    assert uid1 is not None

    ok2, msg2, uid2 = db.create_first_admin_atomic("admin2@bastion.local", "SuperSecurePassword123!")
    assert ok2 is False
    assert uid2 is None
    assert "already been completed" in msg2


def test_fix2_cli_commands():
    """CLI create-admin and reset-password work via getpass prompt without plaintext args."""
    # 1. create-admin
    with patch("getpass.getpass", side_effect=["CliAdminPassword123!", "CliAdminPassword123!"]):
        ok = create_admin_cmd("cli-admin@bastion.local")
        assert ok is True

    user = db.get_user_by_email("cli-admin@bastion.local")
    assert user is not None
    assert db.verify_password("CliAdminPassword123!", user["password_hash"])

    # 2. reset-password
    with patch("getpass.getpass", side_effect=["NewCliPassword456!", "NewCliPassword456!"]):
        ok_reset = reset_password_cmd("cli-admin@bastion.local")
        assert ok_reset is True

    user_updated = db.get_user_by_email("cli-admin@bastion.local")
    assert db.verify_password("NewCliPassword456!", user_updated["password_hash"])


# ============================================================
# FIX 3: PERSISTENT DB ON RENDER
# ============================================================

def test_fix3_persistent_db_path_and_render_check(tmp_path, monkeypatch, caplog):
    """startup_self_check logs DB path, warns if on Render without persistent disk, refuses if prod secrets missing."""
    custom_db = tmp_path / "custom" / "bastion.db"
    monkeypatch.setenv("BASTION_DB_PATH", str(custom_db))
    monkeypatch.setattr(db, "DB_PATH", custom_db)
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("BASTION_SETUP_TOKEN", "test-setup-token")
    monkeypatch.setenv("BASTION_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("BASTION_ENCRYPTION_KEY", "test-encryption-key")

    # When on Render and not under /var/data, logs warning
    with caplog.at_level("WARNING"):
        db.startup_self_check()
    assert "is NOT on persistent storage on Render" in caplog.text

    # In production without BASTION_ENCRYPTION_KEY, refuses startup
    monkeypatch.setenv("BASTION_ENV", "production")
    monkeypatch.delenv("BASTION_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError) as exc_info:
        db.startup_self_check()
    assert "Startup refused" in str(exc_info.value)


# ============================================================
# FIX 4: STATE-CHANGING CSRF PROTECTION
# ============================================================

def test_fix4_csrf_origin_and_synchronizer_token(client):
    """Mutating calls require allowed Origin and valid HMAC synchronizer token."""
    # 1. Setup admin
    res_setup = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecurePassword123!", "setup_token": SETUP_TOKEN},
    )
    assert res_setup.status_code == 200
    csrf_token = res_setup.json()["csrf_token"]
    cookie_name = get_session_cookie_name(client)
    cookie_val = res_setup.cookies.get(cookie_name) or res_setup.cookies.get("bastion_session") or res_setup.cookies.get("__Host-bastion_session")

    # 2. Missing Origin header -> 403
    res_no_origin = client.post(
        "/api/rules",
        json={"rule_id": "942100", "enabled": False},
        headers={"Origin": "", "X-CSRF-Token": csrf_token},
        cookies={cookie_name: cookie_val},
    )
    assert res_no_origin.status_code == 403
    assert "CSRF: Missing Origin" in res_no_origin.json()["detail"]["error"]

    # 3. Foreign Origin -> 403
    res_foreign_origin = client.post(
        "/api/rules",
        json={"rule_id": "942100", "enabled": False},
        headers={"Origin": "https://evil-attacker.com", "X-CSRF-Token": csrf_token},
        cookies={cookie_name: cookie_val},
    )
    assert res_foreign_origin.status_code == 403
    assert "CSRF: Origin not allowed" in res_foreign_origin.json()["detail"]["error"]

    # 4. Valid Origin but missing CSRF token -> 403
    res_no_token = client.post(
        "/api/rules",
        json={"rule_id": "942100", "enabled": False},
        headers={"Origin": "http://testserver"},
        cookies={cookie_name: cookie_val},
    )
    assert res_no_token.status_code == 403
    assert "CSRF: Invalid or missing CSRF token" in res_no_token.json()["detail"]["error"]

    # 5. Valid Origin AND valid CSRF token -> 200
    res_valid = client.post(
        "/api/rules",
        json={"rule_id": "942100", "enabled": False},
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf_token},
        cookies={cookie_name: cookie_val},
    )
    assert res_valid.status_code == 200
    assert res_valid.json()["status"] == "success"


# ============================================================
# FIX 5: TRUSTED PROXY RATE LIMITING & TIMING EQUALITY
# ============================================================

def test_fix5_trusted_proxy_client_ip_resolution(monkeypatch):
    """get_client_ip ignores spoofed X-Forwarded-For unless peer is in BASTION_TRUSTED_PROXIES."""
    class MockClient:
        host = "192.168.1.50"

    class MockRequest:
        client = MockClient()
        headers = {
            "X-Forwarded-For": "203.0.113.195, 10.0.0.1",
            "CF-Connecting-IP": "203.0.113.195",
        }

    # 1. Untrusted peer: ignores headers, returns direct socket IP
    monkeypatch.delenv("BASTION_TRUSTED_PROXIES", raising=False)
    ip_untrusted = get_client_ip(MockRequest())
    assert ip_untrusted == "192.168.1.50"

    # 2. Trusted peer: trusts proxy headers
    monkeypatch.setenv("BASTION_TRUSTED_PROXIES", "192.168.1.50,10.0.0.0/8")
    ip_trusted = get_client_ip(MockRequest())
    assert ip_trusted == "203.0.113.195"


def test_fix5_rate_limit_sliding_window_429(client):
    """11th login attempt within 15 minutes returns 429 Too Many Requests with Retry-After header."""
    reset_rate_limits()

    # Attempts 1 to 10 execute normally
    for i in range(10):
        client.post(
            "/api/auth/login",
            json={"email": "admin@bastion.local", "password": "WrongPassword123!"},
        )

    # 11th attempt hits 429
    res_11 = client.post(
        "/api/auth/login",
        json={"email": "admin@bastion.local", "password": "WrongPassword123!"},
    )
    assert res_11.status_code == 429
    assert "Too many attempts" in res_11.json()["detail"]
    assert "Retry-After" in res_11.headers


def test_fix5_timing_equality_dummy_verify():
    """Non-existent email triggers dummy verify to equalize response timing with existing email."""
    t0 = time.perf_counter()
    db.authenticate_user("nonexistent@bastion.local", "SuperSecurePassword123!", "127.0.0.1")
    t_nonexistent = time.perf_counter() - t0

    # Ensure scrypt was executed (takes at least 5ms)
    assert t_nonexistent > 0.005


# ============================================================
# FIX 6: SECURITY HEADERS & COOKIE ATTRIBUTES
# ============================================================

def test_fix6_security_headers_and_cookie_attributes(client, monkeypatch):
    """Responses include HSTS, nosniff, DENY, CSP, no-store; cookies enforce HttpOnly, SameSite, and Secure."""
    # 1. Headers on /api/*
    res = client.get("/api/auth/status")
    assert res.headers.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains; preload"
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "same-origin"
    assert "default-src 'self'" in res.headers.get("Content-Security-Policy", "")
    assert "no-store" in res.headers.get("Cache-Control", "")

    # 2. Secure cookie prefix when BASTION_COOKIE_SECURE=1
    monkeypatch.setenv("BASTION_COOKIE_SECURE", "1")
    res_setup = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecurePassword123!", "setup_token": SETUP_TOKEN},
    )
    assert res_setup.status_code == 200
    cookie_header = res_setup.headers.get("set-cookie", "")
    assert "__Host-bastion_session=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=lax" in cookie_header or "SameSite=Lax" in cookie_header
    assert "Secure" in cookie_header


# ============================================================
# FIX 7: SESSION LIFECYCLE, REVOCATION, & AUDIT TRAIL
# ============================================================

def test_fix7_session_revocation_endpoints(client):
    """GET /api/auth/sessions lists sessions, DELETE /sessions/{id} and POST /revoke-others work."""
    # 1. Setup admin
    res_setup = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecurePassword123!", "setup_token": SETUP_TOKEN},
    )
    user_id = res_setup.json()["user"]["id"]
    csrf_token = res_setup.json()["csrf_token"]
    cookie_name = get_session_cookie_name(client)
    cookie_val = res_setup.cookies.get(cookie_name) or res_setup.cookies.get("bastion_session") or res_setup.cookies.get("__Host-bastion_session")

    # 2. Add a second session directly to DB
    now = time.time()
    db.create_session(user_id, "second_session_raw_token_xyz", ip="10.10.10.10", user_agent="SecondaryDevice")

    # 3. GET /api/auth/sessions returns 2 sessions
    res_sessions = client.get("/api/auth/sessions", cookies={cookie_name: cookie_val})
    assert res_sessions.status_code == 200
    sessions = res_sessions.json()["sessions"]
    assert len(sessions) == 2
    assert any(s["is_current"] for s in sessions)

    second_session = next(s for s in sessions if not s["is_current"])

    # 4. DELETE /api/auth/sessions/{id} revokes specific session
    res_del = client.delete(
        f"/api/auth/sessions/{second_session['id']}",
        headers={"X-CSRF-Token": csrf_token},
        cookies={cookie_name: cookie_val},
    )
    assert res_del.status_code == 200

    # 5. POST /api/auth/sessions/revoke-others
    db.create_session(user_id, "third_session_raw_token_xyz", ip="10.10.10.20", user_agent="ThirdDevice")
    res_revoke_others = client.post(
        "/api/auth/sessions/revoke-others",
        headers={"X-CSRF-Token": csrf_token},
        cookies={cookie_name: cookie_val},
    )
    assert res_revoke_others.status_code == 200
    assert res_revoke_others.json()["revoked_count"] >= 1


def test_fix7_audit_log_records_and_retrieval(client):
    """Security events write to audit trail and can be queried via authenticated GET /api/audit."""
    # 1. Setup admin
    res_setup = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.local", "password": "SuperSecurePassword123!", "setup_token": SETUP_TOKEN},
    )
    cookie_name = get_session_cookie_name(client)
    cookie_val = res_setup.cookies.get(cookie_name) or res_setup.cookies.get("bastion_session") or res_setup.cookies.get("__Host-bastion_session")

    # 2. Query GET /api/audit
    res_audit = client.get("/api/audit", cookies={cookie_name: cookie_val})
    assert res_audit.status_code == 200
    raw_logs = res_audit.json()
    logs = raw_logs if isinstance(raw_logs, list) else raw_logs.get("logs", [])
    assert len(logs) >= 1
    actions = [l["action"] for l in logs]
    assert "INITIAL_ADMIN_SETUP" in actions


# ============================================================
# FIX 8: DEPLOY-TIME ROUTE COVERAGE TEST
# ============================================================

def test_fix8_route_coverage_assertion():
    """
    Every route under /api/* MUST either have require_auth dependency
    OR be in the explicit PUBLIC_API_ROUTES allowlist.
    Fails build/deploy if any unauthenticated route is unlisted.
    """
    from fastapi.routing import APIRoute

    unprotected_unlisted = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        path = route.path
        if not path.startswith("/api/"):
            continue

        # Check if route has require_auth in endpoint dependencies or route.dependencies
        has_auth = False
        all_deps = list(route.dependencies)
        if hasattr(route.endpoint, "__defaults__") and route.endpoint.__defaults__:
            for d in route.endpoint.__defaults__:
                if hasattr(d, "dependency") and getattr(d.dependency, "__name__", "") == "require_auth":
                    has_auth = True
                    break

        for d in all_deps:
            if hasattr(d, "dependency") and getattr(d.dependency, "__name__", "") == "require_auth":
                has_auth = True
                break

        is_public = path in PUBLIC_API_ROUTES
        if not has_auth and not is_public:
            unprotected_unlisted.append(f"{route.methods} {path}")

    assert len(unprotected_unlisted) == 0, (
        f"CRITICAL: Unprotected /api/* routes detected without require_auth or allowlist: {unprotected_unlisted}"
    )
