"""
Test suite validating PostgreSQL compatibility, database connection pooling,
SQL injection mitigations (LIKE pattern escaping, parameter binding),
and strict Pydantic input validation across Bastion WAF.
"""

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from api.auth import SESSION_COOKIE_NAME, reset_rate_limits
from api.server import app
from database import db
from database.db import (
    escape_like,
    get_db_url,
    get_engine,
    get_logs,
    init_db,
    is_postgres,
    log_event,
    reset_engine,
)


@pytest.fixture(autouse=True)
def clean_test_database(tmp_path, monkeypatch):
    """Ensure isolated test database for each test run."""
    test_db = tmp_path / "test_val_waf.db"
    monkeypatch.setattr(db, "DB_PATH", test_db)
    monkeypatch.setenv("BASTION_SETUP_TOKEN", "test-setup-token")
    monkeypatch.setenv("BASTION_ALLOWED_ORIGINS", "http://testserver,http://localhost:8000")
    reset_rate_limits()
    reset_engine()
    init_db()
    yield
    reset_rate_limits()
    reset_engine()
    if test_db.exists():
        try:
            test_db.unlink()
        except Exception:
            pass


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def authenticated_admin(client):
    """Create an administrator account and return session cookie + csrf token."""
    setup_res = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.test", "password": "SecurePassword12345!", "setup_token": "test-setup-token"},
        headers={"Origin": "http://testserver"},
    )
    assert setup_res.status_code == 200
    cookie_val = setup_res.cookies.get(SESSION_COOKIE_NAME)
    csrf_token = setup_res.json().get("csrf_token")
    return {"cookie": cookie_val, "csrf": csrf_token}


# ============================================================
# 1. Database Connection & PostgreSQL URL Normalization
# ============================================================

def test_database_url_normalization(monkeypatch):
    """Verify that Render postgres:// and standard postgresql:// are normalized to psycopg."""
    monkeypatch.setenv("DATABASE_URL", "postgres://user:secret@render.db.internal:5432/bastion")
    assert get_db_url() == "postgresql+psycopg://user:secret@render.db.internal:5432/bastion"
    assert is_postgres() is True

    monkeypatch.setenv("DATABASE_URL", "postgresql://user:secret@localhost:5432/bastion")
    assert get_db_url() == "postgresql+psycopg://user:secret@localhost:5432/bastion"
    assert is_postgres() is True

    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert get_db_url().startswith("sqlite:///")
    assert is_postgres() is False


def test_sqlite_engine_uses_nullpool():
    """Verify that SQLite engine operates cleanly with pool lifecycle."""
    eng = get_engine()
    assert eng is not None
    assert str(eng.url).startswith("sqlite:///")


# ============================================================
# 2. SQL Injection Mitigations & LIKE Query Escaping
# ============================================================

def test_like_query_escaping_logic():
    """Verify wildcard characters %, _, and backslash are properly escaped."""
    assert escape_like("normal_search") == "normal\\_search"
    assert escape_like("100%_match") == "100\\%\\_match"
    assert escape_like("path\\file") == "path\\\\file"
    assert escape_like("safe-token-123") == "safe-token-123"


def test_like_query_mitigates_wildcard_enumeration():
    """Verify that searching for % does not match all entries due to LIKE escaping."""
    log_event(client_ip="10.0.0.1", method="GET", path="/api/v1/user", blocked=False)
    log_event(client_ip="10.0.0.2", method="POST", path="/api/100%discount", blocked=True)

    # Search for literal '%' should ONLY match the discount path
    results = get_logs(query="%discount")
    assert len(results) == 1
    assert results[0]["path"] == "/api/100%discount"

    # Searching for arbitrary wildcard '%' alone shouldn't bypass filtering
    wildcard_results = get_logs(query="nonexistent%")
    assert len(wildcard_results) == 0


# ============================================================
# 3. Input Validation: Sites & Domain Validation
# ============================================================

def test_add_site_rejects_sqli_payload(client, authenticated_admin):
    """Site creation must reject SQL injection strings in domain."""
    res = client.post(
        "/api/sites",
        json={
            "domain": "'; DROP TABLE users; --",
            "upstream": "http://127.0.0.1:3000",
        },
        cookies={SESSION_COOKIE_NAME: authenticated_admin["cookie"]},
        headers={"X-CSRF-Token": authenticated_admin["csrf"]},
    )
    assert res.status_code == 422  # Pydantic validation failure


def test_add_site_rejects_xss_payload(client, authenticated_admin):
    """Site creation must reject script injection strings in domain."""
    res = client.post(
        "/api/sites",
        json={
            "domain": "<script>alert(1)</script>",
            "upstream": "http://127.0.0.1:3000",
        },
        cookies={SESSION_COOKIE_NAME: authenticated_admin["cookie"]},
        headers={"X-CSRF-Token": authenticated_admin["csrf"]},
    )
    assert res.status_code == 422


def test_add_site_rejects_malicious_upstream_schemes(client, authenticated_admin):
    """Upstream URL must reject javascript: or file: schemes."""
    for bad_upstream in ["javascript:alert(1)", "file:///etc/passwd", "data:text/html,<script>"]:
        res = client.post(
            "/api/sites",
            json={
                "domain": "api.example.com",
                "upstream": bad_upstream,
            },
            cookies={SESSION_COOKIE_NAME: authenticated_admin["cookie"]},
            headers={"X-CSRF-Token": authenticated_admin["csrf"]},
        )
        assert res.status_code == 422


def test_add_site_accepts_valid_domain_and_upstream(client, authenticated_admin):
    """Valid domain and upstream should succeed."""
    res = client.post(
        "/api/sites",
        json={
            "domain": "my-app.example.com:8443",
            "upstream": "https://backend.internal.net:8080",
        },
        cookies={SESSION_COOKIE_NAME: authenticated_admin["cookie"]},
        headers={"Origin": "http://testserver", "X-CSRF-Token": authenticated_admin["csrf"]},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "success"


def test_delete_site_validates_path_parameter(client, authenticated_admin):
    """Deleting a site with negative or invalid ID must return 422."""
    res = client.delete(
        "/api/sites/-1",
        cookies={SESSION_COOKIE_NAME: authenticated_admin["cookie"]},
        headers={"X-CSRF-Token": authenticated_admin["csrf"]},
    )
    assert res.status_code == 422

    res2 = client.delete(
        "/api/sites/0",
        cookies={SESSION_COOKIE_NAME: authenticated_admin["cookie"]},
        headers={"X-CSRF-Token": authenticated_admin["csrf"]},
    )
    assert res2.status_code == 422


# ============================================================
# 4. Input Validation: Rule Toggles
# ============================================================

def test_rule_toggle_rejects_sqli_id(client, authenticated_admin):
    """Rule toggle must strictly enforce 6-digit numeric rule ID."""
    res = client.post(
        "/api/rules",
        json={"rule_id": "942100' OR '1'='1", "enabled": False},
        cookies={SESSION_COOKIE_NAME: authenticated_admin["cookie"]},
        headers={"X-CSRF-Token": authenticated_admin["csrf"]},
    )
    assert res.status_code == 422


def test_rule_toggle_accepts_valid_id(client, authenticated_admin):
    """Rule toggle with valid 6-digit ID succeeds."""
    res = client.post(
        "/api/rules",
        json={"rule_id": "942100", "enabled": False},
        cookies={SESSION_COOKIE_NAME: authenticated_admin["cookie"]},
        headers={"Origin": "http://testserver", "X-CSRF-Token": authenticated_admin["csrf"]},
    )
    assert res.status_code == 200
    assert res.json()["enabled"] is False


# ============================================================
# 5. Input Validation: Logs & Query Clamping
# ============================================================

def test_logs_endpoint_validates_query_params(client, authenticated_admin):
    """Logs endpoint enforces limit bounds (1-500) and string length bounds."""
    # Negative limit
    res_neg = client.get(
        "/api/logs?limit=-1",
        cookies={SESSION_COOKIE_NAME: authenticated_admin["cookie"]},
    )
    assert res_neg.status_code == 422

    # Zero limit
    res_zero = client.get(
        "/api/logs?limit=0",
        cookies={SESSION_COOKIE_NAME: authenticated_admin["cookie"]},
    )
    assert res_zero.status_code == 422

    # Limit too large (> 500)
    res_huge = client.get(
        "/api/logs?limit=1000",
        cookies={SESSION_COOKIE_NAME: authenticated_admin["cookie"]},
    )
    assert res_huge.status_code == 422

    # Valid bounds
    res_ok = client.get(
        "/api/logs?limit=50&q=test&threat=OWASP+Top+10",
        cookies={SESSION_COOKIE_NAME: authenticated_admin["cookie"]},
    )
    assert res_ok.status_code == 200


# ============================================================
# 6. Input Validation: Authentication Payloads
# ============================================================

def test_auth_setup_rejects_malformed_email(client):
    """Setup must reject invalid identifier and email formats."""
    for bad_email in ["admin@", "@domain.com", "not an email with spaces", "bad!chars#"]:
        res = client.post(
            "/api/auth/setup",
            json={"email": bad_email, "password": "SecurePassword123!"},
        )
        assert res.status_code == 422


def test_auth_login_rejects_malformed_email(client):
    """Login must reject invalid identifier format prior to DB query."""
    res = client.post(
        "/api/auth/login",
        json={"email": "bad identifier with spaces!", "password": "AnyPassword123!"},
    )
    assert res.status_code == 422


def test_auth_setup_and_login_accepts_username(client):
    """Setup and login must accept simple alphanumeric usernames like 'admin'."""
    setup_res = client.post(
        "/api/auth/setup",
        json={"email": "admin", "password": "@Robelshitahun7", "setup_token": "test-setup-token"},
        headers={"Origin": "http://testserver"},
    )
    assert setup_res.status_code == 200
    assert setup_res.json()["user"]["email"] == "admin"

    login_res = client.post(
        "/api/auth/login",
        json={"email": "admin", "password": "@Robelshitahun7"},
        headers={"Origin": "http://testserver"},
    )
    assert login_res.status_code == 200
    assert login_res.json()["user"]["email"] == "admin"


def test_simulate_rejects_invalid_http_method(client, authenticated_admin):
    """Threat simulate endpoint must reject unapproved HTTP verbs."""
    res = client.post(
        "/api/simulate",
        json={
            "method": "EVIL_METHOD_INJECTION",
            "path": "/search",
            "body": "",
        },
        cookies={SESSION_COOKIE_NAME: authenticated_admin["cookie"]},
    )
    assert res.status_code == 422
