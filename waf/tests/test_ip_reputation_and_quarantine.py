"""
Tests for Phase 3: Behavioral Baselining & Dynamic IP Quarantine in Bastion WAF.
Covers:
1. CIDR validation and parsing (IPv4, IPv6, subnets).
2. Pre-WAF whitelist bypass (traffic forwarded without inspection).
3. Pre-WAF blacklist fast-drop (immediate 403 with X-Bastion-Blacklist header).
4. Sliding window reputation penalty accumulation.
5. Automated quarantine trigger when reaching >= 100 penalty points.
6. Quarantine Retry-After headers and automated TTL expiration.
7. REST API CRUD endpoints with authentication and CSRF validation.
"""

import time
import pytest
from fastapi.testclient import TestClient

from api.auth import SESSION_COOKIE_NAME, reset_rate_limits
from api.server import app
from database import db
from database.db import (
    add_ip_rule,
    delete_ip_rule,
    get_ip_rules,
    init_db,
    reset_engine,
)
from bastion.core.proxy import app as proxy_app
from bastion.core.reputation import (
    PENALTY_CRITICAL_BLOCK,
    check_ip_access,
    get_reputation_score,
    invalidate_rules_cache,
    quarantine_ip,
    record_penalty,
    reset_reputation_store,
)


SETUP_TOKEN = "test-phase3-setup-token"


@pytest.fixture(autouse=True)
def clean_test_environment(tmp_path, monkeypatch):
    """Ensure isolated SQLite DB and clean in-memory state for every test."""
    test_db = tmp_path / "test_phase3.db"
    monkeypatch.setattr(db, "DB_PATH", test_db)
    monkeypatch.setenv("BASTION_DB_PATH", str(test_db))
    monkeypatch.setenv("BASTION_SETUP_TOKEN", SETUP_TOKEN)
    monkeypatch.setenv("BASTION_ALLOWED_ORIGINS", "http://testserver,http://localhost:8000")
    monkeypatch.setenv("BASTION_TRUSTED_PROXIES", "127.0.0.1,::1,testclient")
    reset_rate_limits()
    reset_reputation_store()
    reset_engine()
    init_db()
    yield
    reset_rate_limits()
    reset_reputation_store()
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
def proxy_client():
    return TestClient(proxy_app)


@pytest.fixture
def authenticated_admin(client):
    """Setup administrator and return session cookie + csrf token."""
    setup_res = client.post(
        "/api/auth/setup",
        json={"email": "admin@bastion.test", "password": "SecurePassword12345!", "setup_token": SETUP_TOKEN},
        headers={"Origin": "http://testserver"},
    )
    assert setup_res.status_code == 200
    cookie_val = setup_res.cookies.get(SESSION_COOKIE_NAME)
    csrf_token = setup_res.json().get("csrf_token")
    return {"cookie": cookie_val, "csrf": csrf_token}


# ============================================================
# 1. CIDR Validation & Access Logic
# ============================================================

def test_cidr_validation_and_parsing():
    """Verify add_ip_rule normalizes valid CIDRs and rejects invalid formats."""
    # Valid single IP
    r1 = add_ip_rule("192.168.1.50", "blacklist", "Single host ban")
    assert r1 > 0

    # Valid subnet
    r2 = add_ip_rule("10.0.0.0/8", "whitelist", "Internal corporate VPN")
    assert r2 > 0

    # Valid IPv6
    r3 = add_ip_rule("2001:db8::/32", "quarantine", "IPv6 Bot ban", duration_seconds=600)
    assert r3 > 0

    # Invalid CIDR string raises ValueError
    with pytest.raises(ValueError):
        add_ip_rule("invalid.ip.string", "blacklist")

    with pytest.raises(ValueError):
        add_ip_rule("192.168.1.1", "invalid_type")


def test_manual_whitelist_bypass(proxy_client):
    """Whitelisted CIDR bypasses WAF inspection even on critical attack payloads."""
    # Add whitelist for 10.50.0.0/16
    add_ip_rule("10.50.0.0/16", "whitelist", "Trusted Monitoring Agent")
    invalidate_rules_cache()

    action, reason, _ = check_ip_access("10.50.12.34")
    assert action == "allow"
    assert "Trusted Monitoring" in reason

    # Test via proxy with SQL injection payload from whitelisted client
    res = proxy_client.get(
        "/search?q=UNION+SELECT+1,2,password+FROM+users--",
        headers={"CF-Connecting-IP": "10.50.12.34"},
    )
    # Because 10.50.12.34 is whitelisted, WAF inspection returns allow (200 or upstream response, not 403 WAF block)
    assert res.status_code != 403


def test_manual_blacklist_fast_drop(proxy_client):
    """Blacklisted CIDRs are dropped immediately at the reverse proxy entry point."""
    add_ip_rule("198.51.100.0/24", "blacklist", "Known Threat Actor ASN")
    invalidate_rules_cache()

    action, reason, _ = check_ip_access("198.51.100.88")
    assert action == "block"
    assert "Known Threat Actor" in reason

    # Request from blacklisted IP is dropped before AST inspection
    res = proxy_client.get(
        "/clean-path",
        headers={"CF-Connecting-IP": "198.51.100.88"},
    )
    assert res.status_code == 403
    assert res.headers.get("X-Bastion-Blacklist") == "active"
    data = res.json()
    assert data["blocked"] is True
    assert data["rule"] == "IP_BLACKLIST_DROP"


# ============================================================
# 2. Behavioral Penalties & Auto-Quarantine
# ============================================================

def test_reputation_penalty_accumulation():
    """Verify reputation penalty points accumulate in sliding window."""
    ip = "203.0.113.15"
    assert get_reputation_score(ip) == 0.0

    score1, q1 = record_penalty(ip, 35.0, "SQLi Probe")
    assert score1 == 35.0
    assert q1 is False
    assert get_reputation_score(ip) == 35.0

    score2, q2 = record_penalty(ip, 15.0, "Bot Header Anomaly")
    assert score2 == 50.0
    assert q2 is False
    assert get_reputation_score(ip) == 50.0


def test_auto_quarantine_trigger_and_retry_after(proxy_client):
    """
    When cumulative penalties reach >= 100 points, the IP is automatically
    quarantined with 403 Forbidden and Retry-After header.
    """
    attacker_ip = "192.0.2.77"

    # 1st attack (+35 points = 35)
    s1, q1 = record_penalty(attacker_ip, PENALTY_CRITICAL_BLOCK, "SQLi Attack")
    assert not q1

    # 2nd attack (+35 points = 70)
    s2, q2 = record_penalty(attacker_ip, PENALTY_CRITICAL_BLOCK, "RCE Attack")
    assert not q2

    # 3rd attack (+35 points = 105 >= 100 threshold -> triggers auto-quarantine)
    s3, q3 = record_penalty(attacker_ip, PENALTY_CRITICAL_BLOCK, "SSRF Attack")
    assert q3 is True
    assert s3 >= 100.0

    # Verify IP is now in quarantine
    action, reason, remaining = check_ip_access(attacker_ip)
    assert action == "block"
    assert "quarantine" in reason.lower()
    assert remaining is not None
    assert remaining > 0

    # Proxy request from this IP receives 403 with Retry-After and X-Bastion-Quarantine headers
    res = proxy_client.get(
        "/api/test",
        headers={"CF-Connecting-IP": attacker_ip},
    )
    assert res.status_code == 403
    assert res.headers.get("X-Bastion-Quarantine") == "active"
    assert "Retry-After" in res.headers
    retry_after = int(res.headers["Retry-After"])
    assert retry_after > 0
    assert res.json()["rule"] == "IP_QUARANTINE_DROP"


def test_quarantine_expiration():
    """Temporary quarantine automatically expires after duration_seconds."""
    test_ip = "192.0.2.99"
    # Quarantine for 1 second
    quarantine_ip(test_ip, duration_seconds=1, reason="Short test ban")
    invalidate_rules_cache()

    action, _, remaining = check_ip_access(test_ip)
    assert action == "block"

    # Sleep past expiration
    time.sleep(1.1)
    invalidate_rules_cache()

    action, _, _ = check_ip_access(test_ip)
    assert action == "pass"


# ============================================================
# 3. REST API CRUD & Management Endpoints
# ============================================================

def test_api_ip_rules_unauthenticated(client):
    """Unauthenticated calls to /api/ip-rules must return 401."""
    res = client.get("/api/ip-rules")
    assert res.status_code == 401

    res = client.post("/api/ip-rules", json={"cidr": "1.2.3.4", "rule_type": "blacklist"})
    assert res.status_code == 401

    res = client.delete("/api/ip-rules/1")
    assert res.status_code == 401


def test_api_ip_rules_crud_lifecycle(client, authenticated_admin):
    """Test full CRUD lifecycle for IP access rules via REST API."""
    cookies = {SESSION_COOKIE_NAME: authenticated_admin["cookie"]}
    headers = {"Origin": "http://testserver", "X-CSRF-Token": authenticated_admin["csrf"]}

    # 1. Initially empty
    res = client.get("/api/ip-rules", cookies=cookies)
    assert res.status_code == 200
    assert len(res.json()) == 0

    # 2. Add Blacklist Rule
    create_res = client.post(
        "/api/ip-rules",
        json={
            "cidr": "45.33.32.156",
            "rule_type": "blacklist",
            "reason": "Scanner botnet node",
            "duration_seconds": 3600,
        },
        cookies=cookies,
        headers=headers,
    )
    assert create_res.status_code == 200
    rule_id = create_res.json()["rule_id"]
    assert rule_id > 0
    assert create_res.json()["cidr"] == "45.33.32.156/32"

    # 3. List rules and verify entry
    list_res = client.get("/api/ip-rules", cookies=cookies)
    assert list_res.status_code == 200
    rules = list_res.json()
    assert len(rules) == 1
    assert rules[0]["id"] == rule_id
    assert rules[0]["rule_type"] == "blacklist"
    assert rules[0]["remaining_seconds"] is not None
    assert rules[0]["remaining_seconds"] > 3500

    # 4. Check IP reputation inspection endpoint
    rep_res = client.get("/api/ip-reputation/45.33.32.156", cookies=cookies)
    assert rep_res.status_code == 200
    rep_data = rep_res.json()
    assert rep_data["ip"] == "45.33.32.156"
    assert rep_data["status"] == "block"

    # 5. Delete rule (unban)
    del_res = client.delete(f"/api/ip-rules/{rule_id}", cookies=cookies, headers=headers)
    assert del_res.status_code == 200

    # 6. Verify rule is gone
    final_res = client.get("/api/ip-rules", cookies=cookies)
    assert len(final_res.json()) == 0
