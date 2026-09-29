"""
Automated Unit and Integration Tests for Interactive Slider CAPTCHA Challenge Engine.
"""

import time
from fastapi.testclient import TestClient
from bastion.challenge.captcha import (
    CLEARANCE_COOKIE_NAME,
    generate_challenge_token,
    generate_clearance_cookie,
    verify_challenge_solution,
    verify_clearance_cookie,
)
from bastion.challenge.evaluator import RiskDecision, RiskEvaluator
from bastion.core.proxy import app as proxy_app
from database.db import init_db


def test_challenge_token_generation_and_verification():
    token, target_x = generate_challenge_token()
    assert token is not None
    assert target_x >= 80

    # 1. Valid human solve with correct position and human duration
    valid, msg = verify_challenge_solution(
        token=token,
        user_x=target_x + 2,  # within +/- 9px tolerance
        duration_ms=450,
        trajectory_count=6,
    )
    assert valid, f"Verification failed: {msg}"

    # 2. Position offset too large
    invalid_pos, msg = verify_challenge_solution(
        token=token,
        user_x=target_x + 25,  # outside tolerance
        duration_ms=450,
        trajectory_count=6,
    )
    assert not invalid_pos
    assert "did not align" in msg

    # 3. Robotic super-fast duration (< 150ms)
    robotic_speed, msg = verify_challenge_solution(
        token=token,
        user_x=target_x,
        duration_ms=30,  # automated script instant slide
        trajectory_count=5,
    )
    assert not robotic_speed
    assert "robotic" in msg.lower()

    # 4. Discontinuous jump (trajectory count < 2)
    teleport_jump, msg = verify_challenge_solution(
        token=token,
        user_x=target_x,
        duration_ms=500,
        trajectory_count=1,
    )
    assert not teleport_jump
    assert "discontinuous" in msg.lower()


def test_clearance_cookie_validation_and_expiry():
    client_ip = "192.0.2.45"
    cookie = generate_clearance_cookie(client_ip, ttl_seconds=60)
    assert cookie is not None

    # Valid check
    assert verify_clearance_cookie(cookie, client_ip) is True

    # Mismatched IP check
    assert verify_clearance_cookie(cookie, "198.51.100.99") is False

    # Expired cookie check
    expired_cookie = generate_clearance_cookie(client_ip, ttl_seconds=-10)
    assert verify_clearance_cookie(expired_cookie, client_ip) is False


def test_proxy_captcha_verification_endpoint():
    init_db()
    client = TestClient(proxy_app)

    token, target_x = generate_challenge_token()

    # Valid solve POST
    res = client.post(
        "/__bastion_captcha_verify__",
        json={
            "token": token,
            "user_x": float(target_x),
            "duration_ms": 400.0,
            "trajectory_count": 5,
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "ok"
    assert CLEARANCE_COOKIE_NAME in res.cookies

    # Invalid solve POST
    res_bad = client.post(
        "/__bastion_captcha_verify__",
        json={
            "token": token,
            "user_x": float(target_x + 50),
            "duration_ms": 400.0,
            "trajectory_count": 5,
        },
    )
    assert res_bad.status_code == 400
    assert res_bad.json()["status"] == "error"


def test_risk_evaluator_3_tier_decisions():
    # Tier 1: Hard Exploit -> BLOCK (No CAPTCHA)
    decision, _ = RiskEvaluator.evaluate(
        verdict_blocked=True,
        rule_id="942100",  # SQLi
        reason="SQL Injection",
        client_ip="127.0.0.1",
        path="/search",
        headers={"user-agent": "Mozilla/5.0"},
        cookies={},
    )
    assert decision == RiskDecision.BLOCK

    # Tier 2: Bot / Rate limit anomaly without clearance -> CHALLENGE
    decision_bot, _ = RiskEvaluator.evaluate(
        verdict_blocked=True,
        rule_id="960100",  # Scanner
        reason="Scanner signature",
        client_ip="127.0.0.1",
        path="/api/data",
        headers={"user-agent": "scanner/1.0"},
        cookies={},
    )
    assert decision_bot == RiskDecision.CHALLENGE

    # Tier 3: Clean request -> ALLOW
    decision_clean, _ = RiskEvaluator.evaluate(
        verdict_blocked=False,
        rule_id="",
        reason="Clean",
        client_ip="127.0.0.1",
        path="/products",
        headers={"user-agent": "Mozilla/5.0"},
        cookies={},
    )
    assert decision_clean == RiskDecision.ALLOW
