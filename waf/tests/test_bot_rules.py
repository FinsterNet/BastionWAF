"""
Unit tests for Bot Protection & Automated Threat rules.
Tests Scanner Signatures, Headless Browsers, Rate Limiting, Credential Stuffing, Header Anomalies, Cryptominers.
"""

from bastion.core.normalizer import normalize_request
from bastion.rules.bot_scanner import BotScannerRule
from bastion.rules.bot_headless import BotHeadlessRule
from bastion.rules.bot_rate_limit import BotRateLimitRule
from bastion.rules.bot_credential_stuffing import BotCredentialStuffingRule
from bastion.rules.bot_header_anomaly import BotHeaderAnomalyRule
from bastion.rules.bot_cryptominer import BotCryptominerRule


def test_bot_scanner_sqlmap_blocked():
    rule = BotScannerRule()
    req = normalize_request("GET", "/search", headers={"user-agent": "sqlmap/1.6.12#stable"})
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "960100"


def test_bot_headless_puppeteer_blocked():
    rule = BotHeadlessRule()
    req = normalize_request("GET", "/", headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/114.0.5735.199 Safari/537.36"})
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "960200"


def test_bot_rate_limit_flood_blocked():
    rule = BotRateLimitRule()
    # Send 70 requests rapidly from same IP
    blocked = False
    for _ in range(70):
        req = normalize_request("GET", "/api/ping", client_ip="203.0.113.55")
        verdict = rule.match(req)
        if verdict.blocked:
            blocked = True
            assert verdict.rule_id == "960300"
            break
    assert blocked, "Rate limit threshold did not trigger on 70 rapid requests"


def test_bot_credential_stuffing_default_creds_blocked():
    rule = BotCredentialStuffingRule()
    req = normalize_request("POST", "/api/login", body=b'{"username": "admin", "password": "password"}')
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "960400"


def test_bot_missing_user_agent_blocked():
    rule = BotHeaderAnomalyRule()
    req = normalize_request("GET", "/", headers={})
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "960500"


def test_bot_cryptominer_coinhive_blocked():
    rule = BotCryptominerRule()
    req = normalize_request("GET", "/app.js", query_string="miner=coinhive.min.js")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "960600"
