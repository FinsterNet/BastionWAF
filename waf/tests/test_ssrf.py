from bastion.core.normalizer import normalize_request
from bastion.rules.ssrf import SSRFRule


def test_ssrf_localhost_blocked():
    rule = SSRFRule()
    req = normalize_request("GET", "/webhook", query_string="url=http://127.0.0.1:8000/admin")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "934100"


def test_ssrf_cloud_metadata_blocked():
    rule = SSRFRule()
    req = normalize_request("GET", "/webhook", query_string="url=http://169.254.169.254/latest/meta-data/")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "934100"


def test_ssrf_clean_public_url_allowed():
    rule = SSRFRule()
    req = normalize_request("GET", "/webhook", query_string="url=https://api.github.com/events")
    verdict = rule.match(req)
    assert not verdict.blocked
