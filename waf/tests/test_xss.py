from bastion.core.normalizer import normalize_request
from bastion.rules.xss import XSSRule


def test_xss_script_tag_blocked():
    rule = XSSRule()
    req = normalize_request("GET", "/comment", query_string="msg=<script>alert('XSS')</script>")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "941100"


def test_xss_onerror_img_blocked():
    rule = XSSRule()
    req = normalize_request("GET", "/comment", query_string="msg=<img src=x onerror=alert(1)>")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "941100"


def test_xss_javascript_uri_blocked():
    rule = XSSRule()
    req = normalize_request("GET", "/redirect", query_string="url=javascript:alert(document.cookie)")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "941100"


def test_xss_clean_request_allowed():
    rule = XSSRule()
    req = normalize_request("GET", "/comment", query_string="msg=Hello, this is a clean inquiry message.")
    verdict = rule.match(req)
    assert not verdict.blocked
