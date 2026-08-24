from bastion.core.normalizer import normalize_request
from bastion.rules.sqli import SQLiRule


def test_union_select_blocked():
    rule = SQLiRule()
    req = normalize_request("GET", "/search", query_string="q=1 UNION SELECT null, username, password FROM users")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "942100"


def test_comment_obfuscated_union_blocked():
    rule = SQLiRule()
    req = normalize_request("GET", "/search", query_string="q=1/**/UNION/**/SELECT/**/1,2,3")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "942100"


def test_classic_tautology_blocked():
    rule = SQLiRule()
    req = normalize_request("GET", "/search", query_string="q=' OR '1'='1")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "942100"


def test_time_based_sleep_blocked():
    rule = SQLiRule()
    req = normalize_request("GET", "/search", query_string="q=1' AND SLEEP(5)--")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "942100"


def test_stacked_query_drop_blocked():
    rule = SQLiRule()
    req = normalize_request("POST", "/update", body=b"data=test; DROP TABLE users;")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "942100"


def test_clean_request_not_blocked():
    rule = SQLiRule()
    req = normalize_request("GET", "/search", query_string="q=laptop computer best price")
    verdict = rule.match(req)
    assert not verdict.blocked
