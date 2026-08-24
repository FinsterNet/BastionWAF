from bastion.core.normalizer import normalize_request
from bastion.rules.command_injection import CommandInjectionRule


def test_rce_chained_whoami_blocked():
    rule = CommandInjectionRule()
    req = normalize_request("GET", "/exec", query_string="cmd=127.0.0.1; whoami")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "932100"


def test_rce_command_substitution_blocked():
    rule = CommandInjectionRule()
    req = normalize_request("GET", "/exec", query_string="cmd=$(cat /etc/passwd)")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "932100"


def test_rce_clean_command_allowed():
    rule = CommandInjectionRule()
    req = normalize_request("GET", "/exec", query_string="cmd=normal_query_string")
    verdict = rule.match(req)
    assert not verdict.blocked
