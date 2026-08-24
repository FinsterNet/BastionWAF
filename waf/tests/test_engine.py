from bastion.core.engine import Engine, discover_rules
from bastion.core.normalizer import normalize_request


def test_discover_rules_finds_all_rules():
    rules = discover_rules()
    rule_ids = {r.RULE_ID for r in rules}
    assert "942100" in rule_ids  # SQLi
    assert "941100" in rule_ids  # XSS
    assert "930120" in rule_ids  # Traversal
    assert "932100" in rule_ids  # RCE
    assert "934100" in rule_ids  # SSRF


def test_engine_evaluates_and_blocks_threats():
    engine = Engine()
    req = normalize_request("GET", "/search", query_string="q=' OR 1=1--")
    verdict = engine.evaluate(req)
    assert verdict.blocked
    assert verdict.rule_id == "942100"


def test_engine_dynamic_enabled_rules_filtering():
    engine = Engine()
    req = normalize_request("GET", "/search", query_string="q=' OR 1=1--")
    # If rule 942100 is not enabled, evaluate returns clean
    verdict = engine.evaluate(req, enabled_rule_ids={"941100", "930120"})
    assert not verdict.blocked
