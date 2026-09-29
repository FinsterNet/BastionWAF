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
    assert "933100" in rule_ids  # SSTI
    assert "933200" in rule_ids  # XXE
    assert "933300" in rule_ids  # Deserialization
    assert "933400" in rule_ids  # Webshell
    assert "933500" in rule_ids  # JNDI
    assert "933600" in rule_ids  # Prototype Pollution
    assert "921100" in rule_ids  # CRLF
    assert "935100" in rule_ids  # Open Redirect
    assert "942200" in rule_ids  # LDAP/XPath
    assert "930200" in rule_ids  # Sensitive Files
    assert "950100" in rule_ids  # API Mass Assignment
    assert "950200" in rule_ids  # GraphQL
    assert "950300" in rule_ids  # API Key Leak
    assert "950400" in rule_ids  # API Verb Tampering
    assert "950500" in rule_ids  # Payload Bomb
    assert "950600" in rule_ids  # CORS Abuse
    assert "950700" in rule_ids  # JWT Tampering
    assert "960100" in rule_ids  # Bot Scanner
    assert "960200" in rule_ids  # Bot Headless
    assert "960300" in rule_ids  # Bot Rate Limit
    assert "960400" in rule_ids  # Credential Stuffing
    assert "960500" in rule_ids  # Header Anomaly
    assert "960600" in rule_ids  # Cryptominer
    assert len(rules) >= 28


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
