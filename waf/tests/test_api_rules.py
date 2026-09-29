"""
Unit tests for API Security rules.
Tests Mass Assignment, GraphQL Abuse, API Key Leaks, Verb Tampering, Payload Bombs, CORS Abuse, JWT Tampering.
"""

from bastion.core.normalizer import normalize_request
from bastion.rules.api_mass_assignment import APIMassAssignmentRule
from bastion.rules.api_graphql_abuse import APIGraphQLAbuseRule
from bastion.rules.api_key_leak import APIKeyLeakRule
from bastion.rules.api_verb_tampering import APIVerbTamperingRule
from bastion.rules.api_payload_bomb import APIPayloadBombRule
from bastion.rules.api_cors_abuse import APICORSAbuseRule
from bastion.rules.jwt_tampering import JWTTamperingRule


def test_api_mass_assignment_blocked():
    rule = APIMassAssignmentRule()
    req = normalize_request("POST", "/api/user/update", body=b'{"name": "Alice", "is_admin": true}')
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "950100"


def test_api_graphql_introspection_blocked():
    rule = APIGraphQLAbuseRule()
    req = normalize_request("POST", "/graphql", body=b'{"query": "{ __schema { types { name } } }"}')
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "950200"


def test_api_key_leak_in_uri_blocked():
    rule = APIKeyLeakRule()
    req = normalize_request("GET", "/api/data", query_string="api_key=mock_dummy_entropy_token_1234567890abcdef")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "950300"


def test_api_verb_tampering_trace_blocked():
    rule = APIVerbTamperingRule()
    req = normalize_request("TRACE", "/api/debug")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "950400"


def test_api_payload_bomb_depth_blocked():
    rule = APIPayloadBombRule()
    nested_json = '{"a": ' * 20 + '"bomb"' + '}' * 20
    req = normalize_request("POST", "/api/upload", body=nested_json.encode())
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "950500"


def test_api_cors_null_origin_blocked():
    rule = APICORSAbuseRule()
    req = normalize_request("POST", "/api/transfer", headers={"origin": "null"})
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "950600"


def test_jwt_alg_none_blocked():
    rule = JWTTamperingRule()
    # {"alg": "none", "typ": "JWT"} -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
    # {"user": "admin"} -> eyJ1c2VyIjoiYWRtaW4ifQ
    none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
    req = normalize_request("GET", "/api/admin", headers={"authorization": f"Bearer {none_jwt}"})
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "950700"
