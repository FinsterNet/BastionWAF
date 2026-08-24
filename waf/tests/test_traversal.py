from bastion.core.normalizer import normalize_request
from bastion.rules.traversal import TraversalRule


def test_traversal_dot_dot_slash_blocked():
    rule = TraversalRule()
    req = normalize_request("GET", "/file", query_string="name=../../../../etc/passwd")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "930120"


def test_traversal_proc_self_blocked():
    rule = TraversalRule()
    req = normalize_request("GET", "/file", query_string="name=/proc/self/environ")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "930120"


def test_traversal_windows_win_ini_blocked():
    rule = TraversalRule()
    req = normalize_request("GET", "/file", query_string="name=c:\\windows\\win.ini")
    verdict = rule.match(req)
    assert verdict.blocked
    assert verdict.rule_id == "930120"


def test_traversal_clean_path_allowed():
    rule = TraversalRule()
    req = normalize_request("GET", "/file", query_string="name=statement_aug.txt")
    verdict = rule.match(req)
    assert not verdict.blocked
