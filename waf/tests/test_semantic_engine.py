"""
Unit tests for the SafeLine-inspired Semantic Analysis Parsers.
"""

from bastion.semantic.sql_parser import SQLSemanticParser
from bastion.semantic.html_js_parser import HTMLJSSemanticParser
from bastion.semantic.shell_parser import ShellSemanticParser
from bastion.semantic.path_analyzer import PathSemanticAnalyzer
from bastion.semantic.url_ip_analyzer import URLIPSuggestedAnalyzer


def test_sql_semantic_tautology_and_stacked():
    # Tautology attacks
    threat, reason, _ = SQLSemanticParser.analyze("' OR '1'='1")
    assert threat
    assert "tautology" in reason.lower()

    threat, reason, _ = SQLSemanticParser.analyze("1' OR 1=1--")
    assert threat

    threat, reason, _ = SQLSemanticParser.analyze("1 OR TRUE")
    assert threat

    # Stacked queries
    threat, reason, _ = SQLSemanticParser.analyze("user_id=1; DROP TABLE users;")
    assert threat
    assert "stacked" in reason.lower()

    # Time-based functions
    threat, reason, _ = SQLSemanticParser.analyze("1' AND SLEEP(5)--")
    assert threat
    assert "dangerous sql function" in reason.lower()

    # Legitimate non-attack
    threat, _, _ = SQLSemanticParser.analyze("Select a plan and sleep 8 hours every night")
    assert not threat


def test_html_js_semantic_context():
    # Real HTML/JS vectors
    threat, _, _ = HTMLJSSemanticParser.analyze("<script>alert(1)</script>")
    assert threat

    threat, _, _ = HTMLJSSemanticParser.analyze("<img src=x onerror=alert(document.cookie)>")
    assert threat

    threat, _, _ = HTMLJSSemanticParser.analyze("javascript:eval('alert(1)')")
    assert threat

    # Harmless plain text with math or dialogue words
    threat, _, _ = HTMLJSSemanticParser.analyze("Is 5 < 10 and 20 > 5?")
    assert not threat

    threat, _, _ = HTMLJSSemanticParser.analyze("Please alert the manager to confirm the booking")
    assert not threat


def test_shell_semantic_chaining_and_subshells():
    # Real command injections
    threat, _, _ = ShellSemanticParser.analyze("test.txt; whoami")
    assert threat

    threat, _, _ = ShellSemanticParser.analyze("127.0.0.1 | cat /etc/passwd")
    assert threat

    threat, _, _ = ShellSemanticParser.analyze("filename=$(whoami)")
    assert threat

    threat, _, _ = ShellSemanticParser.analyze("echo `id`")
    assert threat

    # Harmless text
    threat, _, _ = ShellSemanticParser.analyze("tutorial on whoami command")
    assert not threat

    threat, _, _ = ShellSemanticParser.analyze("cute cat videos")
    assert not threat


def test_path_semantic_breakout():
    # Real traversal
    threat, _, _ = PathSemanticAnalyzer.analyze("../../etc/passwd")
    assert threat

    threat, _, _ = PathSemanticAnalyzer.analyze("/proc/self/environ")
    assert threat

    threat, _, _ = PathSemanticAnalyzer.analyze("c:\\windows\\win.ini")
    assert threat

    # Harmless filename
    threat, _, _ = PathSemanticAnalyzer.analyze("statement_august_2026.pdf")
    assert not threat


def test_url_ip_semantic_obfuscation():
    # Obfuscated decimal IP for 127.0.0.1
    threat, _, _ = URLIPSuggestedAnalyzer.analyze("http://2130706433/admin")
    assert threat

    # Hex IP for 127.0.0.1
    threat, _, _ = URLIPSuggestedAnalyzer.analyze("http://0x7f000001/api")
    assert threat

    # Octal IP for 127.0.0.1
    threat, _, _ = URLIPSuggestedAnalyzer.analyze("http://0177.0.0.1/")
    assert threat

    # Cloud metadata
    threat, _, _ = URLIPSuggestedAnalyzer.analyze("http://169.254.169.254/latest/meta-data/")
    assert threat

    # Dangerous pseudo-protocol
    threat, _, _ = URLIPSuggestedAnalyzer.analyze("gopher://127.0.0.1:6379/_flushall")
    assert threat

    # Legitimate URL
    threat, _, _ = URLIPSuggestedAnalyzer.analyze("https://api.github.com/v3")
    assert not threat
