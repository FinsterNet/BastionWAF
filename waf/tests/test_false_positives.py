"""
False Positive Verification Tests.
Verifies that legitimate user queries, sentences, and math comparisons
are NOT blocked by the SafeLine-inspired Semantic Analysis Engine.
"""

from bastion.core.engine import Engine
from bastion.core.normalizer import normalize_request


def test_sqli_natural_language_not_blocked():
    engine = Engine()
    queries = [
        "I want to select the premium tier and sleep well tonight",
        "Union Jack T-shirt size M or L",
        "Search products: order by popularity and rating",
        "Can we update our profile or delete old addresses?",
        "Select your preferred language: English or Spanish",
        "Looking for books on SQL and database architecture",
    ]
    for q in queries:
        req = normalize_request("GET", "/search", query_string=f"q={q}")
        verdict = engine.evaluate(req)
        assert not verdict.blocked, f"False positive triggered for query: '{q}' (Rule: {verdict.rule_id}, Reason: {verdict.reason})"


def test_xss_natural_language_and_math_not_blocked():
    engine = Engine()
    inquiries = [
        "Please confirm (yes/no) your appointment for tomorrow",
        "We sent an alert (check your inbox for security code)",
        "Check mathematical expression: 5 < 10 and 20 > 5",
        "Price range < 50 dollars",
        "Customer inquiry regarding on time delivery",
        "Please review the attached document.pdf",
    ]
    for msg in inquiries:
        req = normalize_request("GET", "/comment", query_string=f"msg={msg}")
        verdict = engine.evaluate(req)
        assert not verdict.blocked, f"False positive triggered for inquiry: '{msg}' (Rule: {verdict.rule_id}, Reason: {verdict.reason})"


def test_rce_natural_language_not_blocked():
    engine = Engine()
    commands = [
        "Tutorial on how to use whoami command in Linux",
        "Cute cat pictures and funny memes",
        "Understanding user id vs group id in POSIX",
        "Price list: item A | category B",
    ]
    for cmd in commands:
        req = normalize_request("GET", "/exec", query_string=f"cmd={cmd}")
        verdict = engine.evaluate(req)
        assert not verdict.blocked, f"False positive triggered for command query: '{cmd}' (Rule: {verdict.rule_id}, Reason: {verdict.reason})"


def test_ssrf_legitimate_urls_not_blocked():
    engine = Engine()
    urls = [
        "https://api.github.com/repos",
        "https://finances.example.com/fx-rates",
        "https://cdn.jsdelivr.net/npm/chart.js",
    ]
    for u in urls:
        req = normalize_request("GET", "/webhook", query_string=f"url={u}")
        verdict = engine.evaluate(req)
        assert not verdict.blocked, f"False positive triggered for URL: '{u}' (Rule: {verdict.rule_id}, Reason: {verdict.reason})"
