"""
Unit Tests for Score Combination Layer and Decision Thresholds (Layer 4 Spec).
"""

from bastion.core.scorer import ActionDecision, ScoreCombinationEngine
from bastion.core.engine import Engine
from bastion.core.inspector import inspect_request


def test_score_combination_formula():
    # total_score = (w1 * rule_score) + (w2 * semantic_score)
    res = ScoreCombinationEngine.combine(
        rule_score=5.0,
        semantic_score=4.0,
        matched_rules=["942100"],
        primary_rule_id="942100",
        primary_reason="SQL Injection",
        semantic_category="SQLi",
        matched_archetype="1' OR '1'='1' --",
        w1=1.0,
        w2=0.8,
        block_threshold=5.0,
        challenge_threshold=2.5,
    )
    # total = 1.0 * 5.0 + 0.8 * 4.0 = 8.2
    assert res.total_score == 8.2
    assert res.action == ActionDecision.BLOCK


def test_challenge_threshold_trigger():
    # Mild anomaly: rule_score = 0.0, semantic_score = 3.5 -> total = 0.8 * 3.5 = 2.8
    res = ScoreCombinationEngine.combine(
        rule_score=0.0,
        semantic_score=3.5,
        matched_rules=[],
        primary_rule_id="",
        primary_reason="",
        semantic_category="Suspicious",
        matched_archetype="...",
        w1=1.0,
        w2=0.8,
        block_threshold=5.0,
        challenge_threshold=2.5,
    )
    assert res.total_score == 2.8
    assert res.action == ActionDecision.CHALLENGE


def test_clean_allow_threshold():
    res = ScoreCombinationEngine.combine(
        rule_score=0.0,
        semantic_score=0.5,
        matched_rules=[],
        primary_rule_id="",
        primary_reason="",
        semantic_category="Clean",
        matched_archetype="",
        w1=1.0,
        w2=0.8,
        block_threshold=5.0,
        challenge_threshold=2.5,
    )
    assert res.total_score == 0.4
    assert res.action == ActionDecision.ALLOW


def test_shadow_mode_logging():
    # In shadow mode, semantic score does NOT elevate action to block
    res = ScoreCombinationEngine.combine(
        rule_score=0.0,
        semantic_score=8.0,
        matched_rules=[],
        primary_rule_id="",
        primary_reason="",
        semantic_category="SQLi",
        matched_archetype="",
        w1=1.0,
        w2=0.8,
        block_threshold=5.0,
        challenge_threshold=2.5,
        shadow_mode=True,
    )
    # Effective score is 0.0 (ALLOW), but audit total retains full score
    assert res.action == ActionDecision.ALLOW
    assert res.total_score == 6.4
    assert res.shadow_mode is True


def test_engine_end_to_end_scoring():
    engine = Engine()
    inspection = inspect_request(
        method="GET",
        path="/search",
        query_string="q=admin' OR '1'='1 --",
        headers={},
        body=b"",
        client_ip="10.0.0.1",
    )
    scored = engine.evaluate_scored(inspection.request)
    assert scored.action == ActionDecision.BLOCK
    assert scored.rule_score >= 5.0
    assert scored.total_score >= 5.0
    assert scored.primary_rule_id == "942100"
