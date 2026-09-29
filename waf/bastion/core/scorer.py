"""
Score Combination & Decision Layer (Layer 4 Specification).
Combines Rule-Based Anomaly Score with Embedding-Based Semantic Cosine Score:
    total_score = (w1 * score_rules) + (w2 * score_semantic)
Applies 3-Tier Threshold Policy (BLOCK, CHALLENGE, ALLOW) and Shadow Mode evaluation.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
import os
from typing import Any, Dict, List, Optional, Tuple


class ActionDecision(Enum):
    BLOCK = "BLOCK"            # 403 Hard Block
    CHALLENGE = "CHALLENGE"    # Interactive Slider CAPTCHA
    ALLOW = "ALLOW"            # 200 Forward


@dataclass
class CombinedEvaluation:
    action: ActionDecision
    rule_score: float
    semantic_score: float
    total_score: float
    matched_rules: List[str] = field(default_factory=list)
    primary_rule_id: str = ""
    primary_reason: str = ""
    semantic_category: str = "Clean"
    matched_archetype: str = ""
    raw_sample: str = ""
    normalized_sample: str = ""
    shadow_mode: bool = False


class ScoreCombinationEngine:
    """
    Weighted combination and decision evaluator.
    """

    # Configurable weights and thresholds (tunable per environment)
    DEFAULT_W1 = float(os.environ.get("BASTION_W1_RULE_WEIGHT", "1.0"))
    DEFAULT_W2 = float(os.environ.get("BASTION_W2_SEMANTIC_WEIGHT", "0.8"))
    DEFAULT_BLOCK_THRESHOLD = float(os.environ.get("BASTION_BLOCK_THRESHOLD", "5.0"))
    DEFAULT_CHALLENGE_THRESHOLD = float(os.environ.get("BASTION_CHALLENGE_THRESHOLD", "2.5"))
    DEFAULT_SHADOW_MODE = os.environ.get("BASTION_SEMANTIC_SHADOW_MODE", "false").lower() == "true"

    @classmethod
    def combine(
        cls,
        rule_score: float,
        semantic_score: float,
        matched_rules: List[str],
        primary_rule_id: str,
        primary_reason: str,
        semantic_category: str,
        matched_archetype: str,
        raw_sample: str = "",
        normalized_sample: str = "",
        w1: Optional[float] = None,
        w2: Optional[float] = None,
        block_threshold: Optional[float] = None,
        challenge_threshold: Optional[float] = None,
        shadow_mode: Optional[bool] = None,
    ) -> CombinedEvaluation:
        w1 = w1 if w1 is not None else cls.DEFAULT_W1
        w2 = w2 if w2 is not None else cls.DEFAULT_W2
        block_thresh = block_threshold if block_threshold is not None else cls.DEFAULT_BLOCK_THRESHOLD
        challenge_thresh = challenge_threshold if challenge_threshold is not None else cls.DEFAULT_CHALLENGE_THRESHOLD
        is_shadow = shadow_mode if shadow_mode is not None else cls.DEFAULT_SHADOW_MODE

        # Calculate Total Combined Anomaly Score
        # If in shadow mode, semantic score is logged for observation, but total active score only uses rule_score
        effective_semantic_score = 0.0 if is_shadow else semantic_score
        total_score = round((w1 * rule_score) + (w2 * effective_semantic_score), 2)
        combined_score_for_audit = round((w1 * rule_score) + (w2 * semantic_score), 2)

        # 3-Tier Policy Evaluation
        if total_score >= block_thresh:
            action = ActionDecision.BLOCK
        elif total_score >= challenge_thresh:
            action = ActionDecision.CHALLENGE
        else:
            action = ActionDecision.ALLOW

        # Select primary reason
        reason = primary_reason
        if not reason and semantic_score >= 3.0:
            reason = f"Semantic anomaly detected (Cosine match with {semantic_category} archetype: {matched_archetype[:40]}...)"
        elif not reason:
            reason = "Clean request"

        return CombinedEvaluation(
            action=action,
            rule_score=round(rule_score, 2),
            semantic_score=round(semantic_score, 2),
            total_score=combined_score_for_audit,
            matched_rules=matched_rules,
            primary_rule_id=primary_rule_id or ("SEMANTIC_MATCH" if semantic_score >= challenge_thresh else ""),
            primary_reason=reason,
            semantic_category=semantic_category,
            matched_archetype=matched_archetype,
            raw_sample=raw_sample[:500],
            normalized_sample=normalized_sample[:500],
            shadow_mode=is_shadow,
        )
