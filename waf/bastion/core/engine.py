"""
Detection Engine — Multi-Stage Orchestrator (Rules + Semantic Embeddings + Scorer).
"""

import importlib
import inspect
import json
import logging
import os
import pkgutil
from pathlib import Path
from typing import List, Optional, Set, Tuple

from .. import rules as rules_package
from ..rules.base import Rule, Verdict
from ..semantic.embedding_engine import SemanticEmbeddingEngine
from .scorer import ActionDecision, CombinedEvaluation, ScoreCombinationEngine

logger = logging.getLogger(__name__)


CATEGORY_ORDER = {
    "OWASP Top 10": 1,
    "API Security": 2,
    "Bot Protection": 3,
}

RULE_PRIORITY = {
    "942100": 1,   # SQLi
    "941100": 2,   # XSS
    "933400": 3,   # Webshell
    "933200": 4,   # XXE
    "933100": 5,   # SSTI
    "933500": 6,   # JNDI
    "933300": 7,   # Deserialization
    "933600": 8,   # Prototype Pollution
    "932100": 9,   # RCE
    "934100": 10,  # SSRF
    "930120": 11,  # Traversal
    "921100": 12,  # CRLF
    "935100": 13,  # Open Redirect
    "942200": 14,  # LDAP
    "930200": 15,  # Sensitive Files
    "950100": 20,  # API Mass Assignment
    "950200": 21,  # GraphQL
    "950300": 22,  # API Key Leak
    "950400": 23,  # Verb Tampering
    "950500": 24,  # Payload Bomb
    "950600": 25,  # CORS Abuse
    "950700": 26,  # JWT Tampering
    "960100": 30,  # Bot Scanner
    "960200": 31,  # Bot Headless
    "960300": 32,  # Bot Rate Limit
    "960400": 33,  # Bot Credential Stuffing
    "960600": 34,  # Bot Cryptominer
    "960500": 35,  # Bot Header Anomaly
}


def rule_sort_key(r: Rule) -> Tuple[int, str]:
    return (RULE_PRIORITY.get(r.RULE_ID, CATEGORY_ORDER.get(getattr(r, "CATEGORY", ""), 99) * 10), r.RULE_ID)


def discover_rules() -> List[Rule]:
    """Import every rule class defined in bastion/rules/ sorted by category priority."""
    instances: List[Rule] = []
    for _, module_name, _ in pkgutil.iter_modules(rules_package.__path__):
        if module_name == "base":
            continue
        module = importlib.import_module(f"{rules_package.__name__}.{module_name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, Rule) and obj is not Rule and obj.__module__ == module.__name__:
                instances.append(obj())
    instances.sort(key=rule_sort_key)
    return instances


class Engine:
    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        blocklist_path: Optional[str] = None,
    ):
        raw_rules = rules if rules is not None else discover_rules()
        self.rules: List[Rule] = sorted(raw_rules, key=rule_sort_key)
        if blocklist_path:
            self.blocklist_path = blocklist_path
        else:
            base_dir = Path(__file__).resolve().parent.parent.parent
            self.blocklist_path = str(base_dir / "config" / "blocklist.json")

    def _check_blocklist(self, request) -> Optional[Verdict]:
        """Check if client IP or User-Agent is explicitly blocklisted."""
        if not os.path.exists(self.blocklist_path):
            return None
        try:
            with open(self.blocklist_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            ip_blocklist = data.get("ip_blocklist", [])
            ua_blocklist = data.get("user_agent_blocklist", [])

            if request.client_ip and request.client_ip in ip_blocklist:
                return Verdict(
                    blocked=True,
                    rule_id="BLOCKLIST_IP",
                    reason="Client IP is in blocklist",
                    weight=10.0,
                    meta={"client_ip": request.client_ip},
                )

            user_agent = request.headers.get("user-agent", "")
            if user_agent and any(ua.lower() in user_agent.lower() for ua in ua_blocklist):
                return Verdict(
                    blocked=True,
                    rule_id="BLOCKLIST_UA",
                    reason="User-Agent is in blocklist",
                    weight=10.0,
                    meta={"user_agent": user_agent},
                )
        except Exception as e:
            logger.warning("Failed to check blocklist: %s", e)
        return None

    def evaluate_scored(self, request, enabled_rule_ids: Optional[Set[str]] = None) -> CombinedEvaluation:
        """
        Runs Multi-Stage Evaluation:
        1. Blocklists
        2. Rule-based weighted anomaly scoring (Layer 2)
        3. Semantic embedding cosine similarity (Layer 3)
        4. Combined Score Decision (Layer 4)
        """
        # 1. Blocklist check
        blocklist_verdict = self._check_blocklist(request)
        if blocklist_verdict and blocklist_verdict.blocked:
            return CombinedEvaluation(
                action=ActionDecision.BLOCK,
                rule_score=10.0,
                semantic_score=0.0,
                total_score=10.0,
                matched_rules=[blocklist_verdict.rule_id],
                primary_rule_id=blocklist_verdict.rule_id,
                primary_reason=blocklist_verdict.reason,
            )

        rule_score = 0.0
        matched_rules: List[str] = []
        primary_rule_id = ""
        primary_reason = ""

        # 2. Rule matching with severity aggregation
        for rule in self.rules:
            if enabled_rule_ids is not None and rule.RULE_ID not in enabled_rule_ids:
                continue
            try:
                verdict = rule.match(request)
            except NotImplementedError:
                continue
            if verdict.blocked:
                matched_rules.append(verdict.rule_id)
                rule_score += getattr(rule, "WEIGHT", 5.0)
                if not primary_rule_id:
                    primary_rule_id = verdict.rule_id
                    primary_reason = verdict.reason

        # Extract representative input string for semantic embedding comparison
        all_norm_values = [v for _, v in request.iter_values()]
        all_raw_values = [v for _, v in request.iter_raw_values()] if hasattr(request, "iter_raw_values") else all_norm_values
        combined_text = " ".join(all_norm_values)
        raw_text = " ".join(all_raw_values)

        # 3. Semantic Embedding Cosine Similarity Evaluation
        max_semantic_score = 0.0
        top_cat = "Clean"
        top_archetype = ""

        CATEGORY_TO_RULE = {
            "SQLi": "942100",
            "XSS": "941100",
            "LFI": "930120",
            "RCE": "932100",
            "SSRF": "934100",
            "SSTI": "933100",
            "XXE": "933200",
            "Deserialization": "933300",
            "Webshell": "933400",
            "Log4Shell": "933500",
            "APIAssignment": "950100",
            "GraphQL": "950200",
            "JWT": "950700",
        }

        for val in all_norm_values:
            sem_score, sem_cat, sem_arch = SemanticEmbeddingEngine.evaluate(val)
            rule_for_cat = CATEGORY_TO_RULE.get(sem_cat)
            if enabled_rule_ids is not None and rule_for_cat and rule_for_cat not in enabled_rule_ids:
                continue
            if sem_score > max_semantic_score:
                max_semantic_score = sem_score
                top_cat = sem_cat
                top_archetype = sem_arch

        # 4. Score Combination (total = w1*rule_score + w2*semantic_score)
        return ScoreCombinationEngine.combine(
            rule_score=rule_score,
            semantic_score=max_semantic_score,
            matched_rules=matched_rules,
            primary_rule_id=primary_rule_id,
            primary_reason=primary_reason,
            semantic_category=top_cat,
            matched_archetype=top_archetype,
            raw_sample=raw_text,
            normalized_sample=combined_text,
        )

    def evaluate(self, request, enabled_rule_ids: Optional[Set[str]] = None) -> Verdict:
        """
        Backwards-compatible wrapper returning Verdict.
        """
        scored = self.evaluate_scored(request, enabled_rule_ids)
        is_blocked = (scored.action == ActionDecision.BLOCK)
        return Verdict(
            blocked=is_blocked,
            rule_id=scored.primary_rule_id or "CLEAN",
            reason=scored.primary_reason,
            weight=scored.rule_score,
            meta={
                "action": scored.action.value,
                "rule_score": scored.rule_score,
                "semantic_score": scored.semantic_score,
                "total_score": scored.total_score,
                "semantic_category": scored.semantic_category,
                "matched_archetype": scored.matched_archetype,
                "raw_sample": scored.raw_sample,
                "normalized_sample": scored.normalized_sample,
                "shadow_mode": scored.shadow_mode,
            },
        )
