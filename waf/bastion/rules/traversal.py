"""
Path Traversal and LFI detection rule (OWASP CRS 930120).
Powered by Canonical Path Resolution and OS Target Semantic Analyzer.
"""

from ..semantic.path_analyzer import PathSemanticAnalyzer
from .base import Rule, Verdict


class TraversalRule(Rule):
    RULE_ID = "930120"
    NAME = "Path Traversal / LFI Guard"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            is_threat, reason, meta = PathSemanticAnalyzer.analyze(value)
            if is_threat:
                meta_dict = dict(meta)
                meta_dict["field"] = field_label
                meta_dict["matched_value"] = value[:200]
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason=reason,
                    meta=meta_dict,
                )
        return Verdict.clean(self.RULE_ID)
