"""
SQL injection detection rule (OWASP CRS 942100).
Powered by SafeLine-style Semantic AST & Lexer Tokenization.
"""

from ..semantic.sql_parser import SQLSemanticParser
from .base import Rule, Verdict


class SQLiRule(Rule):
    RULE_ID = "942100"
    NAME = "SQL Injection (SQLi) Shield"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            is_threat, reason, meta = SQLSemanticParser.analyze(value)
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
