"""
Remote Code Execution (RCE) / Command Injection detection rule (OWASP CRS 932100).
Powered by Shell Grammar & Command Chaining Semantic Analyzer.
"""

from ..semantic.shell_parser import ShellSemanticParser
from .base import Rule, Verdict


class CommandInjectionRule(Rule):
    RULE_ID = "932100"
    NAME = "Remote Code Execution (RCE) Engine"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            is_threat, reason, meta = ShellSemanticParser.analyze(value)
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
