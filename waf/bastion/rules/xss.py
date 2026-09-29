"""
Cross-Site Scripting (XSS) detection rule (OWASP CRS 941100).
Powered by Context-Aware HTML & JavaScript Semantic Parser.
"""

from ..semantic.html_js_parser import HTMLJSSemanticParser
from .base import Rule, Verdict


class XSSRule(Rule):
    RULE_ID = "941100"
    NAME = "Cross-Site Scripting (XSS) Filter"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            is_threat, reason, meta = HTMLJSSemanticParser.analyze(value)
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
