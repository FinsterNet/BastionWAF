"""
Server-Side Request Forgery (SSRF) detection rule (OWASP CRS 934100).
Powered by Multi-format IP Decoder and Protocol Semantic Analyzer.
"""

from ..semantic.url_ip_analyzer import URLIPSuggestedAnalyzer
from .base import Rule, Verdict


class SSRFRule(Rule):
    RULE_ID = "934100"
    NAME = "Server-Side Request Forgery (SSRF) Guard"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            is_threat, reason, meta = URLIPSuggestedAnalyzer.analyze(value)
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
