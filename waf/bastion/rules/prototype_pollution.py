"""
JavaScript Prototype Pollution detection rule (OWASP CRS 933600).
Mitigates __proto__, constructor.prototype, and prototype override injections in JSON and parameters.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_POLLUTION_PATTERNS: List[Tuple[str, str]] = [
    # Direct __proto__ property injection
    (r"(?:\"|'|\[)?__proto__(?:\"|'|\])?\s*(?::|=|\.)", "JavaScript __proto__ prototype pollution vector"),
    # constructor.prototype manipulation
    (r"(?:constructor\s*\.\s*prototype|\[[\"']constructor[\"']\]\s*\[[\"']prototype[\"']\])", "JavaScript constructor.prototype pollution vector"),
    # Array/query param parameter pollution syntax (e.g. data[__proto__][isAdmin]=true)
    (r"(?:\[__proto__\]|\[constructor\]\[prototype\]|__proto__\[)", "Bracket-notated query/body prototype pollution parameter"),
    # __defineGetter__ / __defineSetter__ injection
    (r"\b(?:__defineGetter__|__defineSetter__|__lookupGetter__|__lookupSetter__)\b", "Dangerous JavaScript Object accessor method pollution"),
]

_COMPILED_POLLUTION = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _POLLUTION_PATTERNS]


class PrototypePollutionRule(Rule):
    RULE_ID = "933600"
    NAME = "JavaScript Prototype Pollution Filter"
    CATEGORY = "OWASP Top 10"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_POLLUTION:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=f"Semantic Prototype: {reason}",
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
