"""
XML External Entity (XXE) Injection detection rule (OWASP CRS 933200).
Detects DTD entity declarations, external system entity inclusions, and parameter entity attacks.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_XXE_PATTERNS: List[Tuple[str, str]] = [
    (r"<!ENTITY\s+[\w:.-]+\s+SYSTEM\s+['\"][^'\"]*['\"]", "XML external DTD entity SYSTEM declaration"),
    (r"<!ENTITY\s+[\w:.-]+\s+PUBLIC\s+['\"][^'\"]*['\"]", "XML external DTD entity PUBLIC declaration"),
    (r"<!ENTITY\s+%\s+[\w:.-]+\s+SYSTEM\s+['\"][^'\"]*['\"]", "XML parameter entity external inclusion"),
    (r"<!DOCTYPE\s+[\w:.-]+\s+\[[\s\S]*?<!ENTITY", "XML inline DOCTYPE entity definition block"),
    (r"php://filter/(?:read=)?convert\.base64-encode", "PHP stream wrapper XXE exfiltration"),
]

_COMPILED_XXE = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _XXE_PATTERNS]


class XXERule(Rule):
    RULE_ID = "933200"
    NAME = "XML External Entity (XXE) Shield"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_XXE:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=f"Semantic AST: {reason}",
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
