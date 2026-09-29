"""
LDAP & XPath Injection detection rule (OWASP CRS 942200).
Detects LDAP filter manipulation and XPath boolean query exploitation patterns.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_LDAP_XPATH_PATTERNS: List[Tuple[str, str]] = [
    # LDAP filter operator manipulation: (&(uid=*)(userPassword=*)) or (|(cn=*))
    (r"\(\s*[&|!]\s*\([a-zA-Z0-9_-]+\s*=\s*\*", "LDAP filter operator tautology injection (&(attr=*))"),
    (r"\)\s*\(\s*(?:&|\||!)\s*\(", "LDAP filter chaining delimiter injection )(&("),
    (r"\bobjectClass\s*=\s*\*", "LDAP objectClass wildcard directory enumeration"),
    # XPath boolean injection: ' or '1'='1' in xpath context or /users/user[
    (r"'\s*or\s+count\s*\(\s*/", "XPath blind count() function injection probe"),
    (r"'\s*or\s+string-length\s*\(", "XPath blind string-length() query probe"),
    (r"\btext\s*\(\s*\)\s*=\s*['\"][^'\"]*['\"]\s+or\s+", "XPath node text comparison injection"),
]

_COMPILED_LDAP = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _LDAP_XPATH_PATTERNS]


class LDAPXPathRule(Rule):
    RULE_ID = "942200"
    NAME = "LDAP & XPath Injection Shield"
    CATEGORY = "OWASP Top 10"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_LDAP:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=f"Semantic LDAP/XPath: {reason}",
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
