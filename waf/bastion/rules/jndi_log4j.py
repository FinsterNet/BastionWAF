"""
JNDI / Log4Shell Remote Class Loading detection rule (OWASP CRS 933500).
Mitigates CVE-2021-44228, Spring4Shell, and JNDI lookup injections across headers and payloads.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_JNDI_PATTERNS: List[Tuple[str, str]] = [
    # Direct JNDI lookup string
    (r"\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|corba|iiop|nis)\s*://", "Standard JNDI lookup injection (${jndi:...})"),
    # Obfuscated / nested expressions: ${${lower:j}ndi:...}, ${${env:BARFOO:-j}ndi:...}
    (r"\$\{\s*\$\{[^}]+(?::-[^}]+)?\}\s*(?:ndi|ndi:)", "Nested/obfuscated JNDI lookup expression"),
    # Spring4Shell ClassLoader accessor probe
    (r"(?:class\.module\.classLoader|classLoader\.resources\.context|pipeline\.first\.directory)", "Spring4Shell ClassLoader resource access exploit"),
    # Generic nested JNDI lookup probe
    (r"\$\{\s*(?:lower|upper|env|sys|base64|date):[\s\S]*?jndi", "Multi-pass Log4j lookup evasive wrapper"),
]

_COMPILED_JNDI = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _JNDI_PATTERNS]


class JNDILog4jRule(Rule):
    RULE_ID = "933500"
    NAME = "JNDI / Log4j Lookup Shield"
    CATEGORY = "OWASP Top 10"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_JNDI:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=f"Semantic JNDI: {reason}",
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
