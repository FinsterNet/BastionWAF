"""
Server-Side Template Injection (SSTI) detection rule (OWASP CRS 933100).
Detects template expressions, sandbox breakout attributes, and execution probes.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_SSTI_PATTERNS: List[Tuple[str, str]] = [
    (r"\{\{[\s\S]*?(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|lipsum|cycler|config)[\s\S]*?\}\}", "Jinja2/Python template sandbox escape probe"),
    (r"\$\{[^}]*?(?:Runtime|ProcessBuilder|class\.module\.classLoader|T\()", "Java Spring/Thymeleaf/FreeMarker SSTI execution payload"),
    (r"\{\{\s*\d+\s*[\*+-/]\s*\d+\s*\}\}", "Template expression arithmetic probe ({{...}})"),
    (r"\$\{\s*\d+\s*[\*+-/]\s*\d+\s*\}", "Template expression arithmetic probe (${...})"),
    (r"<%\s*=\s*[\s\S]*?%>", "ERB / JSP scriptlet template expression"),
    (r"#\{\s*[\s\S]*?\}", "OGNL / Ruby template interpolation expression"),
]

_COMPILED_SSTI = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _SSTI_PATTERNS]


class SSTIRule(Rule):
    RULE_ID = "933100"
    NAME = "Server-Side Template Injection (SSTI) Guard"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_SSTI:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=f"Semantic AST: {reason}",
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
