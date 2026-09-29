"""
Insecure Deserialization detection rule (OWASP CRS 933300).
Detects Java serialized object streams, PHP object injection strings, and Python pickle bytecode.
"""

import base64
import re
from typing import Any, Dict, List, Tuple
from .base import Rule, Verdict

_DESERIALIZATION_PATTERNS: List[Tuple[str, str]] = [
    # Java Serialization magic bytes \xac\xed\x00\x05 (Base64: rO0AB)
    (r"(?:rO0AB[a-zA-Z0-9+/=]{10,}|\\xac\\xed\\x00\\x05)", "Java serialized object stream injection (rO0AB / aced0005)"),
    # PHP serialize format: O:4:"User":2:... or a:2:{...}
    (r"\b[Oa]:\d+:\"[a-zA-Z0-9_\\\\]+\":\d+:", "PHP object injection / serialized data string"),
    # Python pickle bytecode markers: cos\nsystem or c__builtin__\n
    (r"(?:c__builtin__|posix\nsystem|nt\nsystem|builtins\neval|__reduce__|cposix\nsystem)", "Python pickle deserialization opcode injection"),
    # .NET BinaryFormatter / TypeNameHandling payload
    (r"\$type\s*:\s*[\"'][^\"']*System\.(?:Windows\.Data|IO\.FileInfo|Diagnostics\.Process)", ".NET TypeNameHandling JSON deserialization exploit"),
]

_COMPILED_DESER = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _DESERIALIZATION_PATTERNS]


class DeserializationRule(Rule):
    RULE_ID = "933300"
    NAME = "Insecure Deserialization Shield"
    CATEGORY = "OWASP Top 10"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_DESER:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=f"Semantic Deserialization: {reason}",
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
