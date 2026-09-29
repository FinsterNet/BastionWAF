"""
HTTP Verb & Method Tampering detection rule (OWASP API Security 950400).
Detects dangerous HTTP methods (TRACE, TRACK, DEBUG, CONNECT) and HTTP method override header abuse.
"""

from typing import Set
from .base import Rule, Verdict

_DISALLOWED_METHODS: Set[str] = {"TRACE", "TRACK", "DEBUG", "CONNECT"}
_VALID_METHODS: Set[str] = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_OVERRIDE_HEADERS: Set[str] = {"x-http-method-override", "x-http-method", "x-method-override"}


class APIVerbTamperingRule(Rule):
    RULE_ID = "950400"
    NAME = "HTTP Verb & Method Tampering Shield"
    CATEGORY = "API Security"

    def match(self, request) -> Verdict:
        # 1. Direct HTTP method check
        method = (request.method or "").upper()
        if method in _DISALLOWED_METHODS:
            return Verdict(
                blocked=True,
                rule_id=self.RULE_ID,
                reason=f"API Security: Dangerous HTTP diagnostic method invoked ({method})",
                meta={"method": method},
            )

        if method not in _VALID_METHODS:
            return Verdict(
                blocked=True,
                rule_id=self.RULE_ID,
                reason=f"API Security: Non-standard/tampered HTTP verb ({method})",
                meta={"method": method},
            )

        # 2. Method override headers check
        headers = request.headers or {}
        for header_name in _OVERRIDE_HEADERS:
            if header_name in headers:
                override_val = headers[header_name].strip().upper()
                if override_val in _DISALLOWED_METHODS:
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=f"API Security: Disallowed method override ({header_name}: {override_val})",
                        meta={"header": header_name, "override_method": override_val},
                    )

        return Verdict.clean(self.RULE_ID)
