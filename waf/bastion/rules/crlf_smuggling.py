"""
CRLF Injection and HTTP Request Smuggling detection rule (OWASP CRS 921100).
Detects header injection CRLF sequences (%0d%0a, \\r\\n) and conflicting Transfer-Encoding / Content-Length headers.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_CRLF_PATTERNS: List[Tuple[str, str]] = [
    # CRLF followed by arbitrary HTTP response header injection
    (r"(?:%0d%0a|\\r\\n|\r\n)\s*(?:Set-Cookie|Location|Content-Type|X-XSS-Protection|Access-Control-Allow-Origin)\s*:", "CRLF HTTP response header injection"),
    # CRLF followed by injected HTTP status line (HTTP/1.1 200 OK)
    (r"(?:%0d%0a|\\r\\n|\r\n)\s*HTTP/[12]\.[01]\s+\d{3}", "CRLF HTTP response splitting / fake status line injection"),
]

_COMPILED_CRLF = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _CRLF_PATTERNS]


class CRLFSmugglingRule(Rule):
    RULE_ID = "921100"
    NAME = "CRLF Injection & Request Smuggling Shield"
    CATEGORY = "OWASP Top 10"

    def match(self, request) -> Verdict:
        # 1. Check for conflicting request smuggling headers
        headers = request.headers or {}
        if "transfer-encoding" in headers and "content-length" in headers:
            return Verdict(
                blocked=True,
                rule_id=self.RULE_ID,
                reason="HTTP Request Smuggling: Conflicting Transfer-Encoding and Content-Length headers (TE.CL / CL.TE)",
                meta={"headers": ["transfer-encoding", "content-length"]},
            )

        # 2. Check for Transfer-Encoding obfuscation
        te = headers.get("transfer-encoding", "").lower()
        if te and te != "chunked" and ("chunked" in te or "\x00" in te or "\r" in te or "\n" in te):
            return Verdict(
                blocked=True,
                rule_id=self.RULE_ID,
                reason="HTTP Request Smuggling: Obfuscated Transfer-Encoding header",
                meta={"transfer_encoding": te},
            )

        # 3. Check for CRLF header injection in parameter values and headers
        candidates = list(request.iter_values())
        if hasattr(request, "iter_raw_values"):
            candidates.extend(request.iter_raw_values())

        for field_label, value in candidates:
            if not value:
                continue
            for pattern, reason in _COMPILED_CRLF:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=f"Semantic CRLF: {reason}",
                        meta={"field": field_label, "matched_value": value[:200]},
                    )

        return Verdict.clean(self.RULE_ID)
