"""
CORS Misconfiguration & Origin Abuse detection rule (OWASP API Security 950600).
Detects Origin: null exploitation, unauthorized file:// origins, and suspicious cross-origin headers.
"""

from .base import Rule, Verdict


class APICORSAbuseRule(Rule):
    RULE_ID = "950600"
    NAME = "CORS Origin Abuse & Null Origin Guard"
    CATEGORY = "API Security"

    def match(self, request) -> Verdict:
        headers = request.headers or {}
        origin = headers.get("origin", "").strip()

        if not origin:
            return Verdict.clean(self.RULE_ID)

        # 1. Null Origin abuse (often used in sandboxed iframes to bypass CORS)
        if origin.lower() == "null" and request.method in ("POST", "PUT", "DELETE", "PATCH"):
            return Verdict(
                blocked=True,
                rule_id=self.RULE_ID,
                reason="API Security: Dangerous 'Origin: null' header on state-modifying request",
                meta={"origin": origin, "method": request.method},
            )

        # 2. Local file:// or pseudo-scheme origins
        if origin.lower().startswith("file://") or origin.lower().startswith("javascript:"):
            return Verdict(
                blocked=True,
                rule_id=self.RULE_ID,
                reason=f"API Security: Dangerous local protocol Origin header ({origin[:30]})",
                meta={"origin": origin},
            )

        return Verdict.clean(self.RULE_ID)
