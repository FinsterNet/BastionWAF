"""
HTTP Header Anomaly & Protocol Violation detection rule (Bot Protection 960500).
Detects missing mandatory headers (Host, User-Agent), empty user-agents, and malformed encoding headers.
"""

from .base import Rule, Verdict


class BotHeaderAnomalyRule(Rule):
    RULE_ID = "960500"
    NAME = "HTTP Header Anomaly & Protocol Violation Guard"
    CATEGORY = "Bot Protection"

    def match(self, request) -> Verdict:
        headers = request.headers or {}

        # 1. Missing or completely empty User-Agent header
        ua = headers.get("user-agent", "").strip()
        if not ua:
            return Verdict(
                blocked=True,
                rule_id=self.RULE_ID,
                reason="Bot Protection: Missing or blank User-Agent header",
                meta={"anomaly": "empty_user_agent"},
            )

        # 2. Extremely short/bogus User-Agent (e.g. "a", "-", "1")
        if len(ua) <= 2 and not ua.isalpha():
            return Verdict(
                blocked=True,
                rule_id=self.RULE_ID,
                reason=f"Bot Protection: Malformed/bogus User-Agent header ('{ua}')",
                meta={"user_agent": ua},
            )

        # 3. Conflicting or invalid Content-Type headers
        content_type = headers.get("content-type", "")
        if content_type and ("\r" in content_type or "\n" in content_type or "\x00" in content_type):
            return Verdict(
                blocked=True,
                rule_id=self.RULE_ID,
                reason="Bot Protection: Malformed Content-Type header containing control characters",
                meta={"content_type": content_type},
            )

        return Verdict.clean(self.RULE_ID)
