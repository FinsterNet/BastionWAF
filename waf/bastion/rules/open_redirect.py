"""
Open Redirect & Host Header Injection detection rule (OWASP CRS 935100).
Detects protocol-relative and external domain redirect patterns in redirect parameters.
"""

import re
from typing import List, Tuple
from urllib.parse import urlparse
from .base import Rule, Verdict

_REDIRECT_PARAMS = {"url", "redirect", "next", "return", "target", "dest", "destination", "goto", "out", "view", "link"}


class OpenRedirectRule(Rule):
    RULE_ID = "935100"
    NAME = "Open Redirect & Host Header Injection Guard"
    CATEGORY = "OWASP Top 10"

    def match(self, request) -> Verdict:
        # Check query parameters commonly used for redirects
        for param, values in request.query_params.items():
            param_lower = param.lower()
            if param_lower in _REDIRECT_PARAMS:
                for val in values:
                    val_clean = val.strip()
                    # 1. Protocol-relative URL bypass: //evil.com or \\\\evil.com
                    if val_clean.startswith("//") or val_clean.startswith("\\\\"):
                        return Verdict(
                            blocked=True,
                            rule_id=self.RULE_ID,
                            reason=f"Open Redirect: Protocol-relative URL destination ({val_clean[:50]})",
                            meta={"param": param, "target": val_clean[:100]},
                        )

                    # 2. Javascript / data pseudo-scheme in redirect parameter
                    if val_clean.lower().startswith("javascript:") or val_clean.lower().startswith("data:"):
                        return Verdict(
                            blocked=True,
                            rule_id=self.RULE_ID,
                            reason=f"Open Redirect: Dangerous script pseudo-protocol in redirect target",
                            meta={"param": param, "target": val_clean[:100]},
                        )

                    # 3. Absolute URL with foreign scheme or user-info credential trick: https://legit@evil.com
                    if "@" in val_clean and "://" in val_clean:
                        return Verdict(
                            blocked=True,
                            rule_id=self.RULE_ID,
                            reason="Open Redirect: User-info credential domain confusion (@)",
                            meta={"param": param, "target": val_clean[:100]},
                        )

        return Verdict.clean(self.RULE_ID)
