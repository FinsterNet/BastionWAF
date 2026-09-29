"""
Secret Key & Token URI Leakage detection rule (OWASP API Security 950300).
Detects sensitive credentials, private API keys, and access tokens leaked in URL query strings.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_SENSITIVE_KEY_PARAMS = {
    "api_key", "apikey", "secret", "client_secret", "private_key", "access_token",
    "auth_token", "bearer_token", "private_token", "secret_key", "app_secret",
}

_HIGH_ENTROPY_HEX_OR_B64 = re.compile(r"^[a-zA-Z0-9_\-\.]{24,}$")


class APIKeyLeakRule(Rule):
    RULE_ID = "950300"
    NAME = "Secret Key & Token URI Leakage Guard"
    CATEGORY = "API Security"

    def match(self, request) -> Verdict:
        # Check query parameters for high-entropy secret tokens
        for param, vals in request.query_params.items():
            param_lower = param.lower()
            if param_lower in _SENSITIVE_KEY_PARAMS:
                for v in vals:
                    if _HIGH_ENTROPY_HEX_OR_B64.search(v.strip()):
                        return Verdict(
                            blocked=True,
                            rule_id=self.RULE_ID,
                            reason=f"API Security: Sensitive authentication token exposed in GET query URI ('{param}')",
                            meta={"parameter": param, "token_sample": f"{v[:6]}...{v[-4:]}"},
                        )

        return Verdict.clean(self.RULE_ID)
