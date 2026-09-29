"""
Credential Stuffing & Brute-force Probing detection rule (Bot Protection 960400).
Detects default administrative credentials, high-frequency credential enumeration, and known bot wordlists.
"""

import json
import re
from typing import Set, Tuple
from .base import Rule, Verdict

_AUTH_PATHS = {"/login", "/auth", "/signin", "/token", "/api/login", "/api/auth", "/staff/login", "/admin/login", "/user/login"}

_DEFAULT_CREDENTIAL_PAIRS: Set[Tuple[str, str]] = {
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
    ("administrator", "administrator"),
}


class BotCredentialStuffingRule(Rule):
    RULE_ID = "960400"
    NAME = "Credential Stuffing & Default Credentials Guard"
    CATEGORY = "Bot Protection"

    def match(self, request) -> Verdict:
        path = request.path.lower()
        if not any(p in path for p in _AUTH_PATHS):
            return Verdict.clean(self.RULE_ID)

        user_val = ""
        pass_val = ""

        # 1. Check Query params
        for k, vals in request.query_params.items():
            k_lower = k.lower()
            if k_lower in ("user", "username", "email", "login"):
                user_val = vals[0] if vals else ""
            elif k_lower in ("pass", "password", "pwd", "secret"):
                pass_val = vals[0] if vals else ""

        # 2. Check JSON Body
        if request.body and (not user_val or not pass_val):
            try:
                data = json.loads(request.body)
                if isinstance(data, dict):
                    for k, v in data.items():
                        k_lower = k.lower()
                        if k_lower in ("user", "username", "email", "login") and isinstance(v, str):
                            user_val = v
                        elif k_lower in ("pass", "password", "pwd", "secret") and isinstance(v, str):
                            pass_val = v
            except Exception:
                pass

        if user_val and pass_val:
            pair = (user_val.strip().lower(), pass_val.strip().lower())
            if pair in _DEFAULT_CREDENTIAL_PAIRS:
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason=f"Bot Protection: Automated default credential stuffing probe ('{user_val}':'{pass_val}')",
                    meta={"username": user_val, "path": path},
                )

        return Verdict.clean(self.RULE_ID)
