"""
JWT Token Tampering & None Algorithm detection rule (OWASP API Security 950700).
Detects alg:none bypasses, stripped signatures, and key-confusion header attacks in Bearer tokens and cookies.
"""

import base64
import json
import re
from typing import Optional
from .base import Rule, Verdict

_JWT_RE = re.compile(r"\b(ey[a-zA-Z0-9_-]+\.ey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*)\b")


def _decode_b64_segment(segment: str) -> Optional[dict]:
    try:
        padding = "=" * ((4 - len(segment) % 4) % 4)
        raw = base64.urlsafe_b64decode(segment + padding)
        return json.loads(raw)
    except Exception:
        return None


class JWTTamperingRule(Rule):
    RULE_ID = "950700"
    NAME = "JWT None-Algorithm & Signature Tampering Guard"
    CATEGORY = "API Security"

    def match(self, request) -> Verdict:
        # Check Authorization header, cookies, and query params for JWTs
        jwt_candidates = []
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            jwt_candidates.append(auth_header[7:].strip())

        cookie_header = request.headers.get("cookie", "")
        for match in _JWT_RE.finditer(cookie_header):
            jwt_candidates.append(match.group(1))

        for param, vals in request.query_params.items():
            if "token" in param.lower() or "jwt" in param.lower():
                for v in vals:
                    jwt_candidates.append(v)

        for token in jwt_candidates:
            parts = token.split(".")
            if len(parts) >= 2:
                header_obj = _decode_b64_segment(parts[0])
                if header_obj and isinstance(header_obj, dict):
                    alg = str(header_obj.get("alg", "")).lower()

                    # 1. alg: none algorithm bypass
                    if alg in ("none", "none ", "non"):
                        return Verdict(
                            blocked=True,
                            rule_id=self.RULE_ID,
                            reason="API Security: Insecure unsigned JWT token with 'alg: none' algorithm",
                            meta={"token_header": header_obj},
                        )

                    # 2. Key ID (kid) directory traversal in JWT header
                    kid = str(header_obj.get("kid", ""))
                    if ".." in kid or kid.startswith("/"):
                        return Verdict(
                            blocked=True,
                            rule_id=self.RULE_ID,
                            reason=f"API Security: Directory traversal probe in JWT header 'kid' attribute ({kid[:40]})",
                            meta={"kid": kid},
                        )

                    # 3. Stripped signature with non-none algorithm
                    if len(parts) == 3 and not parts[2] and alg != "none":
                        return Verdict(
                            blocked=True,
                            rule_id=self.RULE_ID,
                            reason=f"API Security: Stripped JWT signature on token requiring algorithm '{alg}'",
                            meta={"alg": alg},
                        )

        return Verdict.clean(self.RULE_ID)
