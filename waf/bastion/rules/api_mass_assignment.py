"""
API Mass Assignment & Privilege Escalation detection rule (OWASP API Security 950100).
Detects unauthorized administrative, financial, and privilege override parameters in API payloads.
"""

import json
import re
from typing import Any, Dict, List, Set, Tuple
from .base import Rule, Verdict

_PRIVILEGED_FIELDS: Set[str] = {
    "is_admin", "is_superuser", "is_staff", "role", "roles", "user_role", "group", "permissions",
    "privilege", "account_type", "credit_limit", "balance", "wallet_balance", "is_verified",
    "email_verified", "account_status", "tier", "subscription_level", "discount_rate", "rate_limit_exempt",
}

_PRIVILEGED_VALUE_RE = re.compile(r"^(?:admin|administrator|root|superuser|system|moderator|staff|all|\*)$", re.IGNORECASE)


class APIMassAssignmentRule(Rule):
    RULE_ID = "950100"
    NAME = "API Mass Assignment & Privilege Escalation Guard"
    CATEGORY = "API Security"

    def match(self, request) -> Verdict:
        # Only inspect state-modifying API requests (POST, PUT, PATCH)
        if request.method not in ("POST", "PUT", "PATCH"):
            return Verdict.clean(self.RULE_ID)

        body = request.body
        if not body:
            return Verdict.clean(self.RULE_ID)

        # 1. Parse JSON body if present
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                threat, field, val = self._check_dict_fields(data)
                if threat:
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=f"API Security: Mass assignment attempt on privileged attribute ('{field}': '{val}')",
                        meta={"field": field, "value": str(val)[:50]},
                    )
        except Exception:
            pass

        # 2. Check form / query parameters for privileged fields
        for key, vals in request.query_params.items():
            k_lower = key.lower()
            if k_lower in _PRIVILEGED_FIELDS:
                for v in vals:
                    if v.lower() in ("true", "1", "admin", "root", "superuser"):
                        return Verdict(
                            blocked=True,
                            rule_id=self.RULE_ID,
                            reason=f"API Security: Privilege escalation query parameter ('{key}={v}')",
                            meta={"param": key, "value": v},
                        )

        return Verdict.clean(self.RULE_ID)

    def _check_dict_fields(self, data: Dict[str, Any], depth: int = 0) -> Tuple[bool, str, Any]:
        if depth > 5:
            return False, "", None
        for k, v in data.items():
            k_lower = k.lower()
            if k_lower in _PRIVILEGED_FIELDS:
                if isinstance(v, bool) and v is True:
                    return True, k, v
                if isinstance(v, (int, float)) and v > 0 and k_lower in ("is_admin", "is_superuser", "is_staff"):
                    return True, k, v
                if isinstance(v, str) and _PRIVILEGED_VALUE_RE.search(v.strip()):
                    return True, k, v
                if isinstance(v, list) and any(isinstance(item, str) and _PRIVILEGED_VALUE_RE.search(item.strip()) for item in v):
                    return True, k, v
            if isinstance(v, dict):
                sub_threat, sub_k, sub_v = self._check_dict_fields(v, depth + 1)
                if sub_threat:
                    return True, sub_k, sub_v
        return False, "", None
