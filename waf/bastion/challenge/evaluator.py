"""
Risk-Based Anomaly & Threat Evaluator for Adaptive Challenge Decisions.
Decides whether to ALLOW, BLOCK (403), or CHALLENGE (Slider CAPTCHA).
"""

from collections import defaultdict, deque
from enum import Enum, auto
import threading
import time
from typing import Deque, Dict, Optional, Set, Tuple

from .captcha import verify_clearance_cookie, CLEARANCE_COOKIE_NAME


class RiskDecision(Enum):
    ALLOW = auto()
    BLOCK = auto()
    CHALLENGE = auto()


# High-confidence exploit rules that must ALWAYS be hard-blocked immediately (no CAPTCHA)
HARD_BLOCK_RULES: Set[str] = {
    "942100",  # SQL Injection
    "941100",  # Cross-Site Scripting
    "932100",  # Remote Code Execution / Command Injection
    "930120",  # Path Traversal / LFI
    "933300",  # Insecure Deserialization
    "933200",  # XML External Entity (XXE)
    "933400",  # Webshell & Malicious Upload
    "933500",  # JNDI / Log4Shell
    "933600",  # Prototype Pollution
    "934100",  # SSRF
}

# Sensitive authentication paths that warrant human challenge on unauthenticated visits
SENSITIVE_AUTH_PATHS: Set[str] = {
    "/login", "/signin", "/auth", "/api/login", "/api/auth", "/admin", "/admin/login", "/staff/login"
}

_VELOCITY_LOCK = threading.Lock()
_IP_VELOCITY: Dict[str, Deque[float]] = defaultdict(deque)

# Challenge trigger: > 18 requests within a 5-second window
BURST_WINDOW_SEC = 5.0
BURST_CHALLENGE_THRESHOLD = 18


class RiskEvaluator:
    """
    Evaluates request risk to determine whether to Block, Challenge, or Allow.
    """

    @classmethod
    def evaluate(
        cls,
        verdict_blocked: bool,
        rule_id: str,
        reason: str,
        client_ip: str,
        path: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
    ) -> Tuple[RiskDecision, str]:
        # 1. Check if client has an authentic, non-expired clearance cookie
        clearance_token = cookies.get(CLEARANCE_COOKIE_NAME, "")
        has_valid_clearance = False
        if clearance_token:
            has_valid_clearance = verify_clearance_cookie(clearance_token, client_ip)

        # 2. Check for Hard Critical Exploits (SQLi, RCE, LFI, Deserialization, etc.)
        if verdict_blocked and rule_id in HARD_BLOCK_RULES:
            return RiskDecision.BLOCK, reason

        # 3. Check Velocity / Burst Anomaly (Layer 7 Surge)
        now = time.time()
        with _VELOCITY_LOCK:
            timestamps = _IP_VELOCITY[client_ip]
            while timestamps and now - timestamps[0] > BURST_WINDOW_SEC:
                timestamps.popleft()
            timestamps.append(now)
            burst_count = len(timestamps)

        if not has_valid_clearance and burst_count >= BURST_CHALLENGE_THRESHOLD:
            return RiskDecision.CHALLENGE, f"Traffic surge anomaly detected ({burst_count} req / {BURST_WINDOW_SEC}s)"

        # 4. Check Non-Exploit WAF Rule Violations (e.g. Scanners, Rate Limit, Credential Stuffing, Header Anomaly)
        if verdict_blocked:
            # If the rule triggered was bot scanner, rate limit, or header anomaly -> Challenge!
            if rule_id in ("960100", "960200", "960300", "960400", "960500", "960600", "930200"):
                if not has_valid_clearance:
                    return RiskDecision.CHALLENGE, f"Automated behavior detected: {reason}"
                else:
                    return RiskDecision.BLOCK, reason
            return RiskDecision.BLOCK, reason

        # 5. Check Sensitive Route Protection (e.g. /login or /admin without clearance)
        path_lower = path.lower()
        if not has_valid_clearance and any(p == path_lower or path_lower.startswith(p + "/") for p in SENSITIVE_AUTH_PATHS):
            # Optional: gate sensitive portals with human challenge
            # return RiskDecision.CHALLENGE, "Sensitive authentication endpoint human verification"
            pass

        return RiskDecision.ALLOW, "Clean request"
