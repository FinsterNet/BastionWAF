"""
Slider CAPTCHA Cryptographic Token Generator and Human Motion Dynamics Validator.
"""

import hashlib
import hmac
import os
import random
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

SECRET_KEY = os.environ.get("BASTION_CHALLENGE_SECRET", "bastion_waf_hmac_challenge_secret_key_2026").encode("utf-8")
CLEARANCE_COOKIE_NAME = "bastion_waf_clearance"
COOKIE_TTL_SECONDS = 900  # 15 minutes validity
CHALLENGE_TTL_SECONDS = 180  # 3 minutes challenge validity


def _sign(payload: str) -> str:
    return hmac.new(SECRET_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()[:24]


def generate_challenge_token() -> Tuple[str, int]:
    """
    Generates a cryptographically signed slider challenge token.
    Target X position is randomly selected between 80px and 230px on a 280px slider track.
    Returns: (token_str, target_x)
    """
    target_x = random.randint(85, 225)
    ts = int(time.time())
    nonce = secrets.token_hex(4)
    sig = _sign(f"{target_x}:{ts}:{nonce}")
    token = f"{target_x}:{ts}:{nonce}:{sig}"
    return token, target_x


def verify_challenge_solution(
    token: str,
    user_x: int | float,
    duration_ms: int | float = 500,
    trajectory_count: int = 5,
) -> Tuple[bool, str]:
    """
    Validates the submitted slider position, timestamp signature, and human motion dynamics.
    """
    if not token or ":" not in token:
        return False, "Invalid or missing challenge token"

    parts = token.split(":")
    if len(parts) != 4:
        return False, "Malformed challenge token structure"

    try:
        target_x = int(parts[0])
        ts = int(parts[1])
        nonce = parts[2]
        expected_sig = parts[3]
    except Exception:
        return False, "Corrupted challenge token payload"

    # 1. Verify cryptographic HMAC signature
    computed_sig = _sign(f"{target_x}:{ts}:{nonce}")
    if not hmac.compare_digest(expected_sig, computed_sig):
        return False, "Cryptographic challenge signature mismatch / tampered token"

    # 2. Verify token freshness (not expired)
    now = int(time.time())
    if now - ts > CHALLENGE_TTL_SECONDS or now < ts - 10:
        return False, "Challenge token expired. Please reload and try again"

    # 3. Check slider positioning precision (tolerance +/- 9 pixels)
    if abs(float(user_x) - target_x) > 9.0:
        return False, f"Slider piece did not align with target puzzle slot (Offset: {abs(float(user_x) - target_x):.1f}px)"

    # 4. Check human motion dynamics:
    # Automated headless bot scripts typically drag instantly in < 80ms
    if duration_ms < 150:
        return False, "Automated robotic motion detected: drag speed too fast for human interaction"

    # Headless scripts submit 0 or 1 point jumps without smooth dragging
    if trajectory_count < 2:
        return False, "Automated robotic motion detected: discontinuous cursor movement"

    return True, "Challenge solved successfully"


def generate_clearance_cookie(client_ip: str, ttl_seconds: int = COOKIE_TTL_SECONDS) -> str:
    """
    Generates a cryptographically signed clearance cookie for verified human sessions.
    """
    expires_at = int(time.time()) + ttl_seconds
    nonce = secrets.token_hex(4)
    payload = f"{client_ip}:{expires_at}:{nonce}"
    sig = _sign(payload)
    return f"{payload}:{sig}"


def verify_clearance_cookie(cookie_val: str, client_ip: str) -> bool:
    """
    Verifies that the clearance cookie is authentic, belongs to this client IP, and has not expired.
    """
    if not cookie_val or ":" not in cookie_val:
        return False

    parts = cookie_val.split(":")
    if len(parts) != 4:
        return False

    c_ip, expires_at_str, nonce, sig = parts

    # Verify IP affinity
    if c_ip != client_ip:
        return False

    try:
        expires_at = int(expires_at_str)
    except Exception:
        return False

    # Check expiry
    if time.time() > expires_at:
        return False

    # Check HMAC signature
    computed_sig = _sign(f"{c_ip}:{expires_at_str}:{nonce}")
    return hmac.compare_digest(sig, computed_sig)
