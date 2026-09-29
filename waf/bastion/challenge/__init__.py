"""
Bastion WAF Interactive Risk-Based Challenge & CAPTCHA Package.
Provides slider human verification, HMAC clearance cookies, and risk evaluation.
"""

from .captcha import (
    generate_challenge_token,
    verify_challenge_solution,
    generate_clearance_cookie,
    verify_clearance_cookie,
    CLEARANCE_COOKIE_NAME,
)
from .page import render_captcha_page
from .evaluator import RiskEvaluator, RiskDecision

__all__ = [
    "generate_challenge_token",
    "verify_challenge_solution",
    "generate_clearance_cookie",
    "verify_clearance_cookie",
    "CLEARANCE_COOKIE_NAME",
    "render_captcha_page",
    "RiskEvaluator",
    "RiskDecision",
]
