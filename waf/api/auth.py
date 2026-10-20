"""
Bastion WAF Authentication & Account Security API Router.
Handles admin onboarding, password authentication, session management,
RFC 6238 TOTP 2FA, password resets, and CSRF validation.
"""

from datetime import datetime, timezone
import json
import logging
import os
import secrets
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field

from bastion.core.security import (
    compute_totp_code,
    decrypt_totp_secret,
    generate_csrf_token,
    generate_recovery_codes,
    generate_secure_token,
    generate_totp_secret,
    get_totp_uri,
    validate_password_strength,
    verify_csrf_token,
    verify_totp_code,
)
from database.db import (
    authenticate_user,
    cleanup_expired_sessions,
    consume_password_reset,
    create_first_admin_atomic,
    create_password_reset,
    create_session,
    create_user,
    delete_all_user_sessions,
    delete_session,
    disable_totp,
    enable_totp,
    get_user_by_email,
    get_user_by_id,
    has_users,
    log_audit_action,
    update_user_password,
    validate_session,
    verify_recovery_code,
)

logger = logging.getLogger("bastion.auth")
auth_router = APIRouter(prefix="/api/auth", tags=["Authentication"])

SESSION_COOKIE_NAME = "bastion_session"
# Temporary in-memory store for pending 2FA challenges (token -> {user_id, expires_at})
_PENDING_2FA: Dict[str, Dict[str, Any]] = {}


# ============================================================
# Request / Response Schemas
# ============================================================

EMAIL_REGEX = r"^(?:[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|[a-zA-Z0-9_.-]{3,32})$"


class SetupRequest(BaseModel):
    email: str = Field(..., max_length=254, pattern=EMAIL_REGEX)
    password: str = Field(..., min_length=12, max_length=128)
    setup_token: Optional[str] = Field(None, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(..., max_length=254, pattern=EMAIL_REGEX)
    password: str = Field(..., min_length=1, max_length=128)


class TwoFactorVerifyRequest(BaseModel):
    temp_token: str = Field(..., min_length=16, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    code: str = Field(..., min_length=4, max_length=16, pattern=r"^[a-zA-Z0-9-]+$")
    is_recovery: bool = False


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=12, max_length=128)


class EnableTwoFactorRequest(BaseModel):
    secret: str = Field(..., min_length=16, max_length=64, pattern=r"^[A-Z2-7=]+$")
    code: str = Field(..., min_length=6, max_length=8, pattern=r"^[0-9]+$")


class DisableTwoFactorRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=128)


class ResetRequest(BaseModel):
    email: str = Field(..., max_length=254, pattern=EMAIL_REGEX)


class ResetConfirmRequest(BaseModel):
    token: str = Field(..., min_length=16, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    new_password: str = Field(..., min_length=12, max_length=128)


# ============================================================
# Helpers & Dependencies
# ============================================================

def get_client_ip(request: Request) -> str:
    """Extract client IP with proxy consideration."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def is_cookie_secure(request: Request) -> bool:
    """Determine whether session cookies require the Secure flag."""
    env_flag = os.environ.get("BASTION_SECURE_COOKIES", "").strip().lower()
    if env_flag in ("1", "true", "yes"):
        return True
    if env_flag in ("0", "false", "no"):
        return False
    return request.url.scheme == "https" or request.headers.get("X-Forwarded-Proto") == "https"


def set_session_cookie(response: Response, raw_token: str, request: Request):
    """Set secure, HttpOnly, SameSite session cookie."""
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=7 * 86400,  # 7 days max
        httponly=True,
        samesite="lax",
        secure=is_cookie_secure(request),
        path="/",
    )


def clear_session_cookie(response: Response):
    """Clear session cookie."""
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
    )


async def get_current_session(request: Request) -> Optional[Dict[str, Any]]:
    """Retrieve and validate session from cookie or Bearer token header."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()

    if not token:
        return None

    session = validate_session(token)
    if session:
        session["raw_token"] = token
    return session


async def require_auth(request: Request) -> Dict[str, Any]:
    """Dependency: Require a valid authenticated session."""
    session = await get_current_session(request)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Authentication required", "code": "UNAUTHORIZED"},
        )
    return session


def verify_csrf_or_abort(request: Request, session: Dict[str, Any]):
    """Verify CSRF token and origin for state-changing requests."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        # 1. Verify Origin header if present
        origin = request.headers.get("Origin") or request.headers.get("Referer")
        host = request.headers.get("Host", "")
        if origin and host and host not in origin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "CSRF: Origin validation failed", "code": "INVALID_ORIGIN"},
            )

        # 2. Synchronizer token check
        csrf_header = request.headers.get("X-CSRF-Token")
        if not csrf_header or not verify_csrf_token(csrf_header, session["user_id"], session["session_id"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "CSRF: Invalid or missing CSRF token", "code": "INVALID_CSRF"},
            )


# ============================================================
# Auth Endpoints
# ============================================================

@auth_router.get("/status")
async def auth_status(request: Request):
    """Check system setup status and active session info."""
    setup_req = not has_users()
    session = await get_current_session(request)

    if session:
        csrf_token = generate_csrf_token(session["user_id"], session["session_id"])
        return {
            "setup_required": False,
            "authenticated": True,
            "user": {
                "id": session["user_id"],
                "email": session["email"],
                "totp_enabled": bool(session.get("totp_enabled")),
            },
            "csrf_token": csrf_token,
        }

    return {
        "setup_required": setup_req,
        "authenticated": False,
        "user": None,
        "csrf_token": None,
    }


@auth_router.post("/setup")
async def initial_setup(req: SetupRequest, request: Request, response: Response):
    """
    First-time administrator account creation.
    Only permitted if zero users exist in the database, with atomic lock.
    If BASTION_SETUP_TOKEN is configured in environment, it must match.
    """
    expected_token = os.environ.get("BASTION_SETUP_TOKEN")
    if expected_token and req.setup_token != expected_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid setup token. Administrator registration requires valid token from BASTION_SETUP_TOKEN or local CLI.",
        )

    client_ip = get_client_ip(request)
    success, msg, user_id = create_first_admin_atomic(req.email, req.password)
    if not success or not user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    # Automatically log in the newly created administrator
    raw_token = generate_secure_token()
    user_agent = request.headers.get("User-Agent", "")
    session_data = create_session(user_id, raw_token, ip=client_ip, user_agent=user_agent)

    set_session_cookie(response, raw_token, request)
    csrf_token = generate_csrf_token(user_id, session_data["session_id"])

    log_audit_action(user_id, req.email, "INITIAL_ADMIN_SETUP", "Initial administrator account created", client_ip)

    return {
        "status": "success",
        "message": "Administrator account created successfully",
        "user": {
            "id": user_id,
            "email": req.email.strip().lower(),
            "totp_enabled": False,
        },
        "csrf_token": csrf_token,
    }


@auth_router.post("/login")
async def login(req: LoginRequest, request: Request, response: Response):
    """
    Authenticate administrator credentials with brute-force lockout,
    timing side-channel equalization, and optional 2FA challenge.
    """
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")

    success, msg, user = authenticate_user(req.email, req.password, client_ip)
    if not success or not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=msg)

    # If TOTP 2FA is enabled on this account, trigger second factor challenge
    if user.get("totp_enabled"):
        temp_token = generate_secure_token()
        _PENDING_2FA[temp_token] = {
            "user_id": user["id"],
            "email": user["email"],
            "expires_at": time.time() + 300,  # 5 minutes
            "ip": client_ip,
        }
        return {
            "status": "2fa_required",
            "message": "Two-factor authentication code required",
            "temp_token": temp_token,
        }

    # Issue session & set cookie
    raw_token = generate_secure_token()
    session_data = create_session(user["id"], raw_token, ip=client_ip, user_agent=user_agent)

    set_session_cookie(response, raw_token, request)
    csrf_token = generate_csrf_token(user["id"], session_data["session_id"])

    log_audit_action(user["id"], user["email"], "LOGIN_SUCCESS", "Administrator logged in successfully", client_ip)

    return {
        "status": "success",
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "totp_enabled": False,
        },
        "csrf_token": csrf_token,
    }


@auth_router.post("/2fa/verify")
async def verify_two_factor_login(req: TwoFactorVerifyRequest, request: Request, response: Response):
    """Verify 2FA TOTP code or backup recovery code to complete login."""
    pending = _PENDING_2FA.get(req.temp_token)
    now = time.time()

    if not pending or now > pending["expires_at"]:
        _PENDING_2FA.pop(req.temp_token, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Two-factor session expired. Please log in again.",
        )

    user_id = pending["user_id"]
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    client_ip = get_client_ip(request)
    verified = False

    if req.is_recovery:
        verified = verify_recovery_code(user_id, req.code)
        if not verified:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid recovery code")
    else:
        enc_secret = user.get("totp_secret_encrypted")
        secret = decrypt_totp_secret(enc_secret) if enc_secret else None
        if not secret:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to decrypt 2FA key")

        verified = verify_totp_code(secret, req.code)
        if not verified:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid verification code")

    # Clean up pending token
    _PENDING_2FA.pop(req.temp_token, None)

    # Issue session
    raw_token = generate_secure_token()
    user_agent = request.headers.get("User-Agent", "")
    session_data = create_session(user["id"], raw_token, ip=client_ip, user_agent=user_agent)

    set_session_cookie(response, raw_token, request)
    csrf_token = generate_csrf_token(user["id"], session_data["session_id"])

    log_audit_action(
        user["id"],
        user["email"],
        "LOGIN_2FA_SUCCESS",
        "Logged in via " + ("Recovery Code" if req.is_recovery else "TOTP"),
        client_ip,
    )

    return {
        "status": "success",
        "message": "Two-factor authentication verified",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "totp_enabled": True,
        },
        "csrf_token": csrf_token,
    }


@auth_router.post("/logout")
async def logout(request: Request, response: Response):
    """Invalidate current session and clear session cookie."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    session = await get_current_session(request)

    if token:
        delete_session(token)

    clear_session_cookie(response)

    if session:
        log_audit_action(
            session["user_id"],
            session["email"],
            "LOGOUT",
            "Session terminated by user",
            get_client_ip(request),
        )

    return {"status": "success", "message": "Logged out successfully"}


@auth_router.get("/me")
async def get_me(session: Dict[str, Any] = Depends(require_auth)):
    """Retrieve current authenticated user profile."""
    user = get_user_by_id(session["user_id"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    csrf_token = generate_csrf_token(session["user_id"], session["session_id"])
    return {
        "user": {
            "id": user["id"],
            "email": user["email"],
            "totp_enabled": bool(user.get("totp_enabled")),
            "created_at": user.get("created_at"),
        },
        "csrf_token": csrf_token,
    }


@auth_router.post("/password/change")
async def change_password(
    req: ChangePasswordRequest,
    request: Request,
    response: Response,
    session: Dict[str, Any] = Depends(require_auth),
):
    """Change current password and invalidate all other sessions."""
    verify_csrf_or_abort(request, session)
    user = get_user_by_id(session["user_id"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    client_ip = get_client_ip(request)
    auth_ok, _, _ = authenticate_user(user["email"], req.current_password, client_ip)
    if not auth_ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password incorrect")

    success, msg = update_user_password(user["id"], req.new_password)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    # Issue a fresh session for current browser
    raw_token = generate_secure_token()
    user_agent = request.headers.get("User-Agent", "")
    session_data = create_session(user["id"], raw_token, ip=client_ip, user_agent=user_agent)

    set_session_cookie(response, raw_token, request)
    new_csrf = generate_csrf_token(user["id"], session_data["session_id"])

    log_audit_action(
        user["id"],
        user["email"],
        "PASSWORD_CHANGED",
        "Password changed and other sessions terminated",
        client_ip,
    )

    return {
        "status": "success",
        "message": "Password changed successfully. All other sessions have been logged out.",
        "csrf_token": new_csrf,
    }


@auth_router.post("/2fa/setup")
async def setup_two_factor(
    request: Request,
    session: Dict[str, Any] = Depends(require_auth),
):
    """Generate a new TOTP secret and provisioning URI."""
    verify_csrf_or_abort(request, session)
    secret = generate_totp_secret()
    uri = get_totp_uri(session["email"], secret, issuer="BastionWAF")

    return {
        "secret": secret,
        "otpauth_uri": uri,
    }


@auth_router.post("/2fa/enable")
async def enable_two_factor(
    req: EnableTwoFactorRequest,
    request: Request,
    session: Dict[str, Any] = Depends(require_auth),
):
    """Verify initial TOTP code and enable 2FA with recovery codes."""
    verify_csrf_or_abort(request, session)

    if not verify_totp_code(req.secret, req.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code")

    recovery_codes = generate_recovery_codes(10)
    enable_totp(session["user_id"], req.secret, recovery_codes)

    log_audit_action(
        session["user_id"],
        session["email"],
        "2FA_ENABLED",
        "Two-factor authentication enabled",
        get_client_ip(request),
    )

    return {
        "status": "success",
        "message": "Two-factor authentication enabled successfully",
        "recovery_codes": recovery_codes,
    }


@auth_router.post("/2fa/disable")
async def disable_two_factor(
    req: DisableTwoFactorRequest,
    request: Request,
    session: Dict[str, Any] = Depends(require_auth),
):
    """Disable 2FA after password confirmation."""
    verify_csrf_or_abort(request, session)

    success, msg = disable_totp(session["user_id"], req.password)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    log_audit_action(
        session["user_id"],
        session["email"],
        "2FA_DISABLED",
        "Two-factor authentication disabled",
        get_client_ip(request),
    )

    return {"status": "success", "message": msg}


@auth_router.post("/reset/request")
async def request_password_reset(req: ResetRequest, request: Request):
    """
    Request password reset link. Returns generic response
    to avoid email enumeration.
    """
    token = generate_secure_token()
    user_id = create_password_reset(req.email, token)

    if user_id:
        logger.info(
            f"[SECURITY AUDIT] Password reset requested for {req.email}. "
            f"Reset Token (Dev/Local Emergency): {token}"
        )
        log_audit_action(
            user_id,
            req.email,
            "PASSWORD_RESET_REQUESTED",
            "Reset token issued",
            get_client_ip(request),
        )

    return {
        "status": "success",
        "message": "If an account exists with this email, password reset instructions have been dispatched.",
    }


@auth_router.post("/reset/confirm")
async def confirm_password_reset(req: ResetConfirmRequest, request: Request):
    """Consume reset token, set new password, and invalidate all sessions."""
    success, msg = consume_password_reset(req.token, req.new_password)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    log_audit_action(
        None,
        "",
        "PASSWORD_RESET_COMPLETED",
        "Password reset confirmed via token",
        get_client_ip(request),
    )

    return {
        "status": "success",
        "message": msg,
    }
