"""
Bastion WAF Authentication & Account Security API Router.
Handles admin onboarding, password authentication, session management,
RFC 6238 TOTP 2FA, password resets, and CSRF validation.
"""

from datetime import datetime, timezone
import ipaddress
import json
import logging
import os
import secrets
import time
from typing import Any, Dict, List, Optional
import urllib.parse
import redis

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
    get_audit_logs,
    get_user_by_email,
    get_user_by_id,
    get_user_sessions,
    has_users,
    log_audit_action,
    revoke_other_sessions,
    revoke_session_by_id,
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

def is_ip_in_trusted_proxies(ip_str: str, trusted_list: List[str]) -> bool:
    """Check if an IP string belongs to any trusted proxy IP or CIDR network."""
    if ip_str in trusted_list:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        for trusted in trusted_list:
            if "/" in trusted:
                if ip in ipaddress.ip_network(trusted, strict=False):
                    return True
            else:
                if ip == ipaddress.ip_address(trusted):
                    return True
    except ValueError:
        return False
    return False


def get_client_ip(request: Request) -> str:
    """
    Extract client IP address safely:
    Only trust CF-Connecting-IP or right-most X-Forwarded-For if direct peer
    is in BASTION_TRUSTED_PROXIES; otherwise return the direct socket IP.
    """
    peer_ip = request.client.host if request.client else "127.0.0.1"
    trusted_env = os.environ.get("BASTION_TRUSTED_PROXIES", "").strip()
    if not trusted_env:
        return peer_ip

    trusted_proxies = [p.strip() for p in trusted_env.split(",") if p.strip()]
    if not is_ip_in_trusted_proxies(peer_ip, trusted_proxies):
        return peer_ip

    # Peer is confirmed trusted proxy
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip and cf_ip.strip():
        return cf_ip.strip()

    xff = request.headers.get("X-Forwarded-For")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        for ip in reversed(parts):
            if not is_ip_in_trusted_proxies(ip, trusted_proxies):
                return ip
        if parts:
            return parts[0]

    return peer_ip


_REDIS_CLIENT = None
_REDIS_INITIALIZED = False


def get_redis_client():
    """Retrieve or initialize shared Redis connection pool if REDIS_URL is configured."""
    global _REDIS_CLIENT, _REDIS_INITIALIZED
    if _REDIS_INITIALIZED:
        return _REDIS_CLIENT

    redis_url = os.environ.get("REDIS_URL", "").strip()
    if not redis_url:
        _REDIS_CLIENT = None
        _REDIS_INITIALIZED = True
        return None

    try:
        import redis
        client = redis.Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=1.5,
            socket_timeout=1.5,
        )
        client.ping()
        _REDIS_CLIENT = client
        logger.info("⚡ Distributed Redis connection active for rate limiting: %s", redis_url.split("@")[-1])
    except Exception as e:
        logger.warning("Redis configured at REDIS_URL but connection failed (%s); using in-memory fallback.", e)
        _REDIS_CLIENT = None

    _REDIS_INITIALIZED = True
    return _REDIS_CLIENT


def reset_redis_client():
    """Reset cached Redis client instance (useful for testing or reconnect)."""
    global _REDIS_CLIENT, _REDIS_INITIALIZED
    if _REDIS_CLIENT:
        try:
            _REDIS_CLIENT.close()
        except Exception:
            pass
    _REDIS_CLIENT = None
    _REDIS_INITIALIZED = False


# In-memory sliding window rate limiter: endpoint -> ip -> list of timestamps
_RATE_LIMIT_STORE: Dict[str, Dict[str, List[float]]] = {}
RATE_LIMIT_WINDOW = 900  # 15 minutes
MAX_ATTEMPTS = 10


def check_ip_rate_limit(ip: str, endpoint: str = "login"):
    """
    Enforce sliding window rate limit (10 attempts / 15 minutes) per IP.
    Uses distributed Redis Sorted Sets (ZSET) if REDIS_URL is active;
    otherwise falls back to local process memory store.
    """
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW
    r = get_redis_client()

    if r:
        try:
            key = f"ratelimit:{endpoint}:{ip}"
            r.zremrangebyscore(key, 0, cutoff)
            count = r.zcard(key)
            if count >= MAX_ATTEMPTS:
                oldest_entries = r.zrange(key, 0, 0, withscores=True)
                if oldest_entries:
                    oldest_ts = oldest_entries[0][1]
                    retry_after = max(1, int(oldest_ts + RATE_LIMIT_WINDOW - now))
                else:
                    retry_after = RATE_LIMIT_WINDOW
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many attempts, try again later",
                    headers={"Retry-After": str(retry_after)},
                )
            return
        except HTTPException:
            raise
        except Exception as e:
            logger.warning("Redis rate limit check failed (%s); falling back to memory.", e)

    # In-memory fallback
    if endpoint not in _RATE_LIMIT_STORE:
        _RATE_LIMIT_STORE[endpoint] = {}
    timestamps = _RATE_LIMIT_STORE[endpoint].get(ip, [])
    valid_timestamps = [t for t in timestamps if t >= cutoff]

    if len(valid_timestamps) >= MAX_ATTEMPTS:
        oldest = valid_timestamps[0]
        retry_after = max(1, int(oldest + RATE_LIMIT_WINDOW - now))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts, try again later",
            headers={"Retry-After": str(retry_after)},
        )


def record_ip_attempt(ip: str, endpoint: str = "login"):
    """
    Record an access attempt for IP sliding window tracking.
    Uses distributed Redis ZSET if available, otherwise updates local memory.
    """
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW
    r = get_redis_client()

    if r:
        try:
            key = f"ratelimit:{endpoint}:{ip}"
            member = f"{now}:{secrets.token_hex(4)}"
            pipe = r.pipeline()
            pipe.zremrangebyscore(key, 0, cutoff)
            pipe.zadd(key, {member: now})
            pipe.expire(key, RATE_LIMIT_WINDOW + 60)
            pipe.execute()
            return
        except Exception as e:
            logger.warning("Redis rate limit record failed (%s); falling back to memory.", e)

    # In-memory fallback
    if endpoint not in _RATE_LIMIT_STORE:
        _RATE_LIMIT_STORE[endpoint] = {}
    timestamps = _RATE_LIMIT_STORE[endpoint].get(ip, [])
    valid_timestamps = [t for t in timestamps if t >= cutoff]
    valid_timestamps.append(now)
    _RATE_LIMIT_STORE[endpoint][ip] = valid_timestamps


def reset_rate_limits():
    """Reset all in-memory and Redis rate limiting counters."""
    _RATE_LIMIT_STORE.clear()
    r = get_redis_client()
    if r:
        try:
            keys = r.keys("ratelimit:*")
            if keys:
                r.delete(*keys)
        except Exception:
            pass


def get_allowed_origins() -> List[str]:
    """Retrieve allowed dashboard origins from BASTION_ALLOWED_ORIGINS env var."""
    raw = os.environ.get("BASTION_ALLOWED_ORIGINS", "")
    if raw.strip():
        return [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]
    return [
        "http://localhost:10000",
        "http://127.0.0.1:10000",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://testserver",
        "https://testserver",
    ]


def extract_origin(request: Request) -> Optional[str]:
    """Extract origin from Origin or Referer header."""
    origin = request.headers.get("origin")
    if origin and origin.strip():
        return origin.strip().rstrip("/")
    referer = request.headers.get("referer")
    if referer and referer.strip():
        try:
            parsed = urllib.parse.urlparse(referer.strip())
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        except Exception:
            pass
    return None


def verify_origin_or_abort(request: Request):
    """Enforce Origin/Referer matching against BASTION_ALLOWED_ORIGINS for state-changing calls."""
    origin = extract_origin(request)
    if not origin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "CSRF: Missing Origin or Referer header", "code": "CSRF_ORIGIN_MISSING"},
        )
    allowed = get_allowed_origins()
    if origin not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "CSRF: Origin not allowed", "code": "CSRF_ORIGIN_INVALID"},
        )


def verify_csrf_or_abort(request: Request, session: Optional[Dict[str, Any]] = None):
    """Verify CSRF token and origin for state-changing requests."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        # 1. Verify Origin header
        verify_origin_or_abort(request)

        # 2. Synchronizer token check
        csrf_header = request.headers.get("X-CSRF-Token")
        if not csrf_header or not session or not verify_csrf_token(csrf_header, session["user_id"], session["session_id"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "CSRF: Invalid or missing CSRF token", "code": "INVALID_CSRF"},
            )


def is_cookie_secure(request: Optional[Request] = None) -> bool:
    """Determine whether session cookies require the Secure flag."""
    env_flag = os.environ.get("BASTION_COOKIE_SECURE")
    if env_flag is not None:
        return env_flag.strip().lower() in ("1", "true", "yes")
    if request:
        return getattr(request, "url", None) and getattr(request.url, "scheme", "") == "https"
    return False


def get_session_cookie_name(request: Optional[Request] = None) -> str:
    """Return __Host- prefixed cookie when Secure, fallback to bastion_session for local HTTP dev."""
    return "__Host-bastion_session" if is_cookie_secure(request) else "bastion_session"


def set_session_cookie(response: Response, raw_token: str, request: Request):
    """Set secure, HttpOnly, SameSite session cookie with appropriate prefix."""
    secure = is_cookie_secure(request)
    cookie_name = get_session_cookie_name(request)
    response.set_cookie(
        key=cookie_name,
        value=raw_token,
        max_age=7 * 86400,  # 7 days max
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
    )


def clear_session_cookie(response: Response):
    """Clear both host-prefixed and legacy session cookies."""
    for name in ("__Host-bastion_session", "bastion_session"):
        response.delete_cookie(
            key=name,
            path="/",
            httponly=True,
            samesite="lax",
        )


async def get_current_session(request: Request) -> Optional[Dict[str, Any]]:
    """Retrieve and validate session from cookie or Bearer token header."""
    token = request.cookies.get("__Host-bastion_session") or request.cookies.get("bastion_session")
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


# ============================================================
# Auth Endpoints
# ============================================================

@auth_router.get("/status")
async def auth_status(request: Request):
    """Check system setup status and active session info."""
    users_exist = has_users()
    setup_req = not users_exist
    session = await get_current_session(request)

    if session:
        csrf_token = generate_csrf_token(session["user_id"], session["session_id"])
        return {
            "setup_required": False,
            "setup_available": False,
            "authenticated": True,
            "user": {
                "id": session["user_id"],
                "email": session["email"],
                "totp_enabled": bool(session.get("totp_enabled")),
            },
            "csrf_token": csrf_token,
        }

    expected_token = os.environ.get("BASTION_SETUP_TOKEN")
    setup_available = setup_req and bool(expected_token)
    message = None
    if setup_req and not expected_token:
        message = "setup not available, run the create-admin CLI"

    res = {
        "setup_required": setup_req,
        "setup_available": setup_available,
        "authenticated": False,
        "user": None,
        "csrf_token": None,
    }
    if message:
        res["message"] = message
    return res


@auth_router.post("/setup")
async def initial_setup(req: SetupRequest, request: Request, response: Response):
    """
    First-time administrator account creation.
    Only permitted if zero users exist in the database, with atomic lock.
    Requires BASTION_SETUP_TOKEN to be set in environment and strictly matched.
    """
    verify_origin_or_abort(request)
    client_ip = get_client_ip(request)
    check_ip_rate_limit(client_ip, endpoint="setup")
    record_ip_attempt(client_ip, endpoint="setup")

    expected_token = os.environ.get("BASTION_SETUP_TOKEN")
    if not expected_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Initial setup is disabled. Set BASTION_SETUP_TOKEN or run the CLI create-admin command.",
        )

    provided_token = req.setup_token
    if not provided_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            provided_token = auth_header[7:].strip()

    if not provided_token or not secrets.compare_digest(provided_token.encode("utf-8"), expected_token.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid setup token. Administrator registration requires valid token from BASTION_SETUP_TOKEN or local CLI.",
        )

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
    verify_origin_or_abort(request)
    client_ip = get_client_ip(request)
    check_ip_rate_limit(client_ip, endpoint="login")
    record_ip_attempt(client_ip, endpoint="login")

    user_agent = request.headers.get("User-Agent", "")

    success, msg, user = authenticate_user(req.email, req.password, client_ip)
    if not success or not user:
        log_audit_action(None, req.email, "LOGIN_FAILURE", "Failed login attempt", client_ip)
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

    # Rotate session: invalidate any existing session sent by the client
    old_token = request.cookies.get("__Host-bastion_session") or request.cookies.get("bastion_session")
    if old_token:
        try:
            delete_session(old_token)
        except Exception:
            pass

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
    verify_origin_or_abort(request)
    client_ip = get_client_ip(request)
    check_ip_rate_limit(client_ip, endpoint="2fa")
    record_ip_attempt(client_ip, endpoint="2fa")

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

    verified = False

    if req.is_recovery:
        verified = verify_recovery_code(user_id, req.code)
        if not verified:
            log_audit_action(user_id, user["email"], "2FA_RECOVERY_FAILURE", "Invalid recovery code", client_ip)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid recovery code")
    else:
        enc_secret = user.get("totp_secret_encrypted")
        secret = decrypt_totp_secret(enc_secret) if enc_secret else None
        if not secret:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to decrypt 2FA key")

        verified = verify_totp_code(secret, req.code)
        if not verified:
            log_audit_action(user_id, user["email"], "2FA_VERIFY_FAILURE", "Invalid TOTP verification code", client_ip)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid verification code")

    # Clean up pending token
    _PENDING_2FA.pop(req.temp_token, None)

    # Rotate session: invalidate any existing session sent by the client
    old_token = request.cookies.get("__Host-bastion_session") or request.cookies.get("bastion_session")
    if old_token:
        try:
            delete_session(old_token)
        except Exception:
            pass

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
    token = request.cookies.get("__Host-bastion_session") or request.cookies.get("bastion_session")
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
    verify_origin_or_abort(request)
    client_ip = get_client_ip(request)
    check_ip_rate_limit(client_ip, endpoint="reset")
    record_ip_attempt(client_ip, endpoint="reset")

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
            client_ip,
        )

    return {
        "status": "success",
        "message": "If an account exists with this email, password reset instructions have been dispatched.",
    }


@auth_router.post("/reset/confirm")
async def confirm_password_reset(req: ResetConfirmRequest, request: Request):
    """Consume reset token, set new password, and invalidate all sessions."""
    verify_origin_or_abort(request)
    client_ip = get_client_ip(request)
    check_ip_rate_limit(client_ip, endpoint="reset")
    record_ip_attempt(client_ip, endpoint="reset")

    success, msg = consume_password_reset(req.token, req.new_password)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    log_audit_action(
        None,
        "",
        "PASSWORD_RESET_COMPLETED",
        "Password reset confirmed via token",
        client_ip,
    )

    return {
        "status": "success",
        "message": msg,
    }


# ============================================================
# Session Management Endpoints
# ============================================================

@auth_router.get("/sessions")
async def list_user_sessions(session: Dict[str, Any] = Depends(require_auth)):
    """List active sessions for current user."""
    sessions = get_user_sessions(session["user_id"])
    current_sid = session["session_id"]
    for s in sessions:
        s["is_current"] = (s["id"] == current_sid)
    return {"sessions": sessions}


@auth_router.delete("/sessions/{session_id}")
async def revoke_session_endpoint(
    session_id: int,
    request: Request,
    response: Response,
    session: Dict[str, Any] = Depends(require_auth),
):
    """Revoke a specific active session."""
    verify_csrf_or_abort(request, session)
    client_ip = get_client_ip(request)
    success = revoke_session_by_id(session["user_id"], session_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    if session_id == session["session_id"]:
        clear_session_cookie(response)

    log_audit_action(
        session["user_id"],
        session["email"],
        "SESSION_REVOKED",
        f"Revoked session {session_id}",
        client_ip,
    )
    return {"status": "success", "message": f"Session {session_id} revoked"}


@auth_router.post("/sessions/revoke-others")
async def revoke_others_endpoint(
    request: Request,
    session: Dict[str, Any] = Depends(require_auth),
):
    """Revoke all active sessions for current user except the current one."""
    verify_csrf_or_abort(request, session)
    client_ip = get_client_ip(request)
    count = revoke_other_sessions(session["user_id"], session["session_id"])
    log_audit_action(
        session["user_id"],
        session["email"],
        "SESSIONS_REVOKE_OTHERS",
        f"Revoked {count} other active sessions",
        client_ip,
    )
    return {"status": "success", "revoked_count": count}
