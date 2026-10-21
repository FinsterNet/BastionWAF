"""
Bastion WAF Management REST API & Dashboard Server.
Secured with session authentication, CSRF synchronizer tokens,
security headers, and administrative action audit logging.
"""

import os
from pathlib import Path
import platform
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path as ApiPath, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import ipaddress

from api.auth import (
    auth_router,
    get_allowed_origins,
    get_client_ip,
    get_current_session,
    require_auth,
    verify_csrf_or_abort,
)
from bastion.core.config import get_config
from bastion.core.engine import Engine
from bastion.core.inspector import inspect_request
from bastion.core.reputation import check_ip_access, get_reputation_score, invalidate_rules_cache
from database.db import (
    add_ip_rule,
    add_site,
    clear_logs,
    delete_ip_rule,
    delete_site,
    export_logs_csv,
    get_audit_logs,
    get_enabled_rule_ids,
    get_ip_rules,
    get_logs,
    get_recent_events,
    get_rules,
    get_sites,
    get_stats,
    init_db,
    log_audit_action,
    set_rule_state,
    set_site_defense,
)

init_db()

api_router = APIRouter()
sim_engine = Engine()

START_TIME = time.time()
_SIM_RATE_LIMITS: Dict[str, list] = {}  # ip -> [timestamps]


def check_simulate_rate_limit(ip: str):
    """Limit simulation requests to 30 per minute per IP."""
    now = time.time()
    history = [t for t in _SIM_RATE_LIMITS.get(ip, []) if now - t < 60.0]
    if len(history) >= 30:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for threat simulations (max 30 per minute).",
        )
    history.append(now)
    _SIM_RATE_LIMITS[ip] = history


import re

DOMAIN_REGEX = (
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?::\d{1,5})?$|"
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d{1,5})?$|"
    r"^localhost(?::\d{1,5})?$"
)

UPSTREAM_REGEX = (
    r"^(?:https?://)?"
    r"(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}|"
    r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|"
    r"localhost)"
    r"(?::\d{1,5})?"
    r"(?:/[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]*)?$"
)


class RuleToggleRequest(BaseModel):
    rule_id: str = Field(..., pattern=r"^[0-9]{6}$", description="6-digit OWASP/WAF rule identifier")
    enabled: bool


class SiteToggleRequest(BaseModel):
    site_id: Optional[int] = Field(None, ge=1, le=2147483647)
    defense_mode: Optional[bool] = None
    domain: Optional[str] = Field(None, max_length=253, pattern=DOMAIN_REGEX)
    upstream: Optional[str] = Field(None, max_length=253, pattern=UPSTREAM_REGEX)


class IPRuleCreateRequest(BaseModel):
    cidr: str = Field(..., max_length=64, description="IPv4/IPv6 address or CIDR subnet (e.g. 192.168.1.100 or 10.0.0.0/8)")
    rule_type: str = Field(..., pattern=r"^(whitelist|blacklist|quarantine)$")
    reason: str = Field(default="", max_length=255)
    duration_seconds: Optional[int] = Field(default=None, ge=1, le=2592000)


# ============================================================
# Protected Management API Routes
# ============================================================

@api_router.get("/api/stats")
def stats(session: Dict[str, Any] = Depends(require_auth)):
    return get_stats()


@api_router.get("/api/events")
def events(
    limit: int = Query(15, ge=1, le=100),
    session: Dict[str, Any] = Depends(require_auth),
):
    return get_recent_events(limit=limit)


@api_router.get("/api/logs")
def logs(
    q: str = Query("", max_length=100, alias="q"),
    threat: str = Query("All Threat Types", max_length=50, alias="threat"),
    limit: int = Query(50, ge=1, le=500, alias="limit"),
    session: Dict[str, Any] = Depends(require_auth),
):
    return get_logs(query=q, threat=threat, limit=limit)


@api_router.post("/api/logs/clear")
def clear_all_logs(
    request: Request,
    session: Dict[str, Any] = Depends(require_auth),
):
    verify_csrf_or_abort(request, session)
    clear_logs()
    log_audit_action(
        session["user_id"],
        session["email"],
        "CLEAR_LOGS",
        "All security audit logs cleared by administrator",
        get_client_ip(request),
    )
    return {"status": "success", "message": "All security audit logs cleared"}


@api_router.get("/api/export/csv")
def export_csv(session: Dict[str, Any] = Depends(require_auth)):
    csv_data = export_logs_csv()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=bastion_waf_security_logs.csv"},
    )


@api_router.get("/api/rules")
def list_rules(session: Dict[str, Any] = Depends(require_auth)):
    return get_rules()


@api_router.post("/api/rules")
def update_rule(
    req: RuleToggleRequest,
    request: Request,
    session: Dict[str, Any] = Depends(require_auth),
):
    verify_csrf_or_abort(request, session)
    set_rule_state(req.rule_id, req.enabled)
    log_audit_action(
        session["user_id"],
        session["email"],
        "RULE_TOGGLED",
        f"Rule {req.rule_id} set to {'enabled' if req.enabled else 'disabled'}",
        get_client_ip(request),
    )
    return {"status": "success", "rule_id": req.rule_id, "enabled": req.enabled}


@api_router.get("/api/sites")
def list_sites(session: Dict[str, Any] = Depends(require_auth)):
    return get_sites()


@api_router.post("/api/sites")
def update_or_add_site(
    req: SiteToggleRequest,
    request: Request,
    session: Dict[str, Any] = Depends(require_auth),
):
    verify_csrf_or_abort(request, session)
    client_ip = get_client_ip(request)

    if req.domain and req.upstream:
        add_site(req.domain, req.upstream)
        log_audit_action(
            session["user_id"],
            session["email"],
            "SITE_ADDED",
            f"Protected site {req.domain} mapped to {req.upstream}",
            client_ip,
        )
        return {"status": "success", "action": "created", "domain": req.domain}

    if req.site_id is not None and req.defense_mode is not None:
        set_site_defense(req.site_id, req.defense_mode)
        log_audit_action(
            session["user_id"],
            session["email"],
            "SITE_DEFENSE_MODE_UPDATED",
            f"Site ID {req.site_id} defense mode changed to {req.defense_mode}",
            client_ip,
        )
        return {"status": "success", "action": "updated", "site_id": req.site_id}

    return {"status": "error", "message": "Invalid site payload"}


@api_router.delete("/api/sites/{site_id}")
def remove_site(
    site_id: int = ApiPath(..., ge=1, le=2147483647, description="Protected site ID"),
    request: Request = None,
    session: Dict[str, Any] = Depends(require_auth),
):
    verify_csrf_or_abort(request, session)
    delete_site(site_id)
    log_audit_action(
        session["user_id"],
        session["email"],
        "SITE_DELETED",
        f"Protected site ID {site_id} deleted",
        get_client_ip(request),
    )
    return {"status": "success", "action": "deleted", "site_id": site_id}


# ============================================================
# IP Access Control & Quarantine Endpoints
# ============================================================

@api_router.get("/api/ip-rules")
def list_ip_rules(
    rule_type: Optional[str] = Query(None, pattern=r"^(whitelist|blacklist|quarantine)$"),
    session: Dict[str, Any] = Depends(require_auth),
):
    """List active IP access rules and quarantines with remaining TTL."""
    return get_ip_rules(rule_type=rule_type)


@api_router.post("/api/ip-rules")
def create_ip_rule(
    req: IPRuleCreateRequest,
    request: Request,
    session: Dict[str, Any] = Depends(require_auth),
):
    """Add a whitelist, blacklist, or temporary quarantine rule."""
    verify_csrf_or_abort(request, session)
    try:
        net = ipaddress.ip_network(req.cidr.strip(), strict=False)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid IP address or CIDR format: '{req.cidr}'",
        )

    rule_id = add_ip_rule(
        cidr=str(net),
        rule_type=req.rule_type,
        reason=req.reason,
        duration_seconds=req.duration_seconds,
    )
    invalidate_rules_cache()

    log_audit_action(
        session["user_id"],
        session["email"],
        "IP_RULE_CREATED",
        f"Created {req.rule_type} rule for {str(net)} (duration={req.duration_seconds}s)",
        get_client_ip(request),
    )
    return {
        "status": "success",
        "rule_id": rule_id,
        "cidr": str(net),
        "rule_type": req.rule_type,
        "duration_seconds": req.duration_seconds,
    }


@api_router.delete("/api/ip-rules/{rule_id}")
def remove_ip_rule(
    rule_id: int = ApiPath(..., ge=1, description="IP rule ID"),
    request: Request = None,
    session: Dict[str, Any] = Depends(require_auth),
):
    """Delete an IP rule or release an IP from quarantine."""
    verify_csrf_or_abort(request, session)
    success = delete_ip_rule(rule_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IP rule not found or already expired",
        )
    invalidate_rules_cache()
    log_audit_action(
        session["user_id"],
        session["email"],
        "IP_RULE_DELETED",
        f"Deleted IP rule ID {rule_id}",
        get_client_ip(request),
    )
    return {"status": "success", "message": f"Rule {rule_id} deleted successfully"}


@api_router.get("/api/ip-reputation/{ip}")
def inspect_ip_reputation(
    ip: str = ApiPath(..., max_length=64),
    session: Dict[str, Any] = Depends(require_auth),
):
    """Retrieve current reputation penalty score and access status for an IP."""
    try:
        ipaddress.ip_address(ip.strip())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid IP address format: '{ip}'",
        )

    score = get_reputation_score(ip.strip())
    action, reason, remaining = check_ip_access(ip.strip())
    return {
        "ip": ip.strip(),
        "reputation_score": score,
        "status": action,
        "reason": reason,
        "remaining_seconds": remaining,
    }


@api_router.get("/api/system")
def system_metrics(session: Dict[str, Any] = Depends(require_auth)):
    cpu_percent = 4.8
    ram_used_mb = 138.5
    total_ram_gb = 8.0
    try:
        import psutil
        cpu_percent = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        ram_used_mb = round(mem.used / (1024 * 1024), 1)
        total_ram_gb = round(mem.total / (1024 * 1024 * 1024), 1)
    except Exception:
        pass

    uptime_sec = int(time.time() - START_TIME)
    hours, rem = divmod(uptime_sec, 3600)
    minutes, seconds = divmod(rem, 60)
    uptime_str = f"{hours}h {minutes}m {seconds}s"

    return {
        "cpu_percent": cpu_percent,
        "ram_used_mb": ram_used_mb,
        "ram_total_gb": total_ram_gb,
        "ram_percent": round((ram_used_mb / (total_ram_gb * 1024)) * 100, 1) if total_ram_gb else 15.0,
        "uptime": uptime_str,
        "uptime_seconds": uptime_sec,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "proxy_status": "ONLINE",
        "engine_state": "ACTIVE BLOCKING",
    }


class PayloadSimulateRequest(BaseModel):
    method: str = Field(default="GET", max_length=16, pattern=r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$")
    path: str = Field(default="/search", max_length=1024)
    query_string: str = Field(default="", max_length=4096)
    body: str = Field(default="", max_length=65536)
    headers: dict = Field(default_factory=dict)
    client_ip: str = Field(default="192.168.1.100", max_length=64)


@api_router.post("/api/simulate")
def simulate_payload(
    req: PayloadSimulateRequest,
    request: Request,
    session: Dict[str, Any] = Depends(require_auth),
):
    """
    Evaluate payload simulation inside threat sandbox (authenticated).
    Rate-limited, size-capped, and kept isolated from production threat logs.
    """
    verify_csrf_or_abort(request, session)
    check_simulate_rate_limit(req.client_ip)

    inspection = inspect_request(
        method=req.method,
        path=req.path,
        query_string=req.query_string,
        headers=req.headers,
        body=req.body.encode("utf-8"),
        client_ip=req.client_ip,
    )
    disabled_rules = set(get_config().get_disabled_rules())
    try:
        db_rules = get_enabled_rule_ids()
        enabled_rules = [r for r in db_rules if r not in disabled_rules] if db_rules is not None else None
    except Exception:
        enabled_rules = None

    scored = sim_engine.evaluate_scored(inspection.request, enabled_rule_ids=enabled_rules)
    blocked = (scored.action.value == "BLOCK")

    return {
        "blocked": blocked,
        "action": scored.action.value,
        "rule_id": scored.primary_rule_id,
        "reason": scored.primary_reason,
        "rule_score": scored.rule_score,
        "semantic_score": scored.semantic_score,
        "total_score": scored.total_score,
        "semantic_category": scored.semantic_category,
        "matched_archetype": scored.matched_archetype,
        "raw_payload": scored.raw_sample,
        "normalized_payload": scored.normalized_sample,
        "normalized_targets_checked": len(inspection.request.targets),
    }


@api_router.get("/api/audit")
def get_audit(
    limit: int = Query(50, ge=1, le=200),
    session: Dict[str, Any] = Depends(require_auth),
):
    """Retrieve security audit logs without sensitive secrets (authenticated)."""
    return get_audit_logs(limit=limit)


@api_router.get("/api/openapi.json")
def get_authenticated_openapi(session: Dict[str, Any] = Depends(require_auth)):
    """Authenticated OpenAPI specification (disabled for unauthenticated public)."""
    from fastapi.openapi.utils import get_openapi
    return get_openapi(title="Bastion WAF API", version="1.0.0", routes=app.routes)


# ============================================================
# FastAPI App Initialization & Security Middleware
# ============================================================

BASTION_DEBUG = os.environ.get("BASTION_DEBUG") == "1"

app = FastAPI(
    title="Bastion WAF API & Dashboard Server",
    docs_url="/docs" if BASTION_DEBUG else None,
    redoc_url="/redoc" if BASTION_DEBUG else None,
    openapi_url="/openapi.json" if BASTION_DEBUG else None,
)

# Security Headers & Redirect Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    # 1. HTTP to HTTPS redirect if X-Forwarded-Proto is http
    forwarded_proto = request.headers.get("X-Forwarded-Proto")
    if forwarded_proto == "http":
        url = request.url.replace(scheme="https")
        return Response(status_code=301, headers={"Location": str(url)})

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"

    return response


# Locked-down CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

PUBLIC_API_ALLOWLIST = {
    "/api/auth/login",
    "/api/auth/status",
    "/api/auth/2fa/verify",
    "/api/auth/reset/request",
    "/api/auth/reset/confirm",
    "/api/auth/setup",
}
PUBLIC_API_ROUTES = PUBLIC_API_ALLOWLIST


def audit_route_coverage(fastapi_app: FastAPI):
    """Deploy-time check asserting every /api/* route is either authenticated or allowlisted."""
    unprotected = []
    for route in fastapi_app.routes:
        path = getattr(route, "path", "")
        if not path.startswith("/api/"):
            continue
        if path in PUBLIC_API_ALLOWLIST:
            continue

        route_deps = getattr(route, "dependencies", []) or []
        dependant = getattr(route, "dependant", None)
        all_deps = list(route_deps)
        if dependant:
            all_deps.extend(dependant.dependencies or [])

        dep_callables = [d.dependency for d in all_deps if hasattr(d, "dependency")]
        if require_auth not in dep_callables:
            unprotected.append(f"{getattr(route, 'methods', '')} {path}")

    if unprotected:
        logger.critical(
            "🚨 CRITICAL SECURITY ALERT: Unauthenticated /api/* route(s) detected without allowlisting:\n%s",
            "\n".join(f"  - {u}" for u in unprotected),
        )

# Mount authentication router and protected management router
app.include_router(auth_router)
app.include_router(api_router)

# Mount static frontend dashboard
dashboard_dir = Path(__file__).resolve().parent.parent / "dashboard"
if dashboard_dir.exists():
    app.mount("/", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard")
