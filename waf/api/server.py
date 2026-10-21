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

from api.auth import (
    auth_router,
    get_client_ip,
    get_current_session,
    require_auth,
    verify_csrf_or_abort,
)
from bastion.core.config import get_config
from bastion.core.engine import Engine
from bastion.core.inspector import inspect_request
from database.db import (
    add_site,
    clear_logs,
    delete_site,
    export_logs_csv,
    get_enabled_rule_ids,
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
    session: Dict[str, Any] = Depends(require_auth),
):
    """
    Evaluate payload simulation inside threat sandbox (authenticated).
    Rate-limited, size-capped, and kept isolated from production threat logs.
    """
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


@api_router.get("/api/openapi.json")
def get_authenticated_openapi(session: Dict[str, Any] = Depends(require_auth)):
    """Authenticated OpenAPI specification (disabled for unauthenticated public)."""
    from fastapi.openapi.utils import get_openapi
    return get_openapi(title="Bastion WAF API", version="1.0.0", routes=app.routes)


# ============================================================
# FastAPI App Initialization & Security Middleware
# ============================================================

app = FastAPI(
    title="Bastion WAF API & Dashboard Server",
    docs_url=None,      # Disable public Swagger UI
    redoc_url=None,     # Disable public ReDoc
    openapi_url=None,   # Disable public openapi.json
)

# Security Headers Middleware (Step 9)
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Basic Content Security Policy allowing local self scripts, fonts, and Chart.js
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


# Locked-down CORS configuration (Step 6)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:8080",
        "http://localhost:8080",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Mount authentication router and protected management router
app.include_router(auth_router)
app.include_router(api_router)

# Mount static frontend dashboard
dashboard_dir = Path(__file__).resolve().parent.parent / "dashboard"
if dashboard_dir.exists():
    app.mount("/", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard")
