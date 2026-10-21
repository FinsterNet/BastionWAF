"""
High-Performance WAF Reverse Proxy with Adaptive Risk-Based Slider CAPTCHA Challenge,
dynamic upstream routing, live telemetry logging, and defense bypass support.
"""

from contextlib import asynccontextmanager
import json
import logging
import os
from pathlib import Path
from typing import Optional, Tuple
import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from api.auth import auth_router, get_allowed_origins, require_auth
from api.server import api_router
from .config import get_config
from .engine import Engine
from .inspector import inspect_request
from .scorer import ActionDecision
from ..challenge.captcha import (
    CLEARANCE_COOKIE_NAME,
    generate_clearance_cookie,
    verify_challenge_solution,
    verify_clearance_cookie,
)
from ..challenge.evaluator import RiskDecision, RiskEvaluator
from ..challenge.page import render_captcha_page
from ..telemetry.ecs_formatter import format_ecs_event
from ..telemetry.opensearch_client import get_telemetry_logger
from database.db import get_enabled_rule_ids, get_sites, init_db, log_event

logger = logging.getLogger(__name__)

HOP_BY_HOP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


PUBLIC_API_ALLOWLIST = {
    "/api/auth/login",
    "/api/auth/status",
    "/api/auth/2fa/verify",
    "/api/auth/reset/request",
    "/api/auth/reset/confirm",
    "/api/auth/setup",
}


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    audit_route_coverage(app)
    telemetry = get_telemetry_logger()
    await telemetry.start()
    yield
    await telemetry.stop()


BASTION_DEBUG = os.environ.get("BASTION_DEBUG") == "1"
app = FastAPI(
    title="Bastion WAF Reverse Proxy & Challenge Gateway",
    lifespan=lifespan,
    docs_url="/docs" if BASTION_DEBUG else None,
    redoc_url="/redoc" if BASTION_DEBUG else None,
    openapi_url="/openapi.json" if BASTION_DEBUG else None,
)

# Security Headers & Redirect Middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # 1. HTTP to HTTPS redirect if X-Forwarded-Proto is http
    forwarded_proto = request.headers.get("X-Forwarded-Proto")
    if forwarded_proto == "http":
        url = request.url.replace(scheme="https")
        return Response(status_code=301, headers={"Location": str(url)})

    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
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
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = Engine()
app.include_router(auth_router)
app.include_router(api_router)

dashboard_dir = Path(__file__).resolve().parent.parent.parent / "dashboard"


def resolve_upstream_and_mode(host: str) -> Tuple[Optional[str], bool]:
    """Resolve upstream target and defense mode for the given host from config with DB fallback."""
    target, defense = get_config().resolve_upstream(host)
    if target:
        return target, defense
    try:
        sites = get_sites()
        for site in sites:
            domain = site["domain"].lower()
            current_host = host.lower()
            if domain in current_host or current_host in domain:
                target = site["upstream"] if site["upstream"].startswith("http") else f"http://{site['upstream']}"
                return target, bool(site.get("defense_mode", True))
    except Exception:
        pass
    return None, True


async def forward_upstream(
    request: Request,
    upstream_target: str,
    target_path: str,
    body: bytes,
    headers: dict,
    query_string: str,
    client_ip: str,
) -> Response:
    """Forward an inspected request to the configured upstream server."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            url = f"{upstream_target.rstrip('/')}{target_path}"
            if query_string:
                url += f"?{query_string}"

            fwd_headers = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
            fwd_headers["X-Forwarded-For"] = client_ip
            fwd_headers["X-Forwarded-Proto"] = request.url.scheme

            resp = await client.request(
                method=request.method,
                url=url,
                headers=fwd_headers,
                content=body,
                follow_redirects=False,
            )

            resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
            return Response(content=resp.content, status_code=resp.status_code, headers=resp_headers)
    except httpx.ConnectError:
        return JSONResponse(
            {
                "error": "Upstream unreachable",
                "upstream": upstream_target,
                "message": f"Could not connect to configured upstream target: {upstream_target}",
                "status": 502,
            },
            status_code=502,
        )
    except Exception as e:
        return JSONResponse(
            {
                "error": "Upstream proxy error",
                "upstream": upstream_target,
                "message": str(e),
                "status": 502,
            },
            status_code=502,
        )


async def run_waf_inspection(
    request: Request,
    target_path: str,
    body: bytes = b"",
) -> Tuple[Optional[Response], Any, bool, str, str, Optional[str]]:
    """
    Runs multi-stage WAF inspection on an incoming request.
    Returns (blocking_response, scored, defense_active, client_ip, host_header, upstream_target).
    If blocking_response is not None, the caller must return it immediately (403 Block or CAPTCHA).
    """
    query_string = request.url.query
    headers = dict(request.headers)
    cookies = dict(request.cookies)
    client_ip = request.client.host if request.client else "127.0.0.1"
    host_header = request.headers.get("host", "127.0.0.1:8080")

    upstream_target, defense_active = resolve_upstream_and_mode(host_header)

    inspection = inspect_request(
        method=request.method,
        path=target_path,
        query_string=query_string,
        headers=headers,
        body=body,
        client_ip=client_ip,
    )

    disabled_rules = set(get_config().get_disabled_rules())
    try:
        db_rules = get_enabled_rule_ids()
        if db_rules is not None:
            enabled_rules = [r for r in db_rules if r not in disabled_rules]
        else:
            enabled_rules = None
    except Exception:
        enabled_rules = None

    scored = engine.evaluate_scored(inspection.request, enabled_rule_ids=enabled_rules)

    has_clearance = False
    clearance_token = cookies.get(CLEARANCE_COOKIE_NAME, "")
    if clearance_token:
        has_clearance = verify_clearance_cookie(clearance_token, client_ip)

    effective_action = scored.action
    if effective_action == ActionDecision.CHALLENGE and has_clearance:
        effective_action = ActionDecision.ALLOW

    payload_sample = scored.raw_sample or (query_string if query_string else target_path)

    def send_telemetry(status_code: int, blocked: bool, action: str, rule_id: str, reason: str):
        get_telemetry_logger().enqueue(
            format_ecs_event(
                client_ip=client_ip,
                method=request.method,
                path=target_path,
                query_string=query_string,
                host=host_header,
                status_code=status_code,
                blocked=blocked,
                action=action,
                rule_id=rule_id,
                reason=reason,
                rule_score=scored.rule_score,
                semantic_score=scored.semantic_score,
                total_score=scored.total_score,
                raw_payload=scored.raw_sample,
                normalized_payload=scored.normalized_sample,
                user_agent=headers.get("user-agent", ""),
            )
        )

    if not defense_active:
        log_event(
            client_ip=client_ip,
            method=request.method,
            path=target_path,
            blocked=False,
            rule_id=scored.primary_rule_id,
            reason="Bypass Mode Active",
            action="Bypassed Allowed",
            payload_snippet=payload_sample[:500],
            rule_score=scored.rule_score,
            semantic_score=scored.semantic_score,
            total_score=scored.total_score,
            raw_payload=scored.raw_sample,
            normalized_payload=scored.normalized_sample,
        )
        send_telemetry(200, False, "Bypassed Allowed", scored.primary_rule_id, "Bypass Mode Active")
        return None, scored, defense_active, client_ip, host_header, upstream_target

    if effective_action == ActionDecision.BLOCK:
        log_event(
            client_ip=client_ip,
            method=request.method,
            path=target_path,
            blocked=True,
            rule_id=scored.primary_rule_id,
            reason=scored.primary_reason,
            action="403 Blocked",
            payload_snippet=payload_sample[:500],
            rule_score=scored.rule_score,
            semantic_score=scored.semantic_score,
            total_score=scored.total_score,
            raw_payload=scored.raw_sample,
            normalized_payload=scored.normalized_sample,
        )
        send_telemetry(403, True, "403 Blocked", scored.primary_rule_id, scored.primary_reason)
        return (
            Response(
                content=f'{{"blocked": true, "rule": "{scored.primary_rule_id}", "reason": "{scored.primary_reason}", "total_score": {scored.total_score}, "rule_score": {scored.rule_score}, "semantic_score": {scored.semantic_score}, "status": 403}}',
                status_code=403,
                media_type="application/json",
            ),
            scored,
            defense_active,
            client_ip,
            host_header,
            upstream_target,
        )

    if effective_action == ActionDecision.CHALLENGE:
        log_event(
            client_ip=client_ip,
            method=request.method,
            path=target_path,
            blocked=False,
            rule_id=scored.primary_rule_id or "ANOMALY_CHALLENGE",
            reason=scored.primary_reason,
            action="CAPTCHA Challenged",
            payload_snippet=payload_sample[:500],
            rule_score=scored.rule_score,
            semantic_score=scored.semantic_score,
            total_score=scored.total_score,
            raw_payload=scored.raw_sample,
            normalized_payload=scored.normalized_sample,
        )
        send_telemetry(200, False, "CAPTCHA Challenged", scored.primary_rule_id or "ANOMALY_CHALLENGE", scored.primary_reason)
        captcha_html = render_captcha_page(client_ip=client_ip, target_path=target_path, reason=scored.primary_reason)
        return (
            HTMLResponse(content=captcha_html, status_code=200),
            scored,
            defense_active,
            client_ip,
            host_header,
            upstream_target,
        )

    # Allowed
    log_event(
        client_ip=client_ip,
        method=request.method,
        path=target_path,
        blocked=False,
        rule_id="",
        reason="Clean Request",
        action="200 Allowed",
        payload_snippet=payload_sample[:500],
        rule_score=scored.rule_score,
        semantic_score=scored.semantic_score,
        total_score=scored.total_score,
        raw_payload=scored.raw_sample,
        normalized_payload=scored.normalized_sample,
    )
    send_telemetry(200, False, "200 Allowed", "", "Clean Request")
    return None, scored, defense_active, client_ip, host_header, upstream_target


if dashboard_dir.is_dir():
    app.mount("/dashboard", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard_ui")

    @app.get("/")
    @app.get("/login")
    async def root_dashboard_view(request: Request):
        target_path = "/" if request.url.path == "/" else "/login"
        block_resp, scored, defense_active, client_ip, host_header, upstream_target = await run_waf_inspection(
            request, target_path, body=b""
        )
        if block_resp is not None:
            return block_resp

        # If an upstream site is configured for this domain on root, proxy to it
        if upstream_target and target_path == "/":
            headers = dict(request.headers)
            return await forward_upstream(
                request, upstream_target, "/", b"", headers, request.url.query, client_ip
            )

        index_path = dashboard_dir / "index.html"
        if index_path.is_file():
            return FileResponse(str(index_path))
        return JSONResponse({"status": "running", "service": "bastion-waf"})

    @app.get("/styles.css")
    async def serve_root_styles(request: Request):
        block_resp, *_ = await run_waf_inspection(request, "/styles.css", body=b"")
        if block_resp is not None:
            return block_resp
        return FileResponse(str(dashboard_dir / "styles.css"), media_type="text/css")

    @app.get("/app.js")
    async def serve_root_app_js(request: Request):
        block_resp, *_ = await run_waf_inspection(request, "/app.js", body=b"")
        if block_resp is not None:
            return block_resp
        return FileResponse(str(dashboard_dir / "app.js"), media_type="application/javascript")

    @app.get("/logo.svg")
    async def serve_root_logo(request: Request):
        block_resp, *_ = await run_waf_inspection(request, "/logo.svg", body=b"")
        if block_resp is not None:
            return block_resp
        return FileResponse(str(dashboard_dir / "logo.svg"), media_type="image/svg+xml")


class CaptchaVerifyPayload(BaseModel):
    token: str
    user_x: float
    duration_ms: float = 500.0
    trajectory_count: int = 5


@app.post("/__bastion_captcha_verify__")
async def verify_captcha_endpoint(request: Request, payload: CaptchaVerifyPayload):
    """
    Verification API endpoint called by the interactive Slider CAPTCHA page.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"

    success, msg = verify_challenge_solution(
        token=payload.token,
        user_x=payload.user_x,
        duration_ms=payload.duration_ms,
        trajectory_count=payload.trajectory_count,
    )

    if not success:
        log_event(
            client_ip=client_ip,
            method="POST",
            path="/__bastion_captcha_verify__",
            blocked=True,
            rule_id="CHALLENGE_FAILED",
            reason=f"CAPTCHA verification failed: {msg}",
            action="Challenge Failed",
            payload_snippet=f"Offset: {payload.user_x}, Duration: {payload.duration_ms}ms",
        )
        get_telemetry_logger().enqueue(
            format_ecs_event(
                client_ip=client_ip,
                method="POST",
                path="/__bastion_captcha_verify__",
                status_code=400,
                blocked=True,
                action="Challenge Failed",
                rule_id="CHALLENGE_FAILED",
                reason=f"CAPTCHA verification failed: {msg}",
                raw_payload=f"Offset: {payload.user_x}, Duration: {payload.duration_ms}ms",
            )
        )
        return JSONResponse(status_code=400, content={"status": "error", "message": msg})

    # Issue clearance cookie
    clearance_cookie = generate_clearance_cookie(client_ip)

    log_event(
        client_ip=client_ip,
        method="POST",
        path="/__bastion_captcha_verify__",
        blocked=False,
        rule_id="CHALLENGE_SOLVED",
        reason="Interactive Slider CAPTCHA solved by human user",
        action="Clearance Granted",
        payload_snippet=f"Valid slide duration: {payload.duration_ms:.0f}ms",
    )
    get_telemetry_logger().enqueue(
        format_ecs_event(
            client_ip=client_ip,
            method="POST",
            path="/__bastion_captcha_verify__",
            status_code=200,
            blocked=False,
            action="Clearance Granted",
            rule_id="CHALLENGE_SOLVED",
            reason="Interactive Slider CAPTCHA solved by human user",
            raw_payload=f"Valid slide duration: {payload.duration_ms:.0f}ms",
        )
    )

    res = JSONResponse(content={"status": "ok", "message": "Verification successful"})
    res.set_cookie(
        key=CLEARANCE_COOKIE_NAME,
        value=clearance_cookie,
        max_age=900,
        path="/",
        httponly=True,
        samesite="lax",
    )
    return res


@app.get("/healthz")
@app.get("/health")
async def health_check():
    """Cloud deployment health check probe endpoint for Render, Kubernetes, and load balancers."""
    return JSONResponse(
        status_code=200,
        content={"status": "healthy", "service": "bastion-waf", "mode": "active"},
    )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def waf_proxy(request: Request, path: str):
    # Skip proxying the internal verification endpoint
    if path == "__bastion_captcha_verify__":
        return JSONResponse({"status": "error", "message": "Use POST method"}, status_code=405)

    # Intercept public API docs routes to prevent upstream leakage
    norm_path = path.strip("/").lower()
    if norm_path in ("docs", "redoc", "openapi.json"):
        return JSONResponse({"detail": "Not Found"}, status_code=404)

    body = await request.body()
    target_path = "/" + path if not path.startswith("/") else path

    block_resp, scored, defense_active, client_ip, host_header, upstream_target = await run_waf_inspection(
        request, target_path, body=body
    )
    if block_resp is not None:
        return block_resp

    # Forward to configured upstream site if matched
    if upstream_target:
        headers = dict(request.headers)
        return await forward_upstream(
            request, upstream_target, target_path, body, headers, request.url.query, client_ip
        )

    # Standalone Inspection Echo Service (Independent WAF Gateway when no upstream site is configured)
    try:
        body_text = body.decode("utf-8", errors="replace") if body else None
    except Exception:
        body_text = None

    filtered_headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}

    echo_payload = {
        "status": "allowed",
        "waf": "Bastion Next-Gen WAF Gateway",
        "mode": "ACTIVE BLOCKING" if defense_active else "BYPASS",
        "client_ip": client_ip,
        "method": request.method,
        "path": target_path,
        "query_params": dict(request.query_params),
        "headers": filtered_headers,
        "body_received": body_text[:1000] if body_text else None,
        "inspection": {
            "verdict": "CLEAN",
            "anomaly_score": scored.total_score,
            "rule_score": scored.rule_score,
            "semantic_score": scored.semantic_score,
            "threat_category": scored.semantic_category or "None",
            "message": "Request inspected and passed all active semantic and OWASP security rules.",
        },
    }
    return JSONResponse(content=echo_payload, status_code=200)
