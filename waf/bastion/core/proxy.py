"""
High-Performance WAF Reverse Proxy with Adaptive Risk-Based Slider CAPTCHA Challenge,
dynamic upstream routing, live telemetry logging, and defense bypass support.
"""

from contextlib import asynccontextmanager
import json
import logging
from pathlib import Path
from typing import Optional, Tuple
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Bastion WAF Reverse Proxy & Challenge Gateway", lifespan=lifespan)
engine = Engine()


class CaptchaVerifyPayload(BaseModel):
    token: str
    user_x: float
    duration_ms: float = 500.0
    trajectory_count: int = 5


def resolve_upstream_and_mode(host: str) -> Tuple[Optional[str], bool]:
    """Resolve upstream target and defense mode for the given host."""
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


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def waf_proxy(request: Request, path: str):
    # Skip proxying the internal verification endpoint
    if path == "__bastion_captcha_verify__":
        return JSONResponse({"status": "error", "message": "Use POST method"}, status_code=405)

    body = await request.body()
    query_string = request.url.query
    headers = dict(request.headers)
    cookies = dict(request.cookies)
    client_ip = request.client.host if request.client else "127.0.0.1"
    host_header = request.headers.get("host", "127.0.0.1:8080")

    target_path = "/" + path if not path.startswith("/") else path
    upstream_target, defense_active = resolve_upstream_and_mode(host_header)

    # 1. Inspect request against WAF rules
    inspection = inspect_request(
        method=request.method,
        path=target_path,
        query_string=query_string,
        headers=headers,
        body=body,
        client_ip=client_ip,
    )

    try:
        enabled_rules = get_enabled_rule_ids()
    except Exception:
        enabled_rules = None

    # 1. Multi-Stage Evaluation (Rules + Semantic Embeddings + Combined Scorer)
    scored = engine.evaluate_scored(inspection.request, enabled_rule_ids=enabled_rules)

    has_clearance = False
    clearance_token = cookies.get(CLEARANCE_COOKIE_NAME, "")
    if clearance_token:
        has_clearance = verify_clearance_cookie(clearance_token, client_ip)

    # 2. Risk & Adaptive Action Decision
    effective_action = scored.action
    if effective_action == ActionDecision.CHALLENGE and has_clearance:
        effective_action = ActionDecision.ALLOW

    payload_sample = scored.raw_sample or (query_string if query_string else target_path)

    # If defense mode is disabled for this site (Bypass Mode), allow all
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
    elif effective_action == ActionDecision.BLOCK:
        # Tier 1: Confirmed Threat / High Anomaly -> HTTP 403 Forbidden
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
        return Response(
            content=f'{{"blocked": true, "rule": "{scored.primary_rule_id}", "reason": "{scored.primary_reason}", "total_score": {scored.total_score}, "rule_score": {scored.rule_score}, "semantic_score": {scored.semantic_score}, "status": 403}}',
            status_code=403,
            media_type="application/json",
        )
    elif effective_action == ActionDecision.CHALLENGE:
        # Tier 2: Suspicious Anomaly / Medium Score -> Serve Interactive Slider CAPTCHA
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
        captcha_html = render_captcha_page(client_ip=client_ip, target_path=target_path, reason=scored.primary_reason)
        return HTMLResponse(content=captcha_html, status_code=200)
    else:
        # Tier 3: Clean / Verified Human Session -> Forward to Upstream
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

    # If an upstream site is configured for this domain, proxy to it
    if upstream_target:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                url = f"{upstream_target.rstrip('/')}{target_path}"
                if query_string:
                    url += f"?{query_string}"

                # Forward headers, excluding hop-by-hop
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

    # Standalone Inspection Echo Service (Independent WAF Gateway when no upstream site is configured)
    try:
        body_text = body.decode("utf-8", errors="replace") if body else None
    except Exception:
        body_text = None

    filtered_headers = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}

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
            "targets_checked": len(inspection.request.targets),
            "threat_category": scored.semantic_category or "None",
            "message": "Request inspected and passed all active semantic and OWASP security rules.",
        },
    }
    return JSONResponse(content=echo_payload, status_code=200)
