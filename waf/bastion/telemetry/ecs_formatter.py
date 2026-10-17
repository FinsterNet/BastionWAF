"""
Elastic Common Schema (ECS) Event Formatter for BastionWAF.
Transforms WAF inspection, scoring, and proxy events into standard ECS-compliant JSON documents.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional


def format_ecs_event(
    client_ip: str,
    method: str,
    path: str,
    query_string: str = "",
    host: str = "",
    status_code: int = 200,
    blocked: bool = False,
    action: str = "200 Allowed",
    rule_id: str = "",
    reason: str = "",
    rule_score: float = 0.0,
    semantic_score: float = 0.0,
    total_score: float = 0.0,
    raw_payload: str = "",
    normalized_payload: str = "",
    user_agent: str = "",
) -> Dict[str, Any]:
    """
    Format a WAF security event into an ECS-compliant dictionary suitable for OpenSearch indexing.
    """
    now = datetime.now(timezone.utc).isoformat()

    # Determine event outcome and severity category
    outcome = "failure" if blocked else "success"
    if total_score >= 8.0:
        severity_label = "critical"
        severity_num = 10
    elif total_score >= 5.0:
        severity_label = "high"
        severity_num = 7
    elif total_score >= 2.5:
        severity_label = "medium"
        severity_num = 5
    elif total_score > 0.0:
        severity_label = "low"
        severity_num = 2
    else:
        severity_label = "informational"
        severity_num = 0

    event_types = ["access"]
    if blocked:
        event_types.append("denied")
    else:
        event_types.append("allowed")

    ecs_doc: Dict[str, Any] = {
        "@timestamp": now,
        "ecs": {
            "version": "8.11.0",
        },
        "event": {
            "kind": "alert" if blocked else "event",
            "category": ["network", "web"],
            "type": event_types,
            "action": action,
            "outcome": outcome,
            "severity": severity_num,
            "severity_label": severity_label,
            "module": "bastion_waf",
        },
        "client": {
            "ip": client_ip or "127.0.0.1",
        },
        "http": {
            "request": {
                "method": method.upper(),
            },
            "response": {
                "status_code": status_code,
            },
        },
        "url": {
            "path": path,
            "query": query_string,
        },
        "waf": {
            "blocked": blocked,
            "action": action,
            "rule_id": rule_id or "NONE",
            "reason": reason or "Clean Request",
            "scores": {
                "total": round(float(total_score), 2),
                "rule": round(float(rule_score), 2),
                "semantic": round(float(semantic_score), 2),
            },
            "payload": {
                "raw": raw_payload[:4000] if raw_payload else "",
                "normalized": normalized_payload[:4000] if normalized_payload else "",
                "snippet": (raw_payload or query_string or path)[:500],
            },
        },
    }

    if host:
        ecs_doc["host"] = {"hostname": host}

    if user_agent:
        ecs_doc["user_agent"] = {"original": user_agent}

    return ecs_doc
