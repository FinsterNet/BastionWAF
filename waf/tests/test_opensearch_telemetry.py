import asyncio
import json
from pathlib import Path
import tempfile
import pytest

from bastion.core.config import BastionConfig, OpenSearchConfig, OpenSearchBufferConfig
from bastion.telemetry.ecs_formatter import format_ecs_event
from bastion.telemetry.opensearch_client import OpenSearchTelemetryLogger


def test_ecs_formatter_structure():
    doc = format_ecs_event(
        client_ip="192.168.1.100",
        method="POST",
        path="/api/login",
        query_string="user=admin' OR 1=1--",
        host="app.example.com",
        status_code=403,
        blocked=True,
        action="403 Blocked",
        rule_id="942100",
        reason="SQL Injection detected",
        rule_score=6.0,
        semantic_score=7.5,
        total_score=6.6,
        raw_payload="admin' OR 1=1--",
        normalized_payload="admin' or 1=1--",
        user_agent="sqlmap/1.5",
    )

    # Standard ECS fields
    assert "@timestamp" in doc
    assert doc["ecs"]["version"] == "8.11.0"
    assert doc["event"]["action"] == "403 Blocked"
    assert doc["event"]["outcome"] == "failure"
    assert doc["event"]["severity_label"] == "high"
    assert "denied" in doc["event"]["type"]
    assert doc["client"]["ip"] == "192.168.1.100"
    assert doc["http"]["request"]["method"] == "POST"
    assert doc["http"]["response"]["status_code"] == 403
    assert doc["url"]["path"] == "/api/login"
    assert doc["url"]["query"] == "user=admin' OR 1=1--"
    assert doc["host"]["hostname"] == "app.example.com"
    assert doc["user_agent"]["original"] == "sqlmap/1.5"

    # WAF specific payload and scores
    assert doc["waf"]["blocked"] is True
    assert doc["waf"]["rule_id"] == "942100"
    assert doc["waf"]["scores"]["total"] == 6.6
    assert doc["waf"]["scores"]["rule"] == 6.0
    assert doc["waf"]["scores"]["semantic"] == 7.5
    assert doc["waf"]["payload"]["raw"] == "admin' OR 1=1--"
    assert doc["waf"]["payload"]["normalized"] == "admin' or 1=1--"


def test_opensearch_logger_fallback_buffering():
    async def _run_test():
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            temp_log = Path(f.name)

        try:
            cfg = BastionConfig(
                opensearch=OpenSearchConfig(
                    enabled=True,
                    hosts=["http://127.0.0.1:59999"],  # Closed port
                    buffer=OpenSearchBufferConfig(
                        batch_size=2,
                        flush_interval_seconds=0.5,
                        fallback_log_path=str(temp_log),
                    ),
                )
            )

            logger = OpenSearchTelemetryLogger(config=cfg)
            await logger.start()

            event1 = format_ecs_event(
                client_ip="10.0.0.1",
                method="GET",
                path="/test1",
                blocked=False,
                action="200 Allowed",
            )
            event2 = format_ecs_event(
                client_ip="10.0.0.2",
                method="GET",
                path="/test2",
                blocked=True,
                action="403 Blocked",
                rule_id="942100",
                total_score=8.0,
            )

            # Enqueue non-blockingly
            logger.enqueue(event1)
            logger.enqueue(event2)

            # Stop logger (triggers pending flush)
            await logger.stop()

            # Check fallback JSONL file
            assert temp_log.is_file()
            with open(temp_log, "r", encoding="utf-8") as f:
                lines = [json.loads(line) for line in f if line.strip()]

            assert len(lines) == 2
            assert lines[0]["url"]["path"] == "/test1"
            assert lines[0]["event"]["action"] == "200 Allowed"
            assert lines[1]["url"]["path"] == "/test2"
            assert lines[1]["waf"]["rule_id"] == "942100"
            assert lines[1]["waf"]["blocked"] is True

        finally:
            if temp_log.is_file():
                temp_log.unlink()

    asyncio.run(_run_test())
