import asyncio
import json
from pathlib import Path
import tempfile
from fastapi.testclient import TestClient

from bastion.core.config import BastionConfig, OpenSearchConfig, OpenSearchBufferConfig, load_config, reset_config
from bastion.core.proxy import app as proxy_app
from bastion.telemetry.opensearch_client import OpenSearchTelemetryLogger, get_telemetry_logger


def test_proxy_streams_to_opensearch_fallback():
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        temp_log = Path(f.name)

    reset_config()
    try:
        # Configure OpenSearch fallback log to temp file
        cfg = BastionConfig(
            opensearch=OpenSearchConfig(
                enabled=True,
                hosts=["http://127.0.0.1:59999"],
                buffer=OpenSearchBufferConfig(
                    batch_size=1,
                    flush_interval_seconds=0.1,
                    fallback_log_path=str(temp_log),
                ),
            )
        )

        logger = get_telemetry_logger()
        logger.config = cfg
        logger.os_cfg = cfg.opensearch
        logger.enabled = cfg.opensearch.enabled
        logger.hosts = cfg.opensearch.hosts
        logger.fallback_path = temp_log

        # Clear any leftover items in the singleton queue
        while not logger._queue.empty():
            try:
                logger._queue.get_nowait()
            except Exception:
                break

        client = TestClient(proxy_app)

        # 1. Send clean user request through proxy
        res_clean = client.get("/welcome")
        assert res_clean.status_code == 200

        # 2. Send malicious attack request (SQLi)
        res_attack = client.get("/search?q=%27+OR+%271%27%3D%271")
        assert res_attack.status_code == 403
        assert res_attack.json()["blocked"] is True

        # Flush pending telemetry
        async def _flush():
            await logger._flush_all_pending()
        asyncio.run(_flush())

        # Verify fallback JSONL contains both events in ECS format
        assert temp_log.is_file()
        with open(temp_log, "r", encoding="utf-8") as f:
            events = [json.loads(line) for line in f if line.strip()]

        assert len(events) >= 2

        # Verify the attack event structure for /search
        attack_event = next((e for e in events if e.get("url", {}).get("path") == "/search"), None)
        assert attack_event is not None
        assert attack_event["http"]["response"]["status_code"] == 403
        assert attack_event["waf"]["rule_id"] == "942100"
        assert attack_event["waf"]["scores"]["total"] > 5.0
        assert attack_event["waf"]["payload"]["raw"] != ""

    finally:
        reset_config()
        if temp_log.is_file():
            temp_log.unlink()
