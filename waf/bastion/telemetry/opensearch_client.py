"""
High-Performance Asynchronous OpenSearch Security Telemetry Exporter.
Buffers WAF events non-blockingly and streams batches using the OpenSearch _bulk API.
Includes automatic fallback to local JSONL if OpenSearch is offline or disabled.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx

from ..core.config import BastionConfig, get_config

logger = logging.getLogger("bastion.telemetry.opensearch")


class OpenSearchTelemetryLogger:
    def __init__(self, config: Optional[BastionConfig] = None):
        self.config = config or get_config()
        self.os_cfg = self.config.opensearch
        self.enabled = self.os_cfg.enabled
        self.hosts = self.os_cfg.hosts
        self.index_prefix = self.os_cfg.index_prefix
        self.batch_size = self.os_cfg.buffer.batch_size
        self.flush_interval = self.os_cfg.buffer.flush_interval_seconds
        self.fallback_path = Path(self.os_cfg.buffer.fallback_log_path)

        self._queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=10000)
        self._worker_task: Optional[asyncio.Task] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._running = False

    def _get_target_url(self) -> str:
        base_host = self.hosts[0].rstrip("/") if self.hosts else "http://127.0.0.1:9200"
        return f"{base_host}/_bulk"

    def _get_daily_index(self) -> str:
        today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        return f"{self.index_prefix}-{today}"

    async def start(self):
        """Start the background bulk exporter worker."""
        if self._running:
            return
        self._running = True

        # Ensure fallback log directory exists
        self.fallback_path.parent.mkdir(parents=True, exist_ok=True)

        auth = None
        if self.os_cfg.auth.username and self.os_cfg.auth.password:
            auth = (self.os_cfg.auth.username, self.os_cfg.auth.password)

        self._client = httpx.AsyncClient(
            verify=self.os_cfg.ssl_verify,
            auth=auth,
            timeout=5.0,
        )

        self._worker_task = asyncio.create_task(self._flush_loop(), name="opensearch-exporter")
        logger.info("BastionWAF OpenSearch Telemetry Logger initialized.")

    async def stop(self):
        """Flush remaining items in the queue and cleanly close the exporter."""
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None

        await self._flush_all_pending()

        if self._client:
            await self._client.aclose()
            self._client = None

    def enqueue(self, event: Dict[str, Any]):
        """
        Non-blocking enqueue called by the WAF proxy on every request.
        Zero latency overhead for proxy visitors.
        """
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            # Fallback directly to file if buffer is saturated
            self._write_fallback([event])

    async def _flush_loop(self):
        """Background loop reading from queue and periodically flushing bulk batches."""
        batch: List[Dict[str, Any]] = []
        last_flush_time = asyncio.get_event_loop().time()

        while self._running:
            try:
                timeout = max(0.1, self.flush_interval - (asyncio.get_event_loop().time() - last_flush_time))
                try:
                    event = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                    batch.append(event)
                    self._queue.task_done()
                except asyncio.TimeoutError:
                    pass

                now = asyncio.get_event_loop().time()
                should_flush = len(batch) >= self.batch_size or (batch and (now - last_flush_time) >= self.flush_interval)

                if should_flush and batch:
                    to_flush = batch
                    batch = []
                    await self._ship_bulk(to_flush)
                    last_flush_time = asyncio.get_event_loop().time()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in OpenSearch flush loop: {e}")
                await asyncio.sleep(1.0)

        if batch:
            await self._ship_bulk(batch)

    async def _flush_all_pending(self):
        """Drain everything remaining in the queue."""
        batch: List[Dict[str, Any]] = []
        while not self._queue.empty():
            try:
                batch.append(self._queue.get_nowait())
                self._queue.task_done()
            except asyncio.QueueEmpty:
                break
        if batch:
            await self._ship_bulk(batch)

    async def _ship_bulk(self, events: List[Dict[str, Any]]):
        """Send NDJSON bulk request to OpenSearch, falling back to JSONL file on failure."""
        if not events:
            return

        if not self.enabled:
            self._write_fallback(events)
            return

        index_name = self._get_daily_index()
        # Build OpenSearch NDJSON bulk format
        ndjson_lines: List[str] = []
        for ev in events:
            ndjson_lines.append(json.dumps({"index": {"_index": index_name}}))
            ndjson_lines.append(json.dumps(ev))
        payload = "\n".join(ndjson_lines) + "\n"

        target_url = self._get_target_url()
        try:
            if not self._client:
                raise RuntimeError("HTTP client not initialized")

            resp = await self._client.post(
                target_url,
                content=payload,
                headers={"Content-Type": "application/x-ndjson"},
            )
            if resp.status_code not in (200, 201):
                logger.warning(f"OpenSearch bulk ingest error {resp.status_code}: {resp.text[:200]}")
                self._write_fallback(events)
        except Exception as ex:
            # Resilient fallback: write to local file without crashing
            logger.debug(f"OpenSearch unreachable ({ex}), writing {len(events)} events to fallback log.")
            self._write_fallback(events)

    def _write_fallback(self, events: List[Dict[str, Any]]):
        """Write events locally so no security logs are lost."""
        try:
            self.fallback_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.fallback_path, "a", encoding="utf-8") as f:
                for ev in events:
                    f.write(json.dumps(ev) + "\n")
        except Exception as e:
            logger.error(f"Failed to write to fallback log {self.fallback_path}: {e}")


_TELEMETRY_LOGGER: Optional[OpenSearchTelemetryLogger] = None


def get_telemetry_logger() -> OpenSearchTelemetryLogger:
    """Singleton getter for the OpenSearch telemetry logger."""
    global _TELEMETRY_LOGGER
    if _TELEMETRY_LOGGER is None:
        _TELEMETRY_LOGGER = OpenSearchTelemetryLogger()
    return _TELEMETRY_LOGGER
