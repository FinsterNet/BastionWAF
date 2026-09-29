"""
Sliding-Window CC Flood & Rate Limiting rule (Bot Protection 960300).
Mitigates HTTP floods, brute-force surges, and Layer 7 Denial of Service (DoS) attacks.
"""

from collections import defaultdict, deque
import threading
import time
from typing import Deque, Dict
from .base import Rule, Verdict

# Thread-safe in-memory sliding window store: ip -> deque of timestamps
_WINDOW_LOCK = threading.Lock()
_IP_REQUESTS: Dict[str, Deque[float]] = defaultdict(deque)

# Default configuration: Max 60 requests per 10-second rolling window per IP
WINDOW_SECONDS = 10.0
MAX_REQUESTS_PER_WINDOW = 60


class BotRateLimitRule(Rule):
    RULE_ID = "960300"
    NAME = "Sliding-Window CC Flood & Rate Limiter"
    CATEGORY = "Bot Protection"

    def match(self, request) -> Verdict:
        ip = request.client_ip or "127.0.0.1"
        now = time.time()

        with _WINDOW_LOCK:
            timestamps = _IP_REQUESTS[ip]
            # Evict timestamps older than rolling window
            while timestamps and now - timestamps[0] > WINDOW_SECONDS:
                timestamps.popleft()

            # Record current request
            timestamps.append(now)

            # Check threshold
            if len(timestamps) > MAX_REQUESTS_PER_WINDOW:
                req_count = len(timestamps)
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason=f"Bot Protection: Rate limit exceeded ({req_count} requests in {WINDOW_SECONDS}s window > max {MAX_REQUESTS_PER_WINDOW})",
                    meta={"client_ip": ip, "request_count": req_count, "window_sec": WINDOW_SECONDS},
                )

        return Verdict.clean(self.RULE_ID)
