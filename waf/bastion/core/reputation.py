"""
Bastion WAF Behavioral Baselining & Dynamic IP Quarantine Engine.
Tracks sliding-window reputation penalties per IP, enforces automated temporary
quarantine for aggressive attackers, and provides fast CIDR subnet access control.
"""

from datetime import datetime, timezone
import ipaddress
import logging
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

from api.auth import get_redis_client
from database.db import add_ip_rule, get_active_ip_rules, get_ip_rules

logger = logging.getLogger(__name__)

# Reputation Configuration
REPUTATION_WINDOW_SECONDS = 900  # 15 minutes sliding window
AUTO_QUARANTINE_THRESHOLD = 100.0  # Threshold to trigger quarantine
DEFAULT_QUARANTINE_SECONDS = 900  # 15 minutes quarantine duration

# Penalty weights
PENALTY_CRITICAL_BLOCK = 35.0   # SQLi, RCE, SSRF, Deserialization, etc.
PENALTY_BOT_CHALLENGE = 15.0    # Suspicious user-agent, abnormal burst
PENALTY_AUTH_FAILURE = 10.0     # Failed login or credential stuffing attempt
PENALTY_SCANNER_PROBE = 25.0    # Nikto, SQLMap, .env/.git probes

# Thread-safe in-memory store for fallback: ip -> [(timestamp, points)]
_MEMORY_REPUTATION_STORE: Dict[str, List[Tuple[float, float]]] = {}

# In-memory cache for database access rules to optimize high-throughput proxy inspection
_CACHED_RULES: List[Dict[str, Any]] = []
_CACHED_RULES_TIMESTAMP: float = 0.0
RULE_CACHE_TTL_SECONDS = 3.0


def invalidate_rules_cache():
    """Invalidate cached IP access rules so proxy immediately picks up changes."""
    global _CACHED_RULES_TIMESTAMP
    _CACHED_RULES_TIMESTAMP = 0.0


def get_cached_rules() -> List[Dict[str, Any]]:
    """Retrieve active IP access rules with a short 3-second cache TTL."""
    global _CACHED_RULES, _CACHED_RULES_TIMESTAMP
    now = time.time()
    if now - _CACHED_RULES_TIMESTAMP > RULE_CACHE_TTL_SECONDS:
        try:
            _CACHED_RULES = get_active_ip_rules()
            _CACHED_RULES_TIMESTAMP = now
        except Exception as e:
            logger.warning("Failed to refresh IP rules from database: %s", e)
    return _CACHED_RULES


def check_ip_access(ip_str: str) -> Tuple[str, Optional[str], Optional[int]]:
    """
    Evaluate client IP against Whitelist, Blacklist, and Quarantine rules.
    Returns:
        (action, reason, remaining_seconds)
        action is one of: "allow", "block", "pass"
    """
    if not ip_str or not isinstance(ip_str, str):
        return "pass", None, None

    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return "pass", None, None

    active_rules = get_cached_rules()
    now = time.time()

    # 1. Check Whitelist first (explicit bypass takes precedence)
    for rule in active_rules:
        if rule.get("rule_type") == "whitelist":
            try:
                network = ipaddress.ip_network(rule["cidr"], strict=False)
                if ip_obj in network:
                    return "allow", rule.get("reason") or "Whitelisted IP/CIDR", None
            except ValueError:
                continue

    # 2. Check Blacklist & Quarantine
    for rule in active_rules:
        rtype = rule.get("rule_type")
        if rtype in ("blacklist", "quarantine"):
            try:
                network = ipaddress.ip_network(rule["cidr"], strict=False)
                if ip_obj in network:
                    expires_at = rule.get("expires_at")
                    if expires_at is not None:
                        if now >= expires_at:
                            continue  # Expired quarantine rule
                        remaining = max(1, int(expires_at - now))
                    else:
                        remaining = None

                    reason = rule.get("reason") or (
                        "IP Quarantined due to repeated malicious infractions"
                        if rtype == "quarantine"
                        else "Blacklisted IP/Subnet"
                    )
                    return "block", reason, remaining
            except ValueError:
                continue

    return "pass", None, None


def record_penalty(ip_str: str, points: float, reason: str = "") -> Tuple[float, bool]:
    """
    Record reputation penalty points for an IP within the 15-minute sliding window.
    If cumulative penalty reaches AUTO_QUARANTINE_THRESHOLD (100.0), automatically
    quarantines the IP for 15 minutes.
    Returns:
        (current_total_score, was_quarantined)
    """
    if not ip_str or points <= 0:
        return 0.0, False

    now = time.time()
    cutoff = now - REPUTATION_WINDOW_SECONDS
    r = get_redis_client()
    total_score = 0.0

    if r:
        try:
            key = f"reputation:{ip_str}"
            member = f"{float(points):.1f}:{secrets.token_hex(4)}"
            pipe = r.pipeline()
            pipe.zremrangebyscore(key, 0, cutoff)
            pipe.zadd(key, {member: now})
            pipe.expire(key, REPUTATION_WINDOW_SECONDS + 120)
            pipe.execute()

            # Read all members to sum points
            entries = r.zrange(key, 0, -1)
            for entry in entries:
                val = entry.decode("utf-8") if isinstance(entry, bytes) else str(entry)
                try:
                    pts = float(val.split(":")[0])
                    total_score += pts
                except (ValueError, IndexError):
                    pass
        except Exception as e:
            logger.warning("Redis reputation recording failed (%s); falling back to memory.", e)
            total_score = _record_memory_penalty(ip_str, points, now, cutoff)
    else:
        total_score = _record_memory_penalty(ip_str, points, now, cutoff)

    was_quarantined = False
    if total_score >= AUTO_QUARANTINE_THRESHOLD:
        was_quarantined = quarantine_ip(
            ip_str,
            duration_seconds=DEFAULT_QUARANTINE_SECONDS,
            reason=f"Automated behavioral quarantine: accumulated {total_score:.0f} penalty points ({reason})",
            score=total_score,
        )

    return total_score, was_quarantined


def _record_memory_penalty(ip_str: str, points: float, now: float, cutoff: float) -> float:
    """Helper to record penalty in thread-safe memory fallback."""
    history = _MEMORY_REPUTATION_STORE.get(ip_str, [])
    valid_history = [(ts, pts) for ts, pts in history if ts >= cutoff]
    valid_history.append((now, points))
    _MEMORY_REPUTATION_STORE[ip_str] = valid_history
    return sum(pts for _, pts in valid_history)


def get_reputation_score(ip_str: str) -> float:
    """Retrieve cumulative penalty points for an IP within the current sliding window."""
    if not ip_str:
        return 0.0

    now = time.time()
    cutoff = now - REPUTATION_WINDOW_SECONDS
    r = get_redis_client()

    if r:
        try:
            key = f"reputation:{ip_str}"
            r.zremrangebyscore(key, 0, cutoff)
            entries = r.zrange(key, 0, -1)
            total = 0.0
            for entry in entries:
                val = entry.decode("utf-8") if isinstance(entry, bytes) else str(entry)
                try:
                    total += float(val.split(":")[0])
                except (ValueError, IndexError):
                    pass
            return total
        except Exception:
            pass

    history = _MEMORY_REPUTATION_STORE.get(ip_str, [])
    return sum(pts for ts, pts in history if ts >= cutoff)


def quarantine_ip(
    ip_str: str,
    duration_seconds: int = DEFAULT_QUARANTINE_SECONDS,
    reason: str = "Automated behavioral quarantine",
    score: float = 0.0,
) -> bool:
    """
    Place an IP address into quarantine for duration_seconds.
    Returns True if successfully quarantined.
    """
    try:
        clean_ip = ip_str.strip()
        cidr = clean_ip if "/" in clean_ip else f"{clean_ip}/32"
        add_ip_rule(
            cidr=cidr,
            rule_type="quarantine",
            reason=reason,
            duration_seconds=float(duration_seconds),
            penalty_score=score,
        )
        invalidate_rules_cache()
        logger.warning("🚨 [QUARANTINE] IP %s quarantined for %d seconds. Reason: %s", clean_ip, duration_seconds, reason)
        return True
    except Exception as e:
        logger.error("Failed to quarantine IP %s: %s", ip_str, e)
        return False


def reset_reputation_store():
    """Clear in-memory and cached reputation data (used for testing)."""
    global _MEMORY_REPUTATION_STORE
    _MEMORY_REPUTATION_STORE.clear()
    invalidate_rules_cache()
    r = get_redis_client()
    if r:
        try:
            keys = r.keys("reputation:*")
            if keys:
                r.delete(*keys)
        except Exception:
            pass
