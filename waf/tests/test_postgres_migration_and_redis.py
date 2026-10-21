"""
Tests for PostgreSQL migration utilities and Redis sliding window rate limiting.
"""

import os
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from database.db import migrate_sqlite_to_postgres
from api.auth import (
    check_ip_rate_limit,
    record_ip_attempt,
    reset_rate_limits,
    get_redis_client,
    reset_redis_client,
    _RATE_LIMIT_STORE,
)


def test_migrate_sqlite_missing_source(tmp_path):
    missing = tmp_path / "nonexistent.db"
    ok, msg, counts = migrate_sqlite_to_postgres(sqlite_path=str(missing), pg_url="postgresql://user:pass@localhost:5432/db")
    assert not ok
    assert "Source SQLite file does not exist" in msg


def test_migrate_sqlite_rejects_sqlite_target(tmp_path):
    src = tmp_path / "source.db"
    src.touch()
    ok, msg, counts = migrate_sqlite_to_postgres(sqlite_path=str(src), pg_url="sqlite:///target.db")
    assert not ok
    assert "Target database URL is SQLite" in msg


def test_migrate_sqlite_to_postgres_mocked(tmp_path):
    import sqlite3

    db_path = tmp_path / "source.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, totp_secret_encrypted TEXT, totp_enabled INT, failed_attempts INT, locked_until REAL, created_at TEXT)")
        conn.execute("INSERT INTO users VALUES (1, 'admin@bastion.local', 'hash123', NULL, 0, 0, 0.0, '2026-01-01')")
        conn.execute("CREATE TABLE waf_rules (rule_id TEXT PRIMARY KEY, rule_name TEXT, category TEXT, enabled INT)")
        conn.execute("INSERT INTO waf_rules VALUES ('sqli-01', 'SQLi Rule', 'sqli', 1)")
        conn.execute("CREATE TABLE protected_sites (id INTEGER PRIMARY KEY, domain TEXT, upstream TEXT, ssl_status TEXT, defense_mode INT)")
        conn.execute("INSERT INTO protected_sites VALUES (1, 'example.com', 'http://127.0.0.1:8080', 'Active', 1)")
        conn.execute("CREATE TABLE audit_actions (id INTEGER PRIMARY KEY, timestamp TEXT, actor TEXT, action TEXT, details TEXT, ip TEXT)")
        conn.execute("INSERT INTO audit_actions VALUES (1, '2026-01-01', 'admin', 'login', '{}', '127.0.0.1')")

    mock_engine = MagicMock()
    mock_conn = MagicMock()
    mock_engine.begin.return_value.__enter__.return_value = mock_conn

    with patch("database.db.create_engine", return_value=mock_engine):
        ok, msg, counts = migrate_sqlite_to_postgres(sqlite_path=str(db_path), pg_url="postgresql://user:pass@localhost:5432/db")

        assert ok
        assert counts["users"] == 1
        assert counts["waf_rules"] == 1
        assert counts["protected_sites"] == 1
        assert counts["audit_actions"] == 1
        assert mock_conn.execute.call_count >= 4


def test_redis_sliding_window_rate_limiting():
    mock_redis = MagicMock()
    mock_pipeline = MagicMock()
    mock_redis.pipeline.return_value = mock_pipeline

    with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379/0"}):
        with patch("api.auth.redis.Redis.from_url", return_value=mock_redis):
            reset_redis_client()
            client = get_redis_client()
            assert client is not None

            # 1. Test record attempt uses pipeline
            record_ip_attempt("1.2.3.4", "login")
            assert mock_pipeline.zremrangebyscore.called
            assert mock_pipeline.zadd.called
            assert mock_pipeline.expire.called
            assert mock_pipeline.execute.called

            # 2. Test within limit (count < 10) does not raise
            mock_redis.zcard.return_value = 5
            check_ip_rate_limit("1.2.3.4", "login")

            # 3. Test exceeded limit (count >= 10) raises 429 with Retry-After header
            now = time.time()
            mock_redis.zcard.return_value = 10
            # oldest attempt was 300 seconds ago (window is 900s)
            mock_redis.zrange.return_value = [(b"ignored", now - 300)]
            with pytest.raises(HTTPException) as exc_info:
                check_ip_rate_limit("1.2.3.4", "login")
            assert exc_info.value.status_code == 429
            retry_after = int(exc_info.value.headers.get("Retry-After"))
            assert retry_after > 0
            assert retry_after <= 600

            # 4. Test reset_rate_limits with redis
            mock_redis.keys.return_value = [b"ratelimit:login:1.2.3.4"]
            reset_rate_limits()
            assert mock_redis.delete.called

    reset_redis_client()


def test_redis_fallback_to_memory_when_unreachable():
    reset_redis_client()
    reset_rate_limits()

    # Even if REDIS_URL is provided, if connecting raises an error, fallback to in-memory gracefully
    with patch.dict(os.environ, {"REDIS_URL": "redis://unreachable-host:6379/0"}):
        with patch("api.auth.redis.Redis.from_url", side_effect=Exception("Redis connection error")):
            reset_redis_client()
            client = get_redis_client()
            assert client is None

            ip = "9.9.9.9"
            endpoint = "login"

            for _ in range(10):
                check_ip_rate_limit(ip, endpoint)
                record_ip_attempt(ip, endpoint)

            # 11th attempt should fail in fallback memory store with 429
            with pytest.raises(HTTPException) as exc_info:
                check_ip_rate_limit(ip, endpoint)
            assert exc_info.value.status_code == 429
            assert "Retry-After" in exc_info.value.headers

            # Reset clears memory store
            reset_rate_limits()
            check_ip_rate_limit(ip, endpoint)

    reset_redis_client()
    reset_rate_limits()
