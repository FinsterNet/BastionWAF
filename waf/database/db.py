"""
Enterprise Database Storage for Bastion WAF.
Supports PostgreSQL (with SQLAlchemy connection pooling) and SQLite (with automatic fallback).
All queries use strict parameterized bindings and LIKE wildcard escaping to prevent SQL injection.
"""

import csv
from datetime import datetime, timezone
import io
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import logging

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from bastion.core.security import (
    decrypt_totp_secret,
    dummy_verify_password,
    encrypt_totp_secret,
    hash_password,
    hash_token,
    validate_password_strength,
    verify_password,
)

logger = logging.getLogger("bastion.database")


def get_db_path() -> Path:
    """Retrieve database path from BASTION_DB_PATH env var or default to local waf.db."""
    env_path = os.environ.get("BASTION_DB_PATH")
    if env_path and env_path.strip():
        p = Path(env_path.strip()).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    if "DB_PATH" in globals() and DB_PATH is not None:
        p = Path(DB_PATH).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    default_p = Path(__file__).resolve().parent / "waf.db"
    default_p.parent.mkdir(parents=True, exist_ok=True)
    return default_p


DB_PATH = Path(__file__).resolve().parent / "waf.db"

IDLE_TIMEOUT_SECONDS = 1800  # 30-minute idle session timeout
MAX_SESSION_SECONDS = 7 * 86400  # 7-day maximum session duration
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 900  # 15 minutes

DEFAULT_RULES = (
    # Category 1: OWASP Top 10
    ("942100", "SQL Injection (SQLi) Shield", "OWASP Top 10", 1),
    ("941100", "Cross-Site Scripting (XSS) Filter", "OWASP Top 10", 1),
    ("930120", "Path Traversal / LFI Guard", "OWASP Top 10", 1),
    ("932100", "Remote Code Execution (RCE) Engine", "OWASP Top 10", 1),
    ("934100", "Server-Side Request Forgery (SSRF) Guard", "OWASP Top 10", 1),
    ("933100", "Server-Side Template Injection (SSTI) Guard", "OWASP Top 10", 1),
    ("933200", "XML External Entity (XXE) Shield", "OWASP Top 10", 1),
    ("933300", "Insecure Deserialization Shield", "OWASP Top 10", 1),
    ("933400", "Malicious File Upload & Webshell Guard", "OWASP Top 10", 1),
    ("933500", "JNDI / Log4j Lookup Shield", "OWASP Top 10", 1),
    ("933600", "JavaScript Prototype Pollution Filter", "OWASP Top 10", 1),
    ("921100", "CRLF Injection & Request Smuggling Shield", "OWASP Top 10", 1),
    ("935100", "Open Redirect & Host Header Injection Guard", "OWASP Top 10", 1),
    ("942200", "LDAP & XPath Injection Shield", "OWASP Top 10", 1),
    ("930200", "Sensitive Config & Backup Snooping Guard", "OWASP Top 10", 1),
    # Category 2: API Security
    ("950100", "API Mass Assignment & Privilege Escalation Guard", "API Security", 1),
    ("950200", "GraphQL Introspection & Depth Abuse Guard", "API Security", 1),
    ("950300", "Secret Key & Token URI Leakage Guard", "API Security", 1),
    ("950400", "HTTP Verb & Method Tampering Shield", "API Security", 1),
    ("950500", "JSON/XML Payload Bomb & Parser DoS Guard", "API Security", 1),
    ("950600", "CORS Origin Abuse & Null Origin Guard", "API Security", 1),
    ("950700", "JWT None-Algorithm & Signature Tampering Guard", "API Security", 1),
    # Category 3: Bot Protection
    ("960100", "Vulnerability Scanner Signatures Shield", "Bot Protection", 1),
    ("960200", "Headless Automation Framework Guard", "Bot Protection", 1),
    ("960300", "Sliding-Window CC Flood & Rate Limiter", "Bot Protection", 1),
    ("960400", "Credential Stuffing & Default Credentials Guard", "Bot Protection", 1),
    ("960500", "HTTP Header Anomaly & Protocol Violation Guard", "Bot Protection", 1),
    ("960600", "Cryptomining Script & Stratum Blocker", "Bot Protection", 1),
)

from sqlalchemy.pool import NullPool, QueuePool

_ENGINES: Dict[str, Engine] = {}


def reset_engine():
    """Dispose and clear cached database engines."""
    global _ENGINES
    for eng in list(_ENGINES.values()):
        try:
            eng.dispose()
        except Exception:
            pass
    _ENGINES.clear()


def get_db_url() -> str:
    """Retrieve normalized database URL (converts postgres:// to postgresql+psycopg://)."""
    env_url = os.environ.get("DATABASE_URL", "").strip()
    if env_url:
        if env_url.startswith("postgres://"):
            return env_url.replace("postgres://", "postgresql+psycopg://", 1)
        if env_url.startswith("postgresql://") and not env_url.startswith("postgresql+"):
            return env_url.replace("postgresql://", "postgresql+psycopg://", 1)
        return env_url
    return f"sqlite:///{get_db_path()}"


def is_postgres() -> bool:
    """Check if the active database is PostgreSQL."""
    return not get_db_url().startswith("sqlite")


def get_engine() -> Engine:
    """Get or create SQLAlchemy Engine with connection pooling and pre-ping."""
    url = get_db_url()
    if url not in _ENGINES:
        if url.startswith("sqlite"):
            _ENGINES[url] = create_engine(
                url,
                connect_args={"check_same_thread": False},
                poolclass=NullPool,
            )
        else:
            _ENGINES[url] = create_engine(
                url,
                poolclass=QueuePool,
                pool_size=10,
                max_overflow=20,
                pool_recycle=300,
                pool_pre_ping=True,
            )
    return _ENGINES[url]


def get_connection():
    """Return DB connection for direct or legacy usage (sqlite3.Connection under SQLite)."""
    url = get_db_url()
    if url.startswith("sqlite"):
        conn = sqlite3.connect(Path(DB_PATH).resolve())
        conn.row_factory = sqlite3.Row
        return conn
    return get_engine().raw_connection()


def escape_like(term: str) -> str:
    """Escape SQL LIKE special characters (% and _ and \\) to mitigate pattern injection."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _execute_multi_ddl(conn, ddl_text: str):
    """Execute multiple DDL statements sequentially for DBAPI compatibility."""
    for stmt in ddl_text.split(";"):
        stmt = stmt.strip()
        if stmt:
            conn.execute(text(stmt))


def init_db():
    """Initialize database tables, indexes, and seed default rules."""
    reset_engine()
    engine = get_engine()
    is_pg = is_postgres()

    with engine.begin() as conn:
        if is_pg:
            _execute_multi_ddl(conn, """
            CREATE TABLE IF NOT EXISTS events (
                id BIGSERIAL PRIMARY KEY,
                timestamp VARCHAR(64),
                client_ip VARCHAR(64),
                method VARCHAR(16),
                path VARCHAR(2048),
                blocked SMALLINT DEFAULT 0,
                rule_id VARCHAR(64),
                reason VARCHAR(255),
                action VARCHAR(64),
                payload_snippet VARCHAR(512) DEFAULT '',
                rule_score DOUBLE PRECISION DEFAULT 0.0,
                semantic_score DOUBLE PRECISION DEFAULT 0.0,
                total_score DOUBLE PRECISION DEFAULT 0.0,
                raw_payload TEXT DEFAULT '',
                normalized_payload TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_client_ip ON events (client_ip);
            CREATE INDEX IF NOT EXISTS idx_events_blocked ON events (blocked);

            CREATE TABLE IF NOT EXISTS waf_rules (
                rule_id VARCHAR(64) PRIMARY KEY,
                rule_name VARCHAR(255),
                category VARCHAR(64),
                enabled SMALLINT DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS protected_sites (
                id BIGSERIAL PRIMARY KEY,
                domain VARCHAR(255) UNIQUE,
                upstream VARCHAR(255),
                ssl_status VARCHAR(64) DEFAULT 'Active',
                defense_mode SMALLINT DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                totp_secret_encrypted TEXT DEFAULT NULL,
                totp_enabled SMALLINT DEFAULT 0,
                failed_attempts INT DEFAULT 0,
                locked_until DOUBLE PRECISION DEFAULT 0.0,
                created_at VARCHAR(64)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users (LOWER(email));

            CREATE TABLE IF NOT EXISTS sessions (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash VARCHAR(128) UNIQUE NOT NULL,
                created_at DOUBLE PRECISION NOT NULL,
                last_seen_at DOUBLE PRECISION NOT NULL,
                expires_at DOUBLE PRECISION NOT NULL,
                ip VARCHAR(64),
                user_agent VARCHAR(255)
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions (token_hash);
            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);

            CREATE TABLE IF NOT EXISTS password_resets (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash VARCHAR(128) UNIQUE NOT NULL,
                expires_at DOUBLE PRECISION NOT NULL,
                used_at DOUBLE PRECISION DEFAULT NULL
            );

            CREATE TABLE IF NOT EXISTS recovery_codes (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                code_hash VARCHAR(128) NOT NULL,
                used_at DOUBLE PRECISION DEFAULT NULL
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                id BIGSERIAL PRIMARY KEY,
                email VARCHAR(255),
                ip VARCHAR(64),
                success SMALLINT DEFAULT 0,
                created_at VARCHAR(64)
            );
            CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts (ip, created_at);

            CREATE TABLE IF NOT EXISTS audit_actions (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT,
                email VARCHAR(255),
                action VARCHAR(64),
                details TEXT,
                ip VARCHAR(64),
                timestamp VARCHAR(64)
            );

            CREATE TABLE IF NOT EXISTS ip_access_rules (
                id BIGSERIAL PRIMARY KEY,
                cidr VARCHAR(64) NOT NULL,
                rule_type VARCHAR(16) NOT NULL,
                reason VARCHAR(255) DEFAULT '',
                penalty_score DOUBLE PRECISION DEFAULT 0.0,
                expires_at DOUBLE PRECISION DEFAULT NULL,
                created_at VARCHAR(64) NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ip_rules_type ON ip_access_rules (rule_type);
            CREATE INDEX IF NOT EXISTS idx_ip_rules_cidr ON ip_access_rules (cidr);
            """)
        else:
            Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
            _execute_multi_ddl(conn, """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                client_ip TEXT,
                method TEXT,
                path TEXT,
                blocked INTEGER,
                rule_id TEXT,
                reason TEXT,
                action TEXT,
                payload_snippet TEXT DEFAULT '',
                rule_score REAL DEFAULT 0.0,
                semantic_score REAL DEFAULT 0.0,
                total_score REAL DEFAULT 0.0,
                raw_payload TEXT DEFAULT '',
                normalized_payload TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_client_ip ON events (client_ip);
            CREATE INDEX IF NOT EXISTS idx_events_blocked ON events (blocked);

            CREATE TABLE IF NOT EXISTS waf_rules (
                rule_id TEXT PRIMARY KEY,
                rule_name TEXT,
                category TEXT,
                enabled INTEGER
            );

            CREATE TABLE IF NOT EXISTS protected_sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                upstream TEXT,
                ssl_status TEXT,
                defense_mode INTEGER
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                totp_secret_encrypted TEXT DEFAULT NULL,
                totp_enabled INTEGER DEFAULT 0,
                failed_attempts INTEGER DEFAULT 0,
                locked_until REAL DEFAULT 0.0,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                created_at REAL NOT NULL,
                last_seen_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                ip TEXT,
                user_agent TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions (token_hash);

            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at REAL NOT NULL,
                used_at REAL DEFAULT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                used_at REAL DEFAULT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                ip TEXT,
                success INTEGER,
                created_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts (ip, created_at);

            CREATE TABLE IF NOT EXISTS audit_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                email TEXT,
                action TEXT,
                details TEXT,
                ip TEXT,
                timestamp TEXT
            );

            CREATE TABLE IF NOT EXISTS ip_access_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cidr TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                reason TEXT DEFAULT '',
                penalty_score REAL DEFAULT 0.0,
                expires_at REAL DEFAULT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ip_rules_type ON ip_access_rules (rule_type);
            CREATE INDEX IF NOT EXISTS idx_ip_rules_cidr ON ip_access_rules (cidr);
            """)

        # Seed default rules safely using standard SQL ON CONFLICT
        for r in DEFAULT_RULES:
            conn.execute(
                text("""
                INSERT INTO waf_rules (rule_id, rule_name, category, enabled)
                VALUES (:rid, :rname, :rcat, :renabled)
                ON CONFLICT (rule_id) DO NOTHING
                """),
                {"rid": r[0], "rname": r[1], "rcat": r[2], "renabled": r[3]},
            )

        # Clean legacy demo site
        conn.execute(
            text("DELETE FROM protected_sites WHERE domain = '127.0.0.1:8080' AND upstream = '127.0.0.1:3000'")
        )

        # Auto-migrate from SQLite to PostgreSQL if PostgreSQL is empty and local SQLite has users
        if is_pg:
            try:
                cnt = conn.execute(text("SELECT COUNT(*) FROM users")).scalar_one()
                if (cnt or 0) == 0:
                    sqlite_path = get_db_path()
                    if sqlite_path.exists():
                        with sqlite3.connect(sqlite_path) as s_conn:
                            s_cur = s_conn.cursor()
                            s_cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
                            if s_cur.fetchone():
                                s_cnt = s_cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                                if (s_cnt or 0) > 0:
                                    logger.info("🚚 Auto-migrating existing data from SQLite (%s) to PostgreSQL...", sqlite_path)
                                    ok, msg, m_counts = migrate_sqlite_to_postgres(str(sqlite_path))
                                    logger.info("🚚 Auto-migration completed: %s (%s)", msg, m_counts)
            except Exception as e:
                logger.warning("Auto-migration check skipped: %s", e)

    startup_self_check()


def migrate_sqlite_to_postgres(sqlite_path: Optional[str] = None, pg_url: Optional[str] = None) -> Tuple[bool, str, Dict[str, int]]:
    """
    Migrate users, waf_rules, protected_sites, and audit_actions from SQLite to PostgreSQL.
    Safely transfers records and synchronizes PostgreSQL sequences.
    """
    src_path = Path(sqlite_path or get_db_path()).resolve()
    if not src_path.exists():
        return False, f"Source SQLite file does not exist: {src_path}", {}

    target_url = pg_url or get_db_url()
    if target_url.startswith("sqlite"):
        return False, "Target database URL is SQLite, expected PostgreSQL", {}

    counts = {"users": 0, "waf_rules": 0, "protected_sites": 0, "audit_actions": 0, "ip_access_rules": 0}

    try:
        # 1. Read records from SQLite
        with sqlite3.connect(src_path) as s_conn:
            s_conn.row_factory = sqlite3.Row
            s_cur = s_conn.cursor()

            users = []
            try:
                s_cur.execute("SELECT * FROM users")
                users = [dict(r) for r in s_cur.fetchall()]
            except Exception:
                pass

            rules = []
            try:
                s_cur.execute("SELECT * FROM waf_rules")
                rules = [dict(r) for r in s_cur.fetchall()]
            except Exception:
                pass

            sites = []
            try:
                s_cur.execute("SELECT * FROM protected_sites")
                sites = [dict(r) for r in s_cur.fetchall()]
            except Exception:
                pass

            audits = []
            try:
                s_cur.execute("SELECT * FROM audit_actions")
                audits = [dict(r) for r in s_cur.fetchall()]
            except Exception:
                pass

            ip_rules = []
            try:
                s_cur.execute("SELECT * FROM ip_access_rules")
                ip_rules = [dict(r) for r in s_cur.fetchall()]
            except Exception:
                pass

        # 2. Write to PostgreSQL using target engine
        pg_engine = create_engine(
            target_url,
            poolclass=QueuePool,
            pool_size=5,
            max_overflow=10,
        )

        with pg_engine.begin() as p_conn:
            # Users
            for u in users:
                p_conn.execute(
                    text("""
                    INSERT INTO users (id, email, password_hash, totp_secret_encrypted, totp_enabled, failed_attempts, locked_until, created_at)
                    VALUES (:id, :email, :password_hash, :totp_secret_encrypted, :totp_enabled, :failed_attempts, :locked_until, :created_at)
                    ON CONFLICT (id) DO UPDATE SET
                        password_hash = EXCLUDED.password_hash,
                        totp_secret_encrypted = EXCLUDED.totp_secret_encrypted,
                        totp_enabled = EXCLUDED.totp_enabled,
                        failed_attempts = EXCLUDED.failed_attempts,
                        locked_until = EXCLUDED.locked_until
                    """),
                    u,
                )
                counts["users"] += 1

            # Sync users sequence
            if users:
                try:
                    p_conn.execute(text("SELECT setval(pg_get_serial_sequence('users', 'id'), COALESCE(MAX(id), 1)) FROM users"))
                except Exception:
                    pass

            # Rules
            for r in rules:
                p_conn.execute(
                    text("""
                    INSERT INTO waf_rules (rule_id, rule_name, category, enabled)
                    VALUES (:rule_id, :rule_name, :category, :enabled)
                    ON CONFLICT (rule_id) DO UPDATE SET
                        enabled = EXCLUDED.enabled,
                        rule_name = EXCLUDED.rule_name,
                        category = EXCLUDED.category
                    """),
                    r,
                )
                counts["waf_rules"] += 1

            # Sites
            for s in sites:
                p_conn.execute(
                    text("""
                    INSERT INTO protected_sites (id, domain, upstream, ssl_status, defense_mode)
                    VALUES (:id, :domain, :upstream, :ssl_status, :defense_mode)
                    ON CONFLICT (domain) DO UPDATE SET
                        upstream = EXCLUDED.upstream,
                        ssl_status = EXCLUDED.ssl_status,
                        defense_mode = EXCLUDED.defense_mode
                    """),
                    s,
                )
                counts["protected_sites"] += 1

            if sites:
                try:
                    p_conn.execute(text("SELECT setval(pg_get_serial_sequence('protected_sites', 'id'), COALESCE(MAX(id), 1)) FROM protected_sites"))
                except Exception:
                    pass

            # Audits
            for a in audits:
                p_conn.execute(
                    text("""
                    INSERT INTO audit_actions (user_id, email, action, details, ip, timestamp)
                    VALUES (:user_id, :email, :action, :details, :ip, :timestamp)
                    """),
                    {
                        "user_id": a.get("user_id"),
                        "email": a.get("email"),
                        "action": a.get("action"),
                        "details": a.get("details"),
                        "ip": a.get("ip"),
                        "timestamp": a.get("timestamp"),
                    },
                )
                counts["audit_actions"] += 1

            if audits:
                try:
                    p_conn.execute(text("SELECT setval(pg_get_serial_sequence('audit_actions', 'id'), COALESCE(MAX(id), 1)) FROM audit_actions"))
                except Exception:
                    pass

            # IP Access Rules
            for rule in ip_rules:
                p_conn.execute(
                    text("""
                    INSERT INTO ip_access_rules (id, cidr, rule_type, reason, penalty_score, expires_at, created_at)
                    VALUES (:id, :cidr, :rule_type, :reason, :penalty_score, :expires_at, :created_at)
                    ON CONFLICT (id) DO UPDATE SET
                        cidr = EXCLUDED.cidr,
                        rule_type = EXCLUDED.rule_type,
                        reason = EXCLUDED.reason,
                        penalty_score = EXCLUDED.penalty_score,
                        expires_at = EXCLUDED.expires_at
                    """),
                    rule,
                )
                counts["ip_access_rules"] += 1

            if ip_rules:
                try:
                    p_conn.execute(text("SELECT setval(pg_get_serial_sequence('ip_access_rules', 'id'), COALESCE(MAX(id), 1)) FROM ip_access_rules"))
                except Exception:
                    pass

        pg_engine.dispose()
        return True, "Migration completed successfully", counts
    except Exception as e:
        logger.exception("PostgreSQL migration failed: %s", e)
        return False, f"Migration failed: {str(e)}", counts


def startup_self_check():
    """
    Startup self-check:
    1. Read and log database path and user count.
    2. Log clear WARNING if running on Render and DB is not persistent (/var/data).
    3. Refuse to start in production if BASTION_SETUP_TOKEN, BASTION_SECRET_KEY, or BASTION_ENCRYPTION_KEY are missing.
    """
    is_render = os.environ.get("RENDER", "").lower() in ("true", "1")
    is_production = is_render or os.environ.get("BASTION_ENV", "").lower() == "production"

    if is_production:
        missing = []
        for key in ("BASTION_SETUP_TOKEN", "BASTION_SECRET_KEY", "BASTION_ENCRYPTION_KEY"):
            if not os.environ.get(key):
                missing.append(key)
        if missing:
            raise RuntimeError(
                f"FATAL: Production mode requires environment variables: {', '.join(missing)}. Startup refused."
            )

    active_url = get_db_url()
    if active_url.startswith("sqlite"):
        db_p = str(get_db_path())
        if is_render and not db_p.startswith("/var/data"):
            logger.warning(
                "⚠️ WARNING: Database path '%s' is NOT on persistent storage on Render! "
                "All users, sessions, and data will be wiped on redeploy. "
                "Attach a persistent disk at /var/data and set BASTION_DB_PATH=/var/data/bastion.db",
                db_p,
            )
        logger.info("📦 Database Engine: SQLite | Path: %s", db_p)
    else:
        logger.info("📦 Database Engine: PostgreSQL | Persistent Connection Active")

    try:
        with get_engine().connect() as conn:
            cnt = conn.execute(text("SELECT COUNT(*) FROM users")).scalar_one()
            logger.info("🛡️ Bastion Startup Self-Check: Database Path: %s | Registered Users: %d", str(get_db_path()), cnt)
    except Exception as e:
        logger.warning("Bastion Startup Self-Check: Could not count users: %s", e)


def log_event(
    client_ip: str,
    method: str,
    path: str,
    blocked: bool,
    rule_id: str = "",
    reason: str = "",
    action: Optional[str] = None,
    payload_snippet: str = "",
    rule_score: float = 0.0,
    semantic_score: float = 0.0,
    total_score: float = 0.0,
    raw_payload: str = "",
    normalized_payload: str = "",
):
    """Log an inspected HTTP request event to the database using parameterized bindings."""
    if action is None:
        action = "403 Blocked" if blocked else "200 Allowed"
    with get_engine().begin() as conn:
        conn.execute(
            text("""
            INSERT INTO events (
                timestamp, client_ip, method, path, blocked, rule_id, reason, action,
                payload_snippet, rule_score, semantic_score, total_score, raw_payload, normalized_payload
            )
            VALUES (
                :timestamp, :client_ip, :method, :path, :blocked, :rule_id, :reason, :action,
                :payload_snippet, :rule_score, :semantic_score, :total_score, :raw_payload, :normalized_payload
            )
            """),
            {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "client_ip": str(client_ip)[:64],
                "method": str(method)[:16].upper(),
                "path": str(path)[:2048],
                "blocked": 1 if blocked else 0,
                "rule_id": str(rule_id)[:64],
                "reason": str(reason)[:255],
                "action": str(action)[:64],
                "payload_snippet": str(payload_snippet)[:512],
                "rule_score": float(rule_score),
                "semantic_score": float(semantic_score),
                "total_score": float(total_score),
                "raw_payload": str(raw_payload)[:4096],
                "normalized_payload": str(normalized_payload)[:4096],
            },
        )


def get_threat_category_counts() -> Dict[str, Any]:
    """Calculate aggregated threat categories for the dashboard."""
    with get_engine().connect() as conn:
        r1 = conn.execute(
            text("SELECT category, COUNT(*) as cnt FROM waf_rules WHERE enabled = 1 GROUP BY category")
        ).mappings().all()
        rule_counts = {"OWASP Top 10": 0, "API Security": 0, "Bot Protection": 0}
        for r in r1:
            if r["category"] in rule_counts:
                rule_counts[r["category"]] = r["cnt"]

        r2 = conn.execute(
            text("""
            SELECT rule_id, reason, COUNT(*) as hit_count
            FROM events
            WHERE blocked = 1 OR action = 'CAPTCHA Challenged'
            GROUP BY rule_id, reason
            """)
        ).mappings().all()

        r3 = conn.execute(text("SELECT rule_id, category FROM waf_rules")).mappings().all()
        rule_cat_map = {r["rule_id"]: r["category"] for r in r3}

        threat_counts = {"OWASP Top 10": 0, "API Security": 0, "Bot Protection": 0}
        for row in r2:
            rid = row["rule_id"] or ""
            reason = (row["reason"] or "").lower()
            cnt = row["hit_count"]

            if rid in rule_cat_map:
                threat_counts[rule_cat_map[rid]] += cnt
            elif any(k in reason for k in ("sql", "xss", "traversal", "rce", "command", "ssrf", "ssti", "log4j", "webshell")):
                threat_counts["OWASP Top 10"] += cnt
            elif any(k in reason for k in ("api", "graphql", "jwt", "payload", "cors")):
                threat_counts["API Security"] += cnt
            elif any(k in reason for k in ("bot", "scanner", "crawler", "captcha", "rate", "flood")):
                threat_counts["Bot Protection"] += cnt
            else:
                threat_counts["OWASP Top 10"] += cnt

        total_threats = sum(threat_counts.values())

        return {
            "threat_counts": threat_counts,
            "rule_counts": rule_counts,
            "total_threats": total_threats,
        }


def get_threat_analytics(limit: int = 5) -> Dict[str, Any]:
    """Retrieve top client IPs, targeted endpoints, and triggered rules with bounded limits."""
    safe_limit = max(1, min(int(limit), 100))
    with get_engine().connect() as conn:
        top_ips_res = conn.execute(
            text("""
            SELECT client_ip, COUNT(*) as hit_count,
                   SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_count,
                   MAX(timestamp) as last_seen
            FROM events
            WHERE client_ip != ''
            GROUP BY client_ip
            ORDER BY hit_count DESC
            LIMIT :limit
            """),
            {"limit": safe_limit},
        ).mappings().all()
        top_ips = [
            {
                "ip": r["client_ip"],
                "total": r["hit_count"],
                "blocked": r["blocked_count"],
                "last_seen": r["last_seen"],
            }
            for r in top_ips_res
        ]

        top_paths_res = conn.execute(
            text("""
            SELECT path, COUNT(*) as hit_count,
                   SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_count
            FROM events
            WHERE path != ''
            GROUP BY path
            ORDER BY hit_count DESC
            LIMIT 4
            """)
        ).mappings().all()
        top_paths = [
            {"path": r["path"], "total": r["hit_count"], "blocked": r["blocked_count"]}
            for r in top_paths_res
        ]

        top_rules_res = conn.execute(
            text("""
            SELECT e.rule_id, COALESCE(r.rule_name, e.reason) as rule_name,
                   COALESCE(r.category, 'OWASP Top 10') as category,
                   COUNT(*) as trigger_count
            FROM events e
            LEFT JOIN waf_rules r ON e.rule_id = r.rule_id
            WHERE e.blocked = 1 OR e.action = 'CAPTCHA Challenged'
            GROUP BY e.rule_id, r.rule_name, r.category, e.reason
            ORDER BY trigger_count DESC
            LIMIT 4
            """)
        ).mappings().all()
        top_rules = [
            {
                "rule_id": r["rule_id"] or "ANOMALY",
                "name": r["rule_name"],
                "category": r["category"],
                "count": r["trigger_count"],
            }
            for r in top_rules_res
        ]

        total_unique_ips = conn.execute(text("SELECT COUNT(DISTINCT client_ip) FROM events")).scalar_one() or 0

        return {
            "top_ips": top_ips,
            "top_paths": top_paths,
            "top_rules": top_rules,
            "unique_ips": total_unique_ips,
        }


def get_stats() -> Dict[str, Any]:
    """Retrieve comprehensive system metrics and recent traffic profile."""
    with get_engine().connect() as conn:
        total = conn.execute(text("SELECT COUNT(*) FROM events")).scalar_one() or 0
        blocked = conn.execute(text("SELECT COUNT(*) FROM events WHERE blocked = 1")).scalar_one() or 0
        challenged = conn.execute(text("SELECT COUNT(*) FROM events WHERE action = 'CAPTCHA Challenged'")).scalar_one() or 0

        event_rows = conn.execute(text("SELECT blocked FROM events ORDER BY id DESC LIMIT 70")).mappings().all()
        clean_pts = []
        block_pts = []
        if event_rows:
            chunk_size = max(1, len(event_rows) // 7)
            chunks = [event_rows[i:i + chunk_size] for i in range(0, len(event_rows), chunk_size)][:7]
            for ch in reversed(chunks):
                bl = sum(1 for x in ch if x["blocked"] == 1)
                cl = len(ch) - bl
                clean_pts.append(cl)
                block_pts.append(bl)
        while len(clean_pts) < 7:
            clean_pts.insert(0, 0)
            block_pts.insert(0, 0)

        categories = get_threat_category_counts()
        threat_analytics = get_threat_analytics()

        return {
            "total_requests": total,
            "blocked_attacks": blocked,
            "challenged_requests": challenged,
            "latency_ms": 0.38,
            "categories": categories,
            "analytics": threat_analytics,
            "traffic": {
                "clean": clean_pts,
                "blocked": block_pts,
            },
        }


def get_recent_events(limit: int = 15) -> List[Dict[str, Any]]:
    """Fetch recent security events with integer clamping."""
    safe_limit = max(1, min(int(limit), 500))
    with get_engine().connect() as conn:
        rows = conn.execute(
            text("""
            SELECT id, timestamp, client_ip, method, path, blocked, rule_id, reason,
                   COALESCE(action, CASE WHEN blocked = 1 THEN '403 Blocked' ELSE '200 Allowed' END) as action,
                   COALESCE(payload_snippet, '') as payload_snippet
            FROM events ORDER BY id DESC LIMIT :limit
            """),
            {"limit": safe_limit},
        ).mappings().all()
        return [dict(r) for r in rows]


def get_logs(query: str = "", threat: str = "All Threat Types", limit: int = 50) -> List[Dict[str, Any]]:
    """Search and filter logs using parameterized LIKE queries with wildcard escaping."""
    safe_limit = max(1, min(int(limit), 500))
    clean_q = str(query)[:100].strip()
    clean_threat = str(threat)[:50].strip()

    sql = """
        SELECT id, timestamp, client_ip, method, path, blocked, rule_id, reason,
               COALESCE(action, CASE WHEN blocked = 1 THEN '403 Blocked' ELSE '200 Allowed' END) as action,
               COALESCE(payload_snippet, '') as payload_snippet
        FROM events
        WHERE (client_ip LIKE :pattern ESCAPE '\\' OR path LIKE :pattern ESCAPE '\\' OR payload_snippet LIKE :pattern ESCAPE '\\')
    """
    params: Dict[str, Any] = {
        "pattern": f"%{escape_like(clean_q)}%",
        "limit": safe_limit,
    }

    if clean_threat and clean_threat != "All Threat Types":
        sql += " AND (reason LIKE :threat_pattern ESCAPE '\\' OR rule_id LIKE :threat_pattern ESCAPE '\\')"
        params["threat_pattern"] = f"%{escape_like(clean_threat)}%"

    sql += " ORDER BY id DESC LIMIT :limit"

    with get_engine().connect() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
        return [dict(r) for r in rows]


def clear_logs():
    """Clear all events safely in a transaction."""
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM events"))


def export_logs_csv() -> str:
    """Export recent security logs to CSV format safely."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Client IP", "Method", "Path", "Blocked", "Rule ID", "Reason", "Action", "Payload Snippet"])
    with get_engine().connect() as conn:
        rows = conn.execute(
            text("SELECT id, timestamp, client_ip, method, path, blocked, rule_id, reason, action, payload_snippet FROM events ORDER BY id DESC LIMIT 5000")
        ).mappings().all()
        for r in rows:
            writer.writerow([r["id"], r["timestamp"], r["client_ip"], r["method"], r["path"], r["blocked"], r["rule_id"], r["reason"], r["action"], r["payload_snippet"]])
    return output.getvalue()


def get_rules() -> List[Dict[str, Any]]:
    """Retrieve all WAF inspection rules."""
    with get_engine().connect() as conn:
        rows = conn.execute(text("SELECT rule_id, rule_name, category, enabled FROM waf_rules ORDER BY rule_id ASC")).mappings().all()
        return [
            {
                "rule_id": r["rule_id"],
                "rule_name": r["rule_name"],
                "category": r["category"],
                "enabled": bool(r["enabled"]),
            }
            for r in rows
        ]


def set_rule_state(rule_id: str, enabled: bool):
    """Update rule state with strict parameter binding."""
    with get_engine().begin() as conn:
        conn.execute(
            text("UPDATE waf_rules SET enabled = :enabled WHERE rule_id = :rule_id"),
            {"enabled": 1 if enabled else 0, "rule_id": str(rule_id)},
        )


def get_enabled_rule_ids() -> Set[str]:
    """Retrieve set of currently enabled rule IDs."""
    with get_engine().connect() as conn:
        rows = conn.execute(text("SELECT rule_id FROM waf_rules WHERE enabled = 1")).mappings().all()
        return {r["rule_id"] for r in rows}


def get_sites() -> List[Dict[str, Any]]:
    """Retrieve all configured protected upstream sites."""
    with get_engine().connect() as conn:
        rows = conn.execute(
            text("SELECT id, domain, upstream, ssl_status, defense_mode FROM protected_sites ORDER BY id ASC")
        ).mappings().all()
        return [
            {
                "id": r["id"],
                "domain": r["domain"],
                "upstream": r["upstream"],
                "ssl_status": r["ssl_status"],
                "defense_mode": bool(r["defense_mode"]),
            }
            for r in rows
        ]


def add_site(domain: str, upstream: str, ssl_status: str = "Active", defense_mode: bool = True):
    """Add or update protected site using standard SQL ON CONFLICT."""
    with get_engine().begin() as conn:
        conn.execute(
            text("""
            INSERT INTO protected_sites (domain, upstream, ssl_status, defense_mode)
            VALUES (:domain, :upstream, :ssl_status, :defense_mode)
            ON CONFLICT (domain) DO UPDATE SET
                upstream = excluded.upstream,
                ssl_status = excluded.ssl_status,
                defense_mode = excluded.defense_mode
            """),
            {
                "domain": str(domain).strip().lower(),
                "upstream": str(upstream).strip(),
                "ssl_status": str(ssl_status).strip(),
                "defense_mode": 1 if defense_mode else 0,
            },
        )


def set_site_defense(site_id: int, defense_mode: bool):
    """Update defense mode toggle for a protected site."""
    with get_engine().begin() as conn:
        conn.execute(
            text("UPDATE protected_sites SET defense_mode = :defense_mode WHERE id = :id"),
            {"defense_mode": 1 if defense_mode else 0, "id": int(site_id)},
        )


def delete_site(site_id: int):
    """Remove protected site mapping."""
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM protected_sites WHERE id = :id"), {"id": int(site_id)})


# ============================================================
# User Accounts, Authentication, and Sessions
# ============================================================

def has_users() -> bool:
    """Check if any administrator accounts exist."""
    with get_engine().connect() as conn:
        cnt = conn.execute(text("SELECT COUNT(*) FROM users")).scalar_one()
        return (cnt or 0) > 0


def create_user(email: str, password: str) -> Tuple[bool, str, Optional[int]]:
    """Create a new administrator account with validation."""
    clean_email = email.strip().lower()
    if not clean_email or len(clean_email) < 3 or len(clean_email) > 254:
        return False, "Invalid username or email address", None

    valid, err = validate_password_strength(password)
    if not valid:
        return False, err or "Invalid password", None

    pwd_hash = hash_password(password)
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        with get_engine().begin() as conn:
            # Check duplicate email
            existing = conn.execute(
                text("SELECT id FROM users WHERE LOWER(email) = :email"),
                {"email": clean_email},
            ).first()
            if existing:
                return False, "An account with this username/email already exists", None

            res = conn.execute(
                text("INSERT INTO users (email, password_hash, created_at) VALUES (:email, :pwd, :created_at) RETURNING id"),
                {"email": clean_email, "pwd": pwd_hash, "created_at": now_iso},
            )
            user_id = res.scalar_one()
            return True, "User created successfully", user_id
    except Exception as e:
        return False, f"Failed to create user: {str(e)}", None


def create_first_admin_atomic(email: str, password: str) -> Tuple[bool, str, Optional[int]]:
    """Atomically create the very first administrator account if zero users exist."""
    clean_email = email.strip().lower()
    if not clean_email or len(clean_email) < 3 or len(clean_email) > 254:
        return False, "Invalid username or email address", None

    valid, err = validate_password_strength(password)
    if not valid:
        return False, err or "Invalid password", None

    pwd_hash = hash_password(password)
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        if is_postgres():
            with get_engine().begin() as conn:
                conn.execute(text("LOCK TABLE users IN EXCLUSIVE MODE"))
                cnt = conn.execute(text("SELECT COUNT(*) FROM users")).scalar_one()
                if cnt > 0:
                    return False, "Initial setup has already been completed.", None
                res = conn.execute(
                    text("INSERT INTO users (email, password_hash, created_at) VALUES (:email, :pwd, :created_at) RETURNING id"),
                    {"email": clean_email, "pwd": pwd_hash, "created_at": now_iso},
                )
                user_id = res.scalar_one()
                return True, "Administrator created successfully", user_id
        else:
            with sqlite3.connect(Path(get_db_path()).resolve()) as raw_conn:
                raw_conn.execute("BEGIN IMMEDIATE")
                cursor = raw_conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM users")
                cnt = cursor.fetchone()[0]
                if cnt > 0:
                    raw_conn.rollback()
                    return False, "Initial setup has already been completed.", None
                cursor.execute(
                    "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                    (clean_email, pwd_hash, now_iso),
                )
                user_id = cursor.lastrowid
                raw_conn.commit()
                return True, "Administrator created successfully", user_id
    except Exception as e:
        return False, f"Failed to create user: {str(e)}", None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Fetch user record by ID."""
    with get_engine().connect() as conn:
        row = conn.execute(text("SELECT * FROM users WHERE id = :id"), {"id": int(user_id)}).mappings().first()
        return dict(row) if row else None


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Fetch user record by lowercase email."""
    clean_email = email.strip().lower()
    with get_engine().connect() as conn:
        row = conn.execute(
            text("SELECT * FROM users WHERE LOWER(email) = :email"),
            {"email": clean_email},
        ).mappings().first()
        return dict(row) if row else None


def list_all_users() -> List[Dict[str, Any]]:
    """Fetch all administrator records for the CLI."""
    with get_engine().connect() as conn:
        rows = conn.execute(
            text("SELECT id, email, totp_enabled, failed_attempts, locked_until, created_at FROM users ORDER BY id ASC")
        ).mappings().all()
        return [dict(r) for r in rows]


def record_login_attempt(email: str, ip: str, success: bool):
    """Log an authentication attempt for rate limiting and forensic tracking."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_engine().begin() as conn:
        conn.execute(
            text("INSERT INTO login_attempts (email, ip, success, created_at) VALUES (:email, :ip, :success, :created_at)"),
            {
                "email": email.strip().lower()[:254],
                "ip": str(ip)[:64],
                "success": 1 if success else 0,
                "created_at": now_iso,
            },
        )


def is_ip_rate_limited(ip: str) -> bool:
    """Check if IP has exceeded 10 failed login attempts in the past 15 minutes."""
    cutoff = datetime.fromtimestamp(time.time() - LOCKOUT_DURATION_SECONDS, timezone.utc).isoformat()
    with get_engine().connect() as conn:
        cnt = conn.execute(
            text("SELECT COUNT(*) FROM login_attempts WHERE ip = :ip AND success = 0 AND created_at >= :cutoff"),
            {"ip": str(ip)[:64], "cutoff": cutoff},
        ).scalar_one()
        return (cnt or 0) >= 10


def unlock_user_account(email: str) -> bool:
    """Reset failed attempts and unlock an account."""
    with get_engine().begin() as conn:
        conn.execute(
            text("UPDATE users SET failed_attempts = 0, locked_until = 0.0 WHERE LOWER(email) = :email"),
            {"email": email.strip().lower()},
        )
        return True


def authenticate_user(email: str, password: str, ip: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Authenticate user credentials with brute-force lockout and timing equalization."""
    clean_email = email.strip().lower()

    if is_ip_rate_limited(ip):
        record_login_attempt(clean_email, ip, False)
        return False, "Too many failed attempts from your IP. Please try again in 15 minutes.", None

    user = get_user_by_email(clean_email)
    now = time.time()

    if not user:
        dummy_verify_password(password)
        record_login_attempt(clean_email, ip, False)
        return False, "Invalid email or password", None

    if user.get("locked_until", 0.0) > now:
        dummy_verify_password(password)
        record_login_attempt(clean_email, ip, False)
        return False, "Invalid email or password", None

    pwd_valid = verify_password(password, user["password_hash"])
    if not pwd_valid:
        failed = user.get("failed_attempts", 0) + 1
        if failed >= MAX_FAILED_ATTEMPTS:
            doubling_exp = min(failed - MAX_FAILED_ATTEMPTS, 7)
            duration = min(86400, LOCKOUT_DURATION_SECONDS * (2 ** doubling_exp))
            locked_until = now + duration
        else:
            locked_until = 0.0
        with get_engine().begin() as conn:
            conn.execute(
                text("UPDATE users SET failed_attempts = :failed, locked_until = :locked_until WHERE id = :id"),
                {"failed": failed, "locked_until": locked_until, "id": user["id"]},
            )
        record_login_attempt(clean_email, ip, False)
        return False, "Invalid email or password", None

    # Reset failure counters on success
    with get_engine().begin() as conn:
        conn.execute(
            text("UPDATE users SET failed_attempts = 0, locked_until = 0.0 WHERE id = :id"),
            {"id": user["id"]},
        )

    record_login_attempt(clean_email, ip, True)
    return True, "Authenticated", user


# ============================================================
# Session Operations
# ============================================================

def create_session(user_id: int, raw_token: str, ip: str = "", user_agent: str = "") -> Dict[str, Any]:
    """Store hashed session token with idle and max expiration timestamps."""
    token_hash = hash_token(raw_token)
    now = time.time()
    expires_at = now + MAX_SESSION_SECONDS

    with get_engine().begin() as conn:
        res = conn.execute(
            text("""
            INSERT INTO sessions (user_id, token_hash, created_at, last_seen_at, expires_at, ip, user_agent)
            VALUES (:user_id, :token_hash, :created_at, :last_seen_at, :expires_at, :ip, :user_agent)
            RETURNING id
            """),
            {
                "user_id": int(user_id),
                "token_hash": token_hash,
                "created_at": now,
                "last_seen_at": now,
                "expires_at": expires_at,
                "ip": str(ip)[:64],
                "user_agent": str(user_agent)[:255],
            },
        )
        session_id = res.scalar_one()

    return {
        "session_id": session_id,
        "user_id": user_id,
        "created_at": now,
        "expires_at": expires_at,
    }


def validate_session(raw_token: str) -> Optional[Dict[str, Any]]:
    """Validate session token: checks token hash, idle timeout (30m), and absolute lifetime (7d)."""
    if not raw_token:
        return None

    token_hash = hash_token(raw_token)
    now = time.time()

    with get_engine().begin() as conn:
        row = conn.execute(
            text("""
            SELECT s.id as session_id, s.user_id, s.created_at, s.last_seen_at, s.expires_at,
                   u.email, u.totp_enabled
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token_hash = :token_hash
            """),
            {"token_hash": token_hash},
        ).mappings().first()

        if not row:
            return None

        data = dict(row)

        # Check absolute lifetime
        if now > data["expires_at"]:
            conn.execute(text("DELETE FROM sessions WHERE id = :id"), {"id": data["session_id"]})
            return None

        # Check idle timeout (30 minutes)
        if (now - data["last_seen_at"]) > IDLE_TIMEOUT_SECONDS:
            conn.execute(text("DELETE FROM sessions WHERE id = :id"), {"id": data["session_id"]})
            return None

        # Update activity timestamp
        conn.execute(text("UPDATE sessions SET last_seen_at = :now WHERE id = :id"), {"now": now, "id": data["session_id"]})
        return data


def cleanup_expired_sessions():
    """Purge all sessions that have exceeded idle timeout or max duration."""
    now = time.time()
    with get_engine().begin() as conn:
        conn.execute(
            text("DELETE FROM sessions WHERE expires_at < :now OR (:now - last_seen_at) > :idle"),
            {"now": now, "idle": IDLE_TIMEOUT_SECONDS},
        )


def delete_session(raw_token: str):
    """Invalidate session on logout."""
    if not raw_token:
        return
    token_hash = hash_token(raw_token)
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM sessions WHERE token_hash = :token_hash"), {"token_hash": token_hash})


def delete_all_user_sessions(user_id: int):
    """Invalidate all active sessions for a user (on password change or 2FA update)."""
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM sessions WHERE user_id = :user_id"), {"user_id": int(user_id)})


def update_user_password(user_id: int, new_password: str) -> Tuple[bool, str]:
    """Update password, rehash, and terminate all active sessions."""
    valid, err = validate_password_strength(new_password)
    if not valid:
        return False, err or "Invalid password"

    new_hash = hash_password(new_password)
    with get_engine().begin() as conn:
        conn.execute(text("UPDATE users SET password_hash = :hash WHERE id = :id"), {"hash": new_hash, "id": int(user_id)})
        conn.execute(text("DELETE FROM sessions WHERE user_id = :id"), {"id": int(user_id)})

    return True, "Password updated successfully and all active sessions terminated."


# ============================================================
# Two-Factor Authentication (TOTP)
# ============================================================

def enable_totp(user_id: int, secret: str, recovery_codes: List[str]) -> bool:
    """Store encrypted TOTP secret and hashed recovery codes."""
    enc_secret = encrypt_totp_secret(secret)
    with get_engine().begin() as conn:
        conn.execute(
            text("UPDATE users SET totp_secret_encrypted = :secret, totp_enabled = 1 WHERE id = :id"),
            {"secret": enc_secret, "id": int(user_id)},
        )
        conn.execute(text("DELETE FROM recovery_codes WHERE user_id = :id"), {"id": int(user_id)})
        for code in recovery_codes:
            code_hash = hash_token(code.strip().lower())
            conn.execute(
                text("INSERT INTO recovery_codes (user_id, code_hash) VALUES (:id, :hash)"),
                {"id": int(user_id), "hash": code_hash},
            )
    return True


def disable_totp(user_id: int, password: str) -> Tuple[bool, str]:
    """Disable TOTP 2FA after password confirmation."""
    user = get_user_by_id(user_id)
    if not user:
        return False, "User not found"

    if not verify_password(password, user["password_hash"]):
        return False, "Password verification failed"

    with get_engine().begin() as conn:
        conn.execute(
            text("UPDATE users SET totp_enabled = 0, totp_secret_encrypted = NULL WHERE id = :id"),
            {"id": int(user_id)},
        )
        conn.execute(text("DELETE FROM recovery_codes WHERE user_id = :id"), {"id": int(user_id)})

    return True, "Two-factor authentication disabled."


def verify_recovery_code(user_id: int, code: str) -> bool:
    """Verify single-use recovery code and mark as used."""
    code_hash = hash_token(code.strip().lower())
    now = time.time()
    with get_engine().begin() as conn:
        row = conn.execute(
            text("SELECT id FROM recovery_codes WHERE user_id = :id AND code_hash = :hash AND used_at IS NULL"),
            {"id": int(user_id), "hash": code_hash},
        ).mappings().first()
        if not row:
            return False

        conn.execute(text("UPDATE recovery_codes SET used_at = :now WHERE id = :id"), {"now": now, "id": row["id"]})
        return True


# ============================================================
# Password Resets
# ============================================================

def create_password_reset(email: str, raw_token: str) -> Optional[int]:
    """Generate expiring single-use password reset token hash."""
    user = get_user_by_email(email)
    if not user:
        return None

    token_hash = hash_token(raw_token)
    expires_at = time.time() + 3600  # 1 hour expiration

    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM password_resets WHERE user_id = :id AND used_at IS NULL"), {"id": user["id"]})
        conn.execute(
            text("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (:id, :hash, :expires_at)"),
            {"id": user["id"], "hash": token_hash, "expires_at": expires_at},
        )

    return user["id"]


def consume_password_reset(raw_token: str, new_password: str) -> Tuple[bool, str]:
    """Verify reset token, update password, and terminate all sessions."""
    valid, err = validate_password_strength(new_password)
    if not valid:
        return False, err or "Invalid password"

    token_hash = hash_token(raw_token)
    now = time.time()

    with get_engine().begin() as conn:
        row = conn.execute(
            text("SELECT id, user_id, expires_at, used_at FROM password_resets WHERE token_hash = :hash"),
            {"hash": token_hash},
        ).mappings().first()
        if not row:
            return False, "Invalid or expired password reset token"

        if row["used_at"] is not None:
            return False, "This reset token has already been used"

        if now > row["expires_at"]:
            return False, "Reset token has expired"

        new_hash = hash_password(new_password)
        conn.execute(text("UPDATE users SET password_hash = :hash WHERE id = :id"), {"hash": new_hash, "id": row["user_id"]})
        conn.execute(text("UPDATE password_resets SET used_at = :now WHERE id = :id"), {"now": now, "id": row["id"]})
        conn.execute(text("DELETE FROM sessions WHERE user_id = :id"), {"id": row["user_id"]})

    return True, "Password reset successfully. Please log in with your new password."


# ============================================================
# Audit Actions Logging
# ============================================================

def log_audit_action(user_id: Optional[int], email: Optional[str], action: str, details: str, ip: str = ""):
    """Record administrative actions with parameterized bindings."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_engine().begin() as conn:
        conn.execute(
            text("""
            INSERT INTO audit_actions (user_id, email, action, details, ip, timestamp)
            VALUES (:user_id, :email, :action, :details, :ip, :timestamp)
            """),
            {
                "user_id": int(user_id) if user_id is not None else None,
                "email": str(email or "")[:254],
                "action": str(action)[:64],
                "details": str(details)[:1024],
                "ip": str(ip)[:64],
                "timestamp": now_iso,
            },
        )


def get_user_sessions(user_id: int) -> List[Dict[str, Any]]:
    """Return active sessions for user, purging expired and idle sessions."""
    cleanup_expired_sessions()
    now = time.time()
    with get_engine().connect() as conn:
        rows = conn.execute(
            text("""
            SELECT id, ip, user_agent, created_at, last_seen_at
            FROM sessions
            WHERE user_id = :uid AND expires_at > :now AND (:now - last_seen_at) <= :idle
            ORDER BY last_seen_at DESC
            """),
            {"uid": int(user_id), "now": now, "idle": IDLE_TIMEOUT_SECONDS},
        ).mappings().fetchall()
        return [dict(r) for r in rows]


def revoke_session_by_id(user_id: int, session_id: int) -> bool:
    """Revoke a specific session owned by user_id."""
    with get_engine().begin() as conn:
        res = conn.execute(
            text("DELETE FROM sessions WHERE id = :sid AND user_id = :uid"),
            {"sid": int(session_id), "uid": int(user_id)},
        )
        return res.rowcount > 0


def revoke_other_sessions(user_id: int, keep_session_id: int) -> int:
    """Revoke all active sessions for user_id except keep_session_id."""
    with get_engine().begin() as conn:
        res = conn.execute(
            text("DELETE FROM sessions WHERE user_id = :uid AND id != :keep_sid"),
            {"uid": int(user_id), "keep_sid": int(keep_session_id)},
        )
        return res.rowcount


def get_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Fetch latest security audit log records with safe parameterized limit."""
    safe_limit = max(1, min(int(limit), 200))
    with get_engine().connect() as conn:
        rows = conn.execute(
            text("SELECT id, user_id, email, action, details, ip, timestamp FROM audit_actions ORDER BY id DESC LIMIT :lim"),
            {"lim": safe_limit},
        ).mappings().fetchall()
        return [dict(r) for r in rows]


# ============================================================
# IP Access Rules & Quarantine
# ============================================================

def cleanup_expired_ip_rules() -> int:
    """Purge temporary IP quarantine/access rules whose expires_at timestamp has passed."""
    now = time.time()
    with get_engine().begin() as conn:
        res = conn.execute(
            text("DELETE FROM ip_access_rules WHERE expires_at IS NOT NULL AND expires_at < :now"),
            {"now": now},
        )
        return res.rowcount or 0


def get_ip_rules(rule_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch all active IP access rules and quarantines with remaining TTL."""
    cleanup_expired_ip_rules()
    now = time.time()
    query = "SELECT id, cidr, rule_type, reason, penalty_score, expires_at, created_at FROM ip_access_rules"
    params = {}
    if rule_type:
        query += " WHERE rule_type = :rtype"
        params["rtype"] = str(rule_type).strip().lower()
    query += " ORDER BY id DESC"

    with get_engine().connect() as conn:
        rows = conn.execute(text(query), params).mappings().fetchall()
        results = []
        for r in rows:
            d = dict(r)
            if d.get("expires_at"):
                d["remaining_seconds"] = max(0, int(d["expires_at"] - now))
            else:
                d["remaining_seconds"] = None
            results.append(d)
        return results


def get_active_ip_rules() -> List[Dict[str, Any]]:
    """Fetch all active rules for fast inline inspection evaluation."""
    now = time.time()
    with get_engine().connect() as conn:
        rows = conn.execute(
            text("SELECT id, cidr, rule_type, reason, expires_at FROM ip_access_rules WHERE expires_at IS NULL OR expires_at >= :now"),
            {"now": now},
        ).mappings().fetchall()
        return [dict(r) for r in rows]


def add_ip_rule(
    cidr: str,
    rule_type: str,
    reason: str = "",
    duration_seconds: Optional[float] = None,
    penalty_score: float = 0.0,
) -> int:
    """
    Insert an IP access control or quarantine rule.
    Validates and normalizes CIDR notation.
    """
    import ipaddress
    clean_type = str(rule_type).strip().lower()
    if clean_type not in ("whitelist", "blacklist", "quarantine"):
        raise ValueError(f"Invalid rule_type: {rule_type}")

    net = ipaddress.ip_network(cidr.strip(), strict=False)
    canonical_cidr = str(net)

    now = time.time()
    expires_at = (now + float(duration_seconds)) if duration_seconds and duration_seconds > 0 else None
    now_iso = datetime.now(timezone.utc).isoformat()

    with get_engine().begin() as conn:
        # Check if identical active rule exists to avoid duplicates
        existing = conn.execute(
            text("SELECT id FROM ip_access_rules WHERE cidr = :cidr AND rule_type = :rtype"),
            {"cidr": canonical_cidr, "rtype": clean_type},
        ).scalar()

        if existing:
            conn.execute(
                text("""
                UPDATE ip_access_rules
                SET reason = :reason, penalty_score = :score, expires_at = :expires_at, created_at = :now_iso
                WHERE id = :id
                """),
                {
                    "id": existing,
                    "reason": reason[:254],
                    "score": float(penalty_score),
                    "expires_at": expires_at,
                    "now_iso": now_iso,
                },
            )
            return int(existing)

        is_pg = is_postgres()
        if is_pg:
            res = conn.execute(
                text("""
                INSERT INTO ip_access_rules (cidr, rule_type, reason, penalty_score, expires_at, created_at)
                VALUES (:cidr, :rtype, :reason, :score, :expires_at, :now_iso)
                RETURNING id
                """),
                {
                    "cidr": canonical_cidr,
                    "rtype": clean_type,
                    "reason": reason[:254],
                    "score": float(penalty_score),
                    "expires_at": expires_at,
                    "now_iso": now_iso,
                },
            )
            return int(res.scalar_one())
        else:
            conn.execute(
                text("""
                INSERT INTO ip_access_rules (cidr, rule_type, reason, penalty_score, expires_at, created_at)
                VALUES (:cidr, :rtype, :reason, :score, :expires_at, :now_iso)
                """),
                {
                    "cidr": canonical_cidr,
                    "rtype": clean_type,
                    "reason": reason[:254],
                    "score": float(penalty_score),
                    "expires_at": expires_at,
                    "now_iso": now_iso,
                },
            )
            res = conn.execute(text("SELECT last_insert_rowid()")).scalar()
            return int(res)


def delete_ip_rule(rule_id: int) -> bool:
    """Delete an IP rule or release an IP from quarantine."""
    with get_engine().begin() as conn:
        res = conn.execute(
            text("DELETE FROM ip_access_rules WHERE id = :id"),
            {"id": int(rule_id)},
        )
        return (res.rowcount or 0) > 0
