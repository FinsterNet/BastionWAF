"""
SQLite database storage for WAF security events, rules, and protected sites.
"""

from datetime import datetime, timezone
import io
import csv
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Set

DB_PATH = Path(__file__).resolve().parent / "waf.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.execute(
            """
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
                payload_snippet TEXT DEFAULT ''
            )
            """
        )

        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(events)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        if "action" not in existing_cols:
            conn.execute("ALTER TABLE events ADD COLUMN action TEXT")
        if "payload_snippet" not in existing_cols:
            conn.execute("ALTER TABLE events ADD COLUMN payload_snippet TEXT DEFAULT ''")
        if "rule_score" not in existing_cols:
            conn.execute("ALTER TABLE events ADD COLUMN rule_score REAL DEFAULT 0.0")
        if "semantic_score" not in existing_cols:
            conn.execute("ALTER TABLE events ADD COLUMN semantic_score REAL DEFAULT 0.0")
        if "total_score" not in existing_cols:
            conn.execute("ALTER TABLE events ADD COLUMN total_score REAL DEFAULT 0.0")
        if "raw_payload" not in existing_cols:
            conn.execute("ALTER TABLE events ADD COLUMN raw_payload TEXT DEFAULT ''")
        if "normalized_payload" not in existing_cols:
            conn.execute("ALTER TABLE events ADD COLUMN normalized_payload TEXT DEFAULT ''")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS waf_rules (
                rule_id TEXT PRIMARY KEY,
                rule_name TEXT,
                category TEXT,
                enabled INTEGER
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS protected_sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                upstream TEXT,
                ssl_status TEXT,
                defense_mode INTEGER
            )
            """
        )

        default_rules = [
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
        ]
        for r in default_rules:
            conn.execute(
                "INSERT OR REPLACE INTO waf_rules (rule_id, rule_name, category, enabled) VALUES (?, ?, ?, COALESCE((SELECT enabled FROM waf_rules WHERE rule_id = ?), ?))",
                (r[0], r[1], r[2], r[0], r[3]),
            )

        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM protected_sites")
        count_row = cursor.fetchone()
        if count_row and count_row[0] == 0:
            conn.execute(
                "INSERT INTO protected_sites (id, domain, upstream, ssl_status, defense_mode) VALUES (1, '127.0.0.1:8080', '127.0.0.1:3000', 'Active', 1)"
            )
        conn.commit()


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
    if action is None:
        action = "403 Blocked" if blocked else "200 Allowed"
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO events (
                timestamp, client_ip, method, path, blocked, rule_id, reason, action,
                payload_snippet, rule_score, semantic_score, total_score, raw_payload, normalized_payload
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                client_ip,
                method,
                path,
                int(blocked),
                rule_id,
                reason,
                action,
                payload_snippet,
                rule_score,
                semantic_score,
                total_score,
                raw_payload,
                normalized_payload,
            ),
        )
        conn.commit()


def get_stats() -> Dict[str, Any]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM events WHERE blocked = 1")
        blocked = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM events WHERE action = 'CAPTCHA Challenged'")
        challenged = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM protected_sites")
        sites = cursor.fetchone()[0]

        return {
            "total_requests": total,
            "blocked_attacks": blocked,
            "challenged_requests": challenged,
            "protected_domains": sites,
            "latency_ms": 0.38,
        }


def get_recent_events(limit: int = 15) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, client_ip, method, path, blocked, rule_id, reason,
                   COALESCE(action, CASE WHEN blocked = 1 THEN '403 Blocked' ELSE '200 Allowed' END) as action,
                   COALESCE(payload_snippet, '') as payload_snippet
            FROM events ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_logs(query: str = "", threat: str = "All Threat Types", limit: int = 50) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        sql = """
            SELECT id, timestamp, client_ip, method, path, blocked, rule_id, reason,
                   COALESCE(action, CASE WHEN blocked = 1 THEN '403 Blocked' ELSE '200 Allowed' END) as action,
                   COALESCE(payload_snippet, '') as payload_snippet
            FROM events WHERE (client_ip LIKE ? OR path LIKE ? OR payload_snippet LIKE ?)
        """
        params: List[Any] = [f"%{query}%", f"%{query}%", f"%{query}%"]
        if threat and threat != "All Threat Types":
            sql += " AND (reason LIKE ? OR rule_id LIKE ?)"
            params.extend([f"%{threat}%", f"%{threat}%"])
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cursor.execute(sql, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def clear_logs():
    with get_connection() as conn:
        conn.execute("DELETE FROM events")
        conn.commit()


def export_logs_csv() -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Client IP", "Method", "Path", "Blocked", "Rule ID", "Reason", "Action", "Payload Snippet"])
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, client_ip, method, path, blocked, rule_id, reason, action, payload_snippet FROM events ORDER BY id DESC")
        for row in cursor.fetchall():
            writer.writerow(list(row))
    return output.getvalue()


def get_rules() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT rule_id, rule_name, category, enabled FROM waf_rules")
        rows = cursor.fetchall()
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
    with get_connection() as conn:
        conn.execute("UPDATE waf_rules SET enabled = ? WHERE rule_id = ?", (1 if enabled else 0, rule_id))
        conn.commit()


def get_enabled_rule_ids() -> Set[str]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT rule_id FROM waf_rules WHERE enabled = 1")
        rows = cursor.fetchall()
        return {r[0] for r in rows}


def get_sites() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, domain, upstream, ssl_status, defense_mode FROM protected_sites")
        rows = cursor.fetchall()
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
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO protected_sites (domain, upstream, ssl_status, defense_mode)
            VALUES (?, ?, ?, ?)
            """,
            (domain, upstream, ssl_status, 1 if defense_mode else 0),
        )
        conn.commit()


def set_site_defense(site_id: int, defense_mode: bool):
    with get_connection() as conn:
        conn.execute("UPDATE protected_sites SET defense_mode = ? WHERE id = ?", (1 if defense_mode else 0, site_id))
        conn.commit()


def delete_site(site_id: int):
    with get_connection() as conn:
        conn.execute("DELETE FROM protected_sites WHERE id = ?", (site_id,))
        conn.commit()
