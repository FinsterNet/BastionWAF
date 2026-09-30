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

        # Clean up any legacy default site so users start with a clean slate
        conn.execute("DELETE FROM protected_sites WHERE domain = '127.0.0.1:8080' AND upstream = '127.0.0.1:3000'")
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


def get_threat_category_counts() -> Dict[str, Any]:
    with get_connection() as conn:
        cursor = conn.cursor()

        # 1. Active rule suite breakdown
        cursor.execute("SELECT category, COUNT(*) FROM waf_rules WHERE enabled = 1 GROUP BY category")
        rule_counts = {"OWASP Top 10": 0, "API Security": 0, "Bot Protection": 0}
        for cat, cnt in cursor.fetchall():
            if cat in rule_counts:
                rule_counts[cat] = cnt

        # 2. Real attack events from database
        cursor.execute(
            """
            SELECT e.rule_id, e.reason, COUNT(*) as hit_count
            FROM events e
            WHERE e.blocked = 1 OR e.action = 'CAPTCHA Challenged'
            GROUP BY e.rule_id, e.reason
            """
        )
        rows = cursor.fetchall()

        # Build lookup table from waf_rules
        cursor.execute("SELECT rule_id, category FROM waf_rules")
        rule_cat_map = {r["rule_id"]: r["category"] for r in cursor.fetchall()}

        threat_counts = {"OWASP Top 10": 0, "API Security": 0, "Bot Protection": 0}
        for row in rows:
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
    with get_connection() as conn:
        cursor = conn.cursor()

        # 1. Top active client IPs (real data, no fake countries)
        cursor.execute(
            """
            SELECT client_ip, COUNT(*) as hit_count,
                   SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_count,
                   MAX(timestamp) as last_seen
            FROM events
            WHERE client_ip != ''
            GROUP BY client_ip
            ORDER BY hit_count DESC
            LIMIT ?
            """,
            (limit,),
        )
        top_ips = [
            {
                "ip": r["client_ip"],
                "total": r["hit_count"],
                "blocked": r["blocked_count"],
                "last_seen": r["last_seen"],
            }
            for r in cursor.fetchall()
        ]

        # 2. Top targeted endpoints
        cursor.execute(
            """
            SELECT path, COUNT(*) as hit_count,
                   SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_count
            FROM events
            WHERE path != ''
            GROUP BY path
            ORDER BY hit_count DESC
            LIMIT 4
            """
        )
        top_paths = [
            {"path": r["path"], "total": r["hit_count"], "blocked": r["blocked_count"]}
            for r in cursor.fetchall()
        ]

        # 3. Top triggered defense rules
        cursor.execute(
            """
            SELECT e.rule_id, COALESCE(r.rule_name, e.reason) as rule_name,
                   COALESCE(r.category, 'OWASP Top 10') as category,
                   COUNT(*) as trigger_count
            FROM events e
            LEFT JOIN waf_rules r ON e.rule_id = r.rule_id
            WHERE e.blocked = 1 OR e.action = 'CAPTCHA Challenged'
            GROUP BY e.rule_id
            ORDER BY trigger_count DESC
            LIMIT 4
            """
        )
        top_rules = [
            {
                "rule_id": r["rule_id"] or "ANOMALY",
                "name": r["rule_name"],
                "category": r["category"],
                "count": r["trigger_count"],
            }
            for r in cursor.fetchall()
        ]

        cursor.execute("SELECT COUNT(DISTINCT client_ip) FROM events")
        total_unique_ips = cursor.fetchone()[0] or 0

        return {
            "top_ips": top_ips,
            "top_paths": top_paths,
            "top_rules": top_rules,
            "unique_ips": total_unique_ips,
        }


def get_stats() -> Dict[str, Any]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM events WHERE blocked = 1")
        blocked = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM events WHERE action = 'CAPTCHA Challenged'")
        challenged = cursor.fetchone()[0]

        cursor.execute("SELECT blocked FROM events ORDER BY id DESC LIMIT 70")
        event_rows = cursor.fetchall()
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
