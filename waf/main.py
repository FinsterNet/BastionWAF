"""
BastionWAF Enterprise Security Gateway Launcher.
Runs the high-performance WAF Reverse Proxy with asynchronous OpenSearch SIEM telemetry.
Configuration loaded from bastion.yaml.
"""

import argparse
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uvicorn

# Ensure the waf directory is on python module path
WAF_DIR = Path(__file__).resolve().parent
if str(WAF_DIR) not in sys.path:
    sys.path.insert(0, str(WAF_DIR))

from datetime import datetime, timezone
from sqlalchemy import text
from bastion.core.config import get_config
from database.db import (
    create_first_admin_atomic,
    get_engine,
    get_user_by_email,
    has_users,
    hash_password,
    init_db,
    update_user_password,
)


def free_port(port: int):
    """Ensure port is available by clearing any stale process holding it."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                subprocess.run(f"fuser -k {port}/tcp 2>/dev/null", shell=True)
                time.sleep(0.3)
    except Exception:
        pass


def main():
    cfg = get_config()
    env_port = int(os.environ.get("PORT", cfg.server.port))
    env_host = os.environ.get("BASTION_HOST", cfg.server.host)

    parser = argparse.ArgumentParser(description="Bastion WAF Gateway")
    parser.add_argument("--host", default=env_host, help="Bind host (default from bastion.yaml or BASTION_HOST)")
    parser.add_argument("--port", type=int, default=env_port, help="Bind port (default from bastion.yaml or PORT)")
    args = parser.parse_args()

    host = args.host
    port = args.port

    free_port(port)

    os_status = f"Enabled -> {', '.join(cfg.opensearch.hosts)}" if cfg.opensearch.enabled else "Disabled (Local JSONL Fallback)"

    print("\n" + "=" * 72)
    print("🛡️   BASTION WAF ENTERPRISE SECURITY GATEWAY")
    print("=" * 72)
    print(f"  🔒  WAF Reverse Proxy Gateway:  http://{host}:{port}")
    print(f"  📡  OpenSearch SIEM Telemetry:   {os_status}")
    print(f"  📋  Config File:                 {Path(os.environ.get('BASTION_CONFIG', 'config/bastion.yaml')).resolve()}")
    print("=" * 72)
    if cfg.sites:
        print("  🌐  Configured Upstream Sites:")
        for s in cfg.sites:
            mode = "Active Defense" if s.defense_mode else "Bypass"
            print(f"      • {s.domain:20} -> {s.upstream} ({mode})")
    init_db()
    admin_user = os.environ.get("BASTION_ADMIN_USER", "admin")
    admin_password = os.environ.get("BASTION_ADMIN_PASSWORD", "@Robelshitahun7")
    if not has_users():
        success, msg, uid = create_first_admin_atomic(admin_user, admin_password)
        if success:
            print(f"  👑  Default administrator account created: '{admin_user}'")
    elif admin_user and admin_password:
        existing = get_user_by_email(admin_user)
        if existing:
            update_user_password(existing["id"], admin_password)
            with get_engine().begin() as conn:
                conn.execute(
                    text("UPDATE users SET failed_attempts = 0, locked_until = 0.0 WHERE id = :id"),
                    {"id": existing["id"]},
                )
            print(f"  👑  Administrator credentials synced for: '{admin_user}'")
        else:
            h = hash_password(admin_password)
            with get_engine().begin() as conn:
                conn.execute(
                    text("INSERT INTO users (email, password_hash, created_at) VALUES (:e, :h, :c)"),
                    {"e": admin_user.strip().lower(), "h": h, "c": datetime.now(timezone.utc).isoformat()},
                )
            print(f"  👑  Administrator account provisioned: '{admin_user}'")

    print("=" * 72)
    print("  Press CTRL+C to stop Bastion WAF.\n")

    os.chdir(str(WAF_DIR))
    uvicorn.run("bastion.core.proxy:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
