"""
Bastion WAF Administrative Command-Line Interface (CLI).
Provides local server commands to initialize administrator accounts,
reset passwords, unlock locked accounts, and inspect security status.
"""

import argparse
import sys
from pathlib import Path

# Ensure the waf directory is on python module path
WAF_DIR = Path(__file__).resolve().parent
if str(WAF_DIR) not in sys.path:
    sys.path.insert(0, str(WAF_DIR))

from database.db import (
    create_user,
    get_connection,
    get_user_by_email,
    has_users,
    init_db,
    list_all_users,
    unlock_user_account,
    update_user_password,
)


import getpass


def cmd_create_admin(args):
    init_db()
    email = args.email.strip().lower()
    try:
        password = getpass.getpass("Enter administrator password (min 12 characters): ")
        confirm = getpass.getpass("Confirm password: ")
    except (EOFError, KeyboardInterrupt):
        print("\n❌ Operation cancelled.")
        sys.exit(1)

    if password != confirm:
        print("❌ Error: Passwords do not match.")
        sys.exit(1)

    success, msg, user_id = create_user(email, password)
    if success:
        print(f"🛡️  Administrator '{email}' created successfully (ID: {user_id}).")
    else:
        print(f"❌ Failed to create administrator: {msg}")
        sys.exit(1)


def cmd_reset_password(args):
    init_db()
    email = args.email.strip().lower()
    user = get_user_by_email(email)
    if not user:
        print(f"❌ No administrator account found with email '{email}'.")
        sys.exit(1)

    try:
        password = getpass.getpass(f"Enter new password for '{email}' (min 12 characters): ")
        confirm = getpass.getpass("Confirm password: ")
    except (EOFError, KeyboardInterrupt):
        print("\n❌ Operation cancelled.")
        sys.exit(1)

    if password != confirm:
        print("❌ Error: Passwords do not match.")
        sys.exit(1)

    success, msg = update_user_password(user["id"], password)
    if success:
        print(f"✅ Password for '{email}' successfully reset. All active sessions terminated.")
    else:
        print(f"❌ Failed to reset password: {msg}")
        sys.exit(1)


def cmd_unlock(args):
    init_db()
    email = args.email.strip().lower()
    user = get_user_by_email(email)
    if not user:
        print(f"❌ No administrator account found with email '{email}'.")
        sys.exit(1)

    unlock_user_account(email)
    print(f"🔓 Administrator account '{email}' unlocked. Failed attempts counter reset to 0.")


def cmd_list_users(args):
    init_db()
    rows = list_all_users()
    if not rows:
        print("ℹ️  No administrator accounts registered. Run 'python cli.py create-admin' or use the web setup.")
        return

    print("\n" + "=" * 70)
    print("🛡️   BASTION WAF REGISTERED ADMINISTRATORS")
    print("=" * 70)
    for r in rows:
        totp = "Enabled (2FA)" if r["totp_enabled"] else "Disabled"
        locked = "LOCKED" if r["failed_attempts"] >= 5 else "Active"
        print(f"  • ID: {r['id']:<3} | Email: {r['email']:<28} | 2FA: {totp:<14} | Status: {locked}")
    print("=" * 70 + "\n")


def create_admin_cmd(email: str) -> bool:
    """Programmatic helper to invoke create-admin CLI logic."""
    class Args:
        pass
    args = Args()
    args.email = email
    try:
        cmd_create_admin(args)
        return True
    except SystemExit as e:
        return e.code == 0


def reset_password_cmd(email: str) -> bool:
    """Programmatic helper to invoke reset-password CLI logic."""
    class Args:
        pass
    args = Args()
    args.email = email
    try:
        cmd_reset_password(args)
        return True
    except SystemExit as e:
        return e.code == 0


def main():
    parser = argparse.ArgumentParser(description="Bastion WAF Administrative Security CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # create-admin
    p_create = subparsers.add_parser("create-admin", help="Create a new administrator account")
    p_create.add_argument("--email", required=True, help="Administrator email address")
    p_create.set_defaults(func=cmd_create_admin)

    # reset-password
    p_reset = subparsers.add_parser("reset-password", help="Reset password for an existing administrator")
    p_reset.add_argument("--email", required=True, help="Administrator email address")
    p_reset.set_defaults(func=cmd_reset_password)

    # unlock
    p_unlock = subparsers.add_parser("unlock", help="Unlock an account locked from failed attempts")
    p_unlock.add_argument("--email", required=True, help="Administrator email address")
    p_unlock.set_defaults(func=cmd_unlock)

    # list-users
    p_list = subparsers.add_parser("list-users", help="List registered administrator accounts")
    p_list.set_defaults(func=cmd_list_users)

    # migrate-to-postgres
    p_mig = subparsers.add_parser("migrate-to-postgres", help="Migrate SQLite database records to PostgreSQL")
    p_mig.add_argument("--sqlite-path", default=None, help="Path to source SQLite file (default: BASTION_DB_PATH)")
    p_mig.add_argument("--pg-url", default=None, help="Target PostgreSQL connection URL (default: DATABASE_URL)")
    p_mig.set_defaults(func=cmd_migrate_to_postgres)

    args = parser.parse_args()
    args.func(args)


def cmd_migrate_to_postgres(args):
    from database.db import migrate_sqlite_to_postgres
    sqlite_path = args.sqlite_path
    pg_url = args.pg_url
    print("🚚 Initiating migration from SQLite to PostgreSQL...")
    ok, msg, counts = migrate_sqlite_to_postgres(sqlite_path=sqlite_path, pg_url=pg_url)
    if ok:
        print(f"✅ {msg}")
        print("📊 Migrated Records:")
        for table, cnt in counts.items():
            print(f"   • {table}: {cnt}")
    else:
        print(f"❌ {msg}")
        sys.exit(1)


if __name__ == "__main__":
    main()
