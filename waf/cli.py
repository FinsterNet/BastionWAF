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


def cmd_create_admin(args):
    init_db()
    email = args.email.strip().lower()
    password = args.password

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

    success, msg = update_user_password(user["id"], args.password)
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


def main():
    parser = argparse.ArgumentParser(description="Bastion WAF Administrative Security CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # create-admin
    p_create = subparsers.add_parser("create-admin", help="Create a new administrator account")
    p_create.add_argument("--email", required=True, help="Administrator email address")
    p_create.add_argument("--password", required=True, help="Strong password (min 12 characters)")
    p_create.set_defaults(func=cmd_create_admin)

    # reset-password
    p_reset = subparsers.add_parser("reset-password", help="Reset password for an existing administrator")
    p_reset.add_argument("--email", required=True, help="Administrator email address")
    p_reset.add_argument("--password", required=True, help="New password (min 12 characters)")
    p_reset.set_defaults(func=cmd_reset_password)

    # unlock
    p_unlock = subparsers.add_parser("unlock", help="Unlock an account locked from failed attempts")
    p_unlock.add_argument("--email", required=True, help="Administrator email address")
    p_unlock.set_defaults(func=cmd_unlock)

    # list-users
    p_list = subparsers.add_parser("list-users", help="List registered administrator accounts")
    p_list.set_defaults(func=cmd_list_users)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
