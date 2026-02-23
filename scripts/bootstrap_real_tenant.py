#!/usr/bin/env python3

# Copyright (c) 2026 NyxeraLabs
# Author: José María Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-17 → Apache-2.0
#
# You may:
# ✔ Study
# ✔ Modify
# ✔ Use for internal security testing
#
# You may NOT:
# ✘ Offer as a commercial service
# ✘ Sell derived competing products

"""
Bootstrap a real tenant (no demo/dummy records) for production-style validation.
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vv_core import Database, Role, SessionCrypto


def _role_from_name(role_name: str) -> str:
    mapping = {
        "viewer": Role.VIEWER,
        "operator": Role.OPERATOR,
        "lead": Role.LEAD,
        "admin": Role.ADMIN,
    }
    key = (role_name or "").strip().lower()
    if key not in mapping:
        raise ValueError(f"invalid role '{role_name}' (use viewer|operator|lead|admin)")
    return mapping[key]


def ensure_tenant(pg_url: str, tenant_id: str, tenant_name: str) -> str:
    with psycopg.connect(pg_url, autocommit=False) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tenants (id, name, active)
                VALUES (%s, %s, TRUE)
                ON CONFLICT (id) DO UPDATE
                SET name=EXCLUDED.name,
                    active=TRUE
                """,
                (tenant_id, tenant_name),
            )
        conn.commit()
    return tenant_id


def ensure_user(db: Database, username: str, password: str, role: str) -> str:
    ok, _ = db.authenticate_user(username, password)
    if ok:
        return "present"
    created, msg = db.register_user(username, password, role=role, group_name="default", bypass_legal=True)
    if created:
        return "created"
    if "already exists" in msg.lower():
        return "exists_with_different_password"
    return f"error:{msg}"


def assign_user_tenant_access(db: Database, username: str, tenant_id: str, access_role: str) -> None:
    c = db.conn.cursor()
    c.execute("SELECT id FROM users WHERE username=?", (username,))
    row = c.fetchone()
    if not row:
        raise RuntimeError(f"user not found for tenant mapping: {username}")
    user_id = int(row["id"])
    c.execute(
        """INSERT INTO user_tenant_access (user_id, username, tenant_id, access_role, active)
           VALUES (?, ?, ?, ?, TRUE)
           ON CONFLICT (user_id, tenant_id) DO UPDATE SET
             username=EXCLUDED.username,
             access_role=EXCLUDED.access_role,
             active=TRUE""",
        (user_id, username, tenant_id, access_role),
    )
    db.conn.commit()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bootstrap tenant/users without dummy records")
    parser.add_argument("--backend", choices=["postgres"], default="postgres")
    parser.add_argument("--pg-url", required=True)
    parser.add_argument("--tenant-name", required=True)
    parser.add_argument("--tenant-id", default="auto")
    parser.add_argument("--admin-user", required=True)
    parser.add_argument("--admin-pass", required=True)
    parser.add_argument("--client-user", required=True)
    parser.add_argument("--client-pass", required=True)
    parser.add_argument("--client-role", default="viewer")
    parser.add_argument("--operator-user", default="")
    parser.add_argument("--operator-pass", default="")
    parser.add_argument("--operator-role", default="operator")
    parser.add_argument(
        "--passphrase",
        default=None,
        help="Database encryption passphrase (defaults to --admin-pass).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    tenant_id = str(uuid.uuid4()) if args.tenant_id == "auto" else str(args.tenant_id)

    os.environ["VV_DB_BACKEND"] = "postgres"
    os.environ["VV_DB_URL"] = args.pg_url

    passphrase = args.passphrase or args.admin_pass
    crypto = SessionCrypto()
    if not crypto.derive_key(passphrase):
        raise RuntimeError("failed to derive encryption key")

    db = Database(crypto_manager=crypto)
    try:
        if db.has_users() and not db.verify_or_set_canary():
            raise RuntimeError(
                "existing DB encrypted with another passphrase. "
                "Use --passphrase with the original value or reset DB."
            )

        ensure_tenant(args.pg_url, tenant_id, args.tenant_name)

        admin_status = ensure_user(db, args.admin_user, args.admin_pass, Role.ADMIN)
        client_status = ensure_user(db, args.client_user, args.client_pass, _role_from_name(args.client_role))

        operator_status = "skipped"
        if args.operator_user.strip() and args.operator_pass.strip():
            operator_status = ensure_user(db, args.operator_user, args.operator_pass, _role_from_name(args.operator_role))

        assign_user_tenant_access(db, args.admin_user, tenant_id, "admin")
        assign_user_tenant_access(db, args.client_user, tenant_id, args.client_role)
        if args.operator_user.strip():
            assign_user_tenant_access(db, args.operator_user, tenant_id, args.operator_role)

        print("Real tenant bootstrap complete.")
        print(f"tenant_id={tenant_id}")
        print(f"tenant_name={args.tenant_name}")
        print(f"admin={args.admin_user} status={admin_status}")
        print(f"client={args.client_user} role={args.client_role} status={client_status}")
        if args.operator_user.strip():
            print(f"operator={args.operator_user} role={args.operator_role} status={operator_status}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
