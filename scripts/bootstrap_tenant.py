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

"""Bootstrap tenant metadata for per-customer deployments."""

from __future__ import annotations

import argparse
import uuid

import psycopg


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bootstrap tenant row in PostgreSQL")
    parser.add_argument("--pg-url", required=True, help="PostgreSQL DSN")
    parser.add_argument("--tenant-name", required=True, help="Tenant display name")
    parser.add_argument("--tenant-id", default="auto", help="Tenant UUID or 'auto'")
    parser.add_argument("--active", action="store_true", default=True, help="Set tenant active (default true)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    tenant_id = str(uuid.uuid4()) if args.tenant_id == "auto" else args.tenant_id

    with psycopg.connect(args.pg_url, autocommit=False) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tenants (id, name, active)
                VALUES (%s, %s, %s)
                ON CONFLICT (id) DO UPDATE
                SET name = EXCLUDED.name,
                    active = EXCLUDED.active
                """,
                (tenant_id, args.tenant_name, args.active),
            )
        conn.commit()

    print(f"Tenant bootstrapped: id={tenant_id} name={args.tenant_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
