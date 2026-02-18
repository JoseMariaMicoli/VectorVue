#!/usr/bin/env python3
"""
Copyright (c) 2026 José María Micoli
Licensed under Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Remove copyright notices

Reset VectorVue local database state for clean testing.
"""

import argparse
import os
from pathlib import Path

import psycopg


ROOT = Path(__file__).resolve().parents[1]


def build_pg_url(explicit_url: str | None) -> str:
    if explicit_url:
        return explicit_url
    env_url = os.environ.get("VV_DB_URL")
    if env_url:
        return env_url
    user = os.environ.get("VV_DB_USER", "vectorvue")
    password = os.environ.get("VV_DB_PASSWORD", "vectorvue")
    host = os.environ.get("VV_DB_HOST", "127.0.0.1")
    port = os.environ.get("VV_DB_PORT", "5432")
    name = os.environ.get("VV_DB_NAME", "vectorvue")
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


def reset_postgres(pg_url: str, drop_schema: bool = False) -> None:
    with psycopg.connect(pg_url, autocommit=False) as conn:
        with conn.cursor() as cur:
            if drop_schema:
                cur.execute("DROP SCHEMA IF EXISTS public CASCADE")
                cur.execute("CREATE SCHEMA public")
                cur.execute("GRANT ALL ON SCHEMA public TO current_user")
                print("Dropped and recreated schema public.")
            else:
                cur.execute(
                    "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
                )
                tables = [row[0] for row in cur.fetchall()]
                if tables:
                    ident_list = ", ".join(f'"{t}"' for t in tables)
                    cur.execute(f"TRUNCATE TABLE {ident_list} RESTART IDENTITY CASCADE")
                    print(f"Truncated {len(tables)} tables in public schema.")
                else:
                    print("No tables found in public schema.")
        conn.commit()


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset VectorVue database and local session.")
    parser.add_argument(
        "--backend",
        choices=["sqlite", "postgres"],
        default=os.environ.get("VV_DB_BACKEND", "sqlite").strip().lower(),
        help="Database backend to reset (default: env VV_DB_BACKEND or sqlite).",
    )
    parser.add_argument(
        "--sqlite-path",
        default=str(ROOT / "vectorvue.db"),
        help="SQLite database path when backend=sqlite.",
    )
    parser.add_argument(
        "--pg-url",
        default=None,
        help="PostgreSQL URL. Falls back to VV_DB_URL or VV_DB_* env vars.",
    )
    parser.add_argument(
        "--drop-schema",
        action="store_true",
        help="For postgres only: drop/recreate schema public instead of truncate.",
    )
    parser.add_argument("--yes", action="store_true", help="Execute reset without prompt.")
    args = parser.parse_args()

    session_file = ROOT / ".vectorvue_session"
    sqlite_path = Path(args.sqlite_path)
    pg_url = build_pg_url(args.pg_url) if args.backend == "postgres" else None

    if not args.yes:
        print("This will reset:")
        if args.backend == "sqlite":
            print(f"  - SQLite DB file: {sqlite_path}")
        else:
            action = "drop+recreate schema public" if args.drop_schema else "truncate all public tables"
            print(f"  - PostgreSQL DB: {pg_url} ({action})")
        print(f"  - Session file: {session_file}")
        confirm = input("Proceed? [y/N] ").strip().lower()
        if confirm not in {"y", "yes"}:
            print("Aborted.")
            return 1

    if args.backend == "sqlite":
        if sqlite_path.exists():
            sqlite_path.unlink()
            print(f"Deleted {sqlite_path}")
        else:
            print(f"Not found {sqlite_path}")
    else:
        reset_postgres(pg_url, drop_schema=args.drop_schema)

    if session_file.exists():
        session_file.unlink()
        print(f"Deleted {session_file}")
    else:
        print(f"Not found {session_file}")

    print(f"Reset complete (backend={args.backend}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
