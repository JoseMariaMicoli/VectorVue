"""
Copyright (c) 2026 José María Micoli
Licensed under Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Remove copyright notices
"""

from __future__ import annotations

import argparse
import re
import sqlite3
from pathlib import Path
from typing import Iterable

import psycopg
from psycopg import sql as psql
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SQLITE = ROOT / "vectorvue.db"
DEFAULT_SCHEMA = ROOT / "sql" / "postgres_schema.sql"


def split_sql_statements(sql_blob: str) -> list[str]:
    statements: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(sql_blob)
    in_single = False
    in_double = False
    in_line_comment = False
    in_block_comment = False
    dollar_tag: str | None = None

    while i < n:
        ch = sql_blob[i]
        nxt = sql_blob[i + 1] if i + 1 < n else ""

        if in_line_comment:
            buf.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            buf.append(ch)
            if ch == "*" and nxt == "/":
                buf.append(nxt)
                i += 2
                in_block_comment = False
            else:
                i += 1
            continue

        if dollar_tag:
            if sql_blob.startswith(dollar_tag, i):
                buf.append(dollar_tag)
                i += len(dollar_tag)
                dollar_tag = None
            else:
                buf.append(ch)
                i += 1
            continue

        if not in_single and not in_double:
            if ch == "-" and nxt == "-":
                buf.append(ch)
                buf.append(nxt)
                i += 2
                in_line_comment = True
                continue
            if ch == "/" and nxt == "*":
                buf.append(ch)
                buf.append(nxt)
                i += 2
                in_block_comment = True
                continue
            if ch == "$":
                m = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", sql_blob[i:])
                if m:
                    tag = m.group(0)
                    buf.append(tag)
                    i += len(tag)
                    dollar_tag = tag
                    continue

        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue

        if ch == ";" and not in_single and not in_double and not dollar_tag:
            stmt = "".join(buf).strip()
            if stmt:
                statements.append(stmt)
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)
    return statements


def table_names(sqlite_conn: sqlite3.Connection) -> list[str]:
    cur = sqlite_conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    return [r[0] for r in cur.fetchall()]


def sqlite_rows(sqlite_conn: sqlite3.Connection, table: str, batch_size: int = 1000) -> Iterable[list[sqlite3.Row]]:
    cur = sqlite_conn.cursor()
    cur.execute(f'SELECT * FROM "{table}"')
    while True:
        rows = cur.fetchmany(batch_size)
        if not rows:
            break
        yield rows


def apply_schema(pg_conn: psycopg.Connection, schema_path: Path) -> None:
    sql_blob = schema_path.read_text(encoding="utf-8")
    statements = split_sql_statements(sql_blob)
    with pg_conn.cursor() as cur:
        for stmt in statements:
            cur.execute(stmt)
    pg_conn.commit()


def migrate(sqlite_db: Path, pg_url: str, schema_path: Path, truncate: bool = False) -> None:
    sconn = sqlite3.connect(sqlite_db)
    sconn.row_factory = sqlite3.Row
    pconn = psycopg.connect(pg_url, autocommit=False, row_factory=dict_row)

    try:
        apply_schema(pconn, schema_path)

        tables = table_names(sconn)
        with pconn.cursor() as pcur:
            if truncate:
                for t in reversed(tables):
                    pcur.execute(psql.SQL("TRUNCATE TABLE {} RESTART IDENTITY CASCADE").format(psql.Identifier(t)))
                pconn.commit()

        try:
            with pconn.cursor() as pcur:
                # Allow loading in any order, then enforce constraints after copy.
                pcur.execute("SET session_replication_role = replica")
            pconn.commit()

            for table in tables:
                scur = sconn.cursor()
                scur.execute(f'PRAGMA table_info("{table}")')
                cols = [r["name"] for r in scur.fetchall()]
                if not cols:
                    continue

                insert_stmt = psql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                    psql.Identifier(table),
                    psql.SQL(", ").join(psql.Identifier(c) for c in cols),
                    psql.SQL(", ").join(psql.Placeholder() for _ in cols),
                )

                with pconn.cursor() as pcur:
                    total = 0
                    for batch in sqlite_rows(sconn, table):
                        values = [tuple(row[c] for c in cols) for row in batch]
                        pcur.executemany(insert_stmt, values)
                        total += len(values)
                    pconn.commit()
                    print(f"migrated {table}: {total} rows")

            with pconn.cursor() as pcur:
                # Re-sync sequences after explicit id inserts.
                pcur.execute(
                    """
                    DO $$
                    DECLARE
                        rec record;
                    BEGIN
                        FOR rec IN
                            SELECT table_schema, table_name, column_name
                            FROM information_schema.columns
                            WHERE table_schema='public' AND column_default LIKE 'nextval(%'
                        LOOP
                            EXECUTE format(
                                'SELECT setval(pg_get_serial_sequence(''%I.%I'', ''%I''), COALESCE(MAX(%I), 1), MAX(%I) IS NOT NULL) FROM %I.%I',
                                rec.table_schema, rec.table_name, rec.column_name, rec.column_name, rec.column_name, rec.table_schema, rec.table_name
                            );
                        END LOOP;
                    END$$;
                    """
                )
            pconn.commit()
        finally:
            try:
                pconn.rollback()
            except Exception:
                pass
            with pconn.cursor() as pcur:
                pcur.execute("SET session_replication_role = origin")
            pconn.commit()

        print("SQLite -> PostgreSQL migration complete")
    finally:
        sconn.close()
        pconn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate VectorVue SQLite DB to PostgreSQL")
    parser.add_argument("--sqlite", default=str(DEFAULT_SQLITE), help="Path to source sqlite db")
    parser.add_argument("--pg-url", required=True, help="PostgreSQL connection URL")
    parser.add_argument("--schema", default=str(DEFAULT_SCHEMA), help="Path to postgres schema SQL")
    parser.add_argument("--truncate", action="store_true", help="Truncate destination tables first")
    args = parser.parse_args()

    migrate(Path(args.sqlite), args.pg_url, Path(args.schema), truncate=args.truncate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
