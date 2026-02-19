"""Apply a SQL file against PostgreSQL with basic statement splitting."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import psycopg


def _normalize_hash_comments(sql_blob: str) -> str:
    """Convert shell-style # comments to SQL -- comments for compatibility."""
    out_lines: list[str] = []
    for line in sql_blob.splitlines():
        if line.lstrip().startswith("#"):
            indent = line[: len(line) - len(line.lstrip())]
            out_lines.append(f"{indent}-- {line.lstrip()[1:].lstrip()}")
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


def _split_sql_statements(sql_blob: str) -> list[str]:
    """Split SQL script into statements while respecting quoted blocks."""
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Apply SQL migration file to PostgreSQL")
    parser.add_argument("--pg-url", required=True, help="PostgreSQL DSN")
    parser.add_argument("--sql", required=True, help="Path to SQL file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sql_path = Path(args.sql)
    if not sql_path.exists():
        raise FileNotFoundError(f"SQL file not found: {sql_path}")

    sql_blob = _normalize_hash_comments(sql_path.read_text(encoding="utf-8"))
    statements = _split_sql_statements(sql_blob)

    with psycopg.connect(args.pg_url, autocommit=False) as conn:
        with conn.cursor() as cur:
            for stmt in statements:
                cur.execute(stmt)
        conn.commit()

    print(f"Applied {len(statements)} statements from {sql_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
