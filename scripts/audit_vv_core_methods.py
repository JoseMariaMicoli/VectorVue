"""
Copyright (c) 2026 José María Micoli
Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "vv_core.py"
OUT = ROOT / "docs" / "manuals" / "POSTGRES_AUDIT_REPORT.md"


CRUD_HINTS = {
    "create": ("INSERT",),
    "read": ("SELECT",),
    "update": ("UPDATE",),
    "delete": ("DELETE",),
}


def classify_sql(sql: str) -> set[str]:
    up = sql.upper()
    kinds = set()
    for k, hints in CRUD_HINTS.items():
        if any(h in up for h in hints):
            kinds.add(k)
    if "JOIN" in up:
        kinds.add("join")
    if "BEGIN" in up or "COMMIT" in up or "ROLLBACK" in up:
        kinds.add("txn")
    if "ON CONFLICT" in up or "INSERT OR IGNORE" in up:
        kinds.add("upsert")
    return kinds


def extract_methods(tree: ast.AST):
    methods = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "Database":
            for n in node.body:
                if isinstance(n, ast.FunctionDef):
                    sql_fragments = []
                    for sub in ast.walk(n):
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            val = sub.value.strip()
                            if any(x in val.upper() for x in ("SELECT", "INSERT", "UPDATE", "DELETE", "CREATE TABLE", "ALTER TABLE")):
                                sql_fragments.append(val)
                    kinds = set()
                    for frag in sql_fragments:
                        kinds |= classify_sql(frag)
                    multi_mutation = sum(1 for frag in sql_fragments if any(x in frag.upper() for x in ("INSERT", "UPDATE", "DELETE"))) > 1
                    methods.append((n.name, kinds, multi_mutation, len(sql_fragments)))
    return methods


def main() -> int:
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    methods = extract_methods(tree)

    lines = []
    lines.append("/*")
    lines.append("Copyright (c) 2026 José María Micoli")
    lines.append("Licensed under Apache-2.0")
    lines.append("")
    lines.append("You may:")
    lines.append("✔ Study")
    lines.append("✔ Modify")
    lines.append("✔ Use for internal security testing")
    lines.append("")
    lines.append("You may NOT:")
    lines.append("✘ Remove copyright notices")
    lines.append("*/")
    lines.append("")
    lines.append("# PostgreSQL Migration Audit Report")
    lines.append("")
    lines.append("Generated from static analysis of `vv_core.py` database methods.")
    lines.append("")
    lines.append("## Method Classification")
    lines.append("")
    lines.append("| Method | Categories | Multi-table Mutation Candidate | SQL Fragments |")
    lines.append("|---|---|---|---|")
    for name, kinds, multi_mutation, frag_count in methods:
        cats = ", ".join(sorted(kinds)) if kinds else "none"
        lines.append(f"| `{name}` | {cats} | {'Yes' if multi_mutation else 'No'} | {frag_count} |")

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- Methods marked `Multi-table Mutation Candidate = Yes` should be validated with explicit transaction tests.")
    lines.append("- Upsert and conflict-handling SQL was normalized for PostgreSQL in compatibility wrappers.")
    lines.append("- Immutable and audit-sensitive tables require trigger-based protections in PostgreSQL schema.")

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
