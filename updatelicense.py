#!/usr/bin/env python3
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

"""
Bulk license header updater for a project tree.

- Traverses from project root (default: current directory)
- Excludes: venv/, .git/, __pycache__/, .github/
- Adds/replaces headers:
  - .py files -> triple-quoted Python header
  - non-.py files -> # comment header
- Preserves shebang lines
- Preserves encoding as best effort
- Prints:
  - [UPDATED] <filepath>
  - [SKIPPED] <filepath>
"""

from __future__ import annotations

import argparse
import os
import re
import tokenize
from pathlib import Path
from typing import Tuple

EXCLUDED_DIRS = {"venv", ".git", "__pycache__", ".github"}
KEYWORDS = ("Copyright", "Licensed")

PY_HEADER = '''"""
Copyright (c) 2026 José María Micoli
Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
"""'''

TEXT_HEADER = """# Copyright (c) 2026 José María Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}
#
# You may:
# ✔ Study
# ✔ Modify
# ✔ Use for internal security testing
#
# You may NOT:
# ✘ Offer as a commercial service
# ✘ Sell derived competing products"""


def detect_newline(text: str) -> str:
    if "\r\n" in text:
        return "\r\n"
    if "\r" in text:
        return "\r"
    return "\n"


def detect_encoding(raw: bytes, path: Path) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    try:
        # Honors PEP263 coding cookies for python-like files.
        return tokenize.detect_encoding(iter(raw.splitlines(keepends=True)).__next__)[0]
    except Exception:
        pass
    try:
        raw.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        return "latin-1"


def is_binary(raw: bytes) -> bool:
    return b"\x00" in raw


def split_preserved_prefix(text: str, is_python: bool) -> Tuple[str, str]:
    """
    Preserve shebang (all files) and python coding line (for .py).
    Return (prefix, remaining_text).
    """
    prefix = []
    rest = text

    lines = rest.splitlines(keepends=True)
    idx = 0

    if lines and lines[0].startswith("#!"):
        prefix.append(lines[0])
        idx = 1

    if is_python and idx < len(lines):
        # Preserve coding cookie if present in first two physical lines.
        coding_re = re.compile(r"^[ \t]*#.*coding[:=][ \t]*[-\w.]+")
        if coding_re.match(lines[idx]):
            prefix.append(lines[idx])
            idx += 1

    return "".join(prefix), "".join(lines[idx:])


def remove_existing_header(body: str) -> Tuple[str, bool]:
    """
    Remove top header block if it contains Copyright or Licensed.
    Supports:
    - triple-quoted block
    - consecutive # comment block
    - C-style /* ... */ block
    """
    original = body
    i = 0
    n = len(body)

    # Skip leading blank lines (so headers after a blank line are still detected).
    while i < n and body[i] in " \t\r\n":
        i += 1

    candidate_start = i
    removed = False

    # Triple-quoted block
    if body.startswith('"""', candidate_start) or body.startswith("'''", candidate_start):
        q = body[candidate_start:candidate_start + 3]
        end = body.find(q, candidate_start + 3)
        if end != -1:
            block_end = end + 3
            block = body[candidate_start:block_end]
            if any(k in block for k in KEYWORDS):
                body = body[:candidate_start] + body[block_end:]
                removed = True

    # Hash-comment block
    elif body.startswith("#", candidate_start):
        lines = body[candidate_start:].splitlines(keepends=True)
        j = 0
        while j < len(lines):
            s = lines[j].strip()
            if s == "" or s.startswith("#"):
                j += 1
            else:
                break
        block = "".join(lines[:j])
        if any(k in block for k in KEYWORDS):
            body = body[:candidate_start] + "".join(lines[j:])
            removed = True

    # C-style block
    elif body.startswith("/*", candidate_start):
        end = body.find("*/", candidate_start + 2)
        if end != -1:
            block_end = end + 2
            block = body[candidate_start:block_end]
            if any(k in block for k in KEYWORDS):
                body = body[:candidate_start] + body[block_end:]
                removed = True

    return (body, removed) if removed else (original, False)


def normalize_leading_blank_lines(text: str) -> str:
    return text.lstrip("\r\n")


def build_header(is_python: bool, nl: str) -> str:
    base = PY_HEADER if is_python else TEXT_HEADER
    return base.replace("\n", nl)


def process_file(path: Path) -> bool:
    raw = path.read_bytes()
    if is_binary(raw):
        print(f"[SKIPPED] {path}")
        return False

    encoding = detect_encoding(raw, path)
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError:
        # Last fallback; keep file untouched if still not decodable.
        print(f"[SKIPPED] {path}")
        return False

    is_python = path.suffix.lower() == ".py"
    nl = detect_newline(text)

    prefix, body = split_preserved_prefix(text, is_python)
    body, _ = remove_existing_header(body)
    body = normalize_leading_blank_lines(body)

    header = build_header(is_python, nl)
    new_text = f"{prefix}{header}{nl}{nl}{body}"

    if new_text != text:
        path.write_text(new_text, encoding=encoding, newline="")
        print(f"[UPDATED] {path}")
        return True

    print(f"[SKIPPED] {path}")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply new license headers across project files.")
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Project root directory (default: current directory).",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not root.exists() or not root.is_dir():
        print(f"[SKIPPED] {root}")
        return 1

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune excluded dirs and print them as skipped.
        kept = []
        for d in dirnames:
            full = Path(dirpath) / d
            if d in EXCLUDED_DIRS:
                print(f"[SKIPPED] {full}")
            else:
                kept.append(d)
        dirnames[:] = kept

        for name in filenames:
            path = Path(dirpath) / name
            try:
                process_file(path)
            except Exception:
                print(f"[SKIPPED] {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
