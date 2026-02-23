#!/usr/bin/env python3
"""Mandatory legal acceptance gate for production-grade make install."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from shutil import get_terminal_size

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.legal_acceptance import (
    DEFAULT_ACCEPTANCE_PATH,
    current_legal_bundle,
    validate_local_acceptance_manifest,
    write_local_acceptance_manifest,
)


EXPECTED_PHRASE = "I ACCEPT VECTORVUE LEGAL TERMS"


def _is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _paginate_document(title: str, content: str) -> bool:
    width = max(80, get_terminal_size(fallback=(120, 30)).columns)
    height = max(10, get_terminal_size(fallback=(120, 30)).lines - 3)
    lines = [f"===== {title} =====", ""] + content.splitlines()
    cursor = 0
    while cursor < len(lines):
        end = min(cursor + height, len(lines))
        for line in lines[cursor:end]:
            print(line[:width])
        cursor = end
        if cursor >= len(lines):
            break
        answer = input("[Enter] next page | q abort: ")
        if answer.strip() == "q":
            return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="VectorVue legal acceptance installer guard")
    parser.add_argument("--mode", default="self-hosted", choices=["self-hosted", "saas"])
    parser.add_argument("--acceptance-file", default=str(DEFAULT_ACCEPTANCE_PATH))
    args = parser.parse_args()

    acceptance_path = Path(args.acceptance_file)
    ok, reason, _ = validate_local_acceptance_manifest(mode=args.mode, acceptance_path=acceptance_path)
    if ok:
        print(f"Legal acceptance already valid: {acceptance_path}")
        return 0

    if not _is_interactive():
        print(f"Legal acceptance required but terminal is non-interactive: {reason}", file=sys.stderr)
        return 1

    print("Legal acceptance required for make install.")
    print(f"Reason: {reason}")
    bundle = current_legal_bundle(mode=args.mode)
    for doc in bundle["documents"]:
        if not _paginate_document(doc["name"], doc["content"]):
            print("Installation aborted: legal review cancelled.")
            return 1

    typed = input("Type EXACTLY to continue: I ACCEPT VECTORVUE LEGAL TERMS\n> ")
    if typed != EXPECTED_PHRASE:
        print("Installation aborted: acceptance phrase mismatch.")
        return 1

    payload = write_local_acceptance_manifest(mode=args.mode, output_path=acceptance_path)
    ok, reason, _ = validate_local_acceptance_manifest(mode=args.mode, acceptance_path=acceptance_path)
    if not ok:
        print(f"Installation aborted: acceptance manifest invalid after write: {reason}", file=sys.stderr)
        return 1

    print(f"Legal acceptance recorded at {acceptance_path}")
    print(f"document_hash={payload['document_hash']}")
    print(f"version={payload['version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
