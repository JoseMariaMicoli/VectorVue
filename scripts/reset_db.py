#!/usr/bin/env python3
"""
Reset VectorVue local database state for clean testing.
"""

from pathlib import Path
import argparse


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset VectorVue database and local session.")
    parser.add_argument("--yes", action="store_true", help="Execute reset without prompt.")
    args = parser.parse_args()

    targets = [
        ROOT / "vectorvue.db",
        ROOT / ".vectorvue_session",
    ]

    if not args.yes:
        print("This will delete:")
        for path in targets:
            print(f"  - {path}")
        confirm = input("Proceed? [y/N] ").strip().lower()
        if confirm not in {"y", "yes"}:
            print("Aborted.")
            return 1

    for path in targets:
        if path.exists():
            path.unlink()
            print(f"Deleted {path}")
        else:
            print(f"Not found {path}")

    print("Reset complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
