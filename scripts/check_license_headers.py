# Copyright (c) 2026 NyxeraLabs
# Author: Jose Maria Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-22 -> Apache-2.0

"""Fail when tracked source/config files miss required license markers."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REQUIRED_PATTERNS = (
    re.compile(r"Copyright \(c\) 2026 NyxeraLabs"),
    re.compile(r"Licensed under BSL 1\.1"),
    re.compile(r"Change Date:"),
)

TARGET_EXTENSIONS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".mjs",
    ".sh",
    ".yml",
    ".yaml",
    ".toml",
    ".conf",
}

TARGET_ROOTS = {
    ".github",
    "api",
    "app",
    "cli",
    "models",
    "portal",
    "scripts",
    "security",
    "services",
    "tests",
    "utils",
    "workers",
}

HEADER_SCAN_LINES = 40


def is_target(path: Path) -> bool:
    if not path.parts:
        return False
    if path.parts[0] not in TARGET_ROOTS and path.name not in {"Makefile", "Dockerfile"}:
        return False
    if path.name in {"Makefile", "Dockerfile"}:
        return True
    return path.suffix in TARGET_EXTENSIONS


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [Path(line) for line in result.stdout.splitlines() if line.strip()]


def has_license_header(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            first_lines = "".join(handle.readline() for _ in range(HEADER_SCAN_LINES))
    except OSError:
        return False
    return all(pattern.search(first_lines) for pattern in REQUIRED_PATTERNS)


def main(argv: list[str]) -> int:
    files = [Path(arg) for arg in argv] if argv else tracked_files()
    missing: list[Path] = []

    for file_path in files:
        if not file_path.exists() or file_path.is_dir() or not is_target(file_path):
            continue
        if not has_license_header(file_path):
            missing.append(file_path)

    if not missing:
        return 0

    print("Missing or incomplete license header in:")
    for file_path in missing:
        print(f"- {file_path}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
