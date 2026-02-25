"""Shared legal acceptance utilities for install, TUI, and web flows."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LEGAL_DOCUMENTS: tuple[tuple[str, Path], ...] = (
    ("LICENSE", Path("LICENSE")),
    ("EULA.md", Path("docs/EULA.md")),
    ("ACCEPTABLE_USE_POLICY.md", Path("docs/ACCEPTABLE_USE_POLICY.md")),
    ("USER_POLICY.md", Path("docs/USER_POLICY.md")),
    ("SECURITY_POLICY.md", Path("docs/SECURITY_POLICY.md")),
    ("PRIVACY_POLICY.md", Path("docs/PRIVACY_POLICY.md")),
    ("DISCLAIMER.md", Path("docs/DISCLAIMER.md")),
)

DEFAULT_ACCEPTANCE_PATH = Path(".vectorvue/legal_acceptance.json")
DEFAULT_LEGAL_VERSION = "2026.02"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _project_root(project_root: Path | None = None) -> Path:
    if project_root is not None:
        return Path(project_root).resolve()
    return Path(__file__).resolve().parent.parent


def legal_version(default_version: str = DEFAULT_LEGAL_VERSION) -> str:
    return (os.environ.get("VECTORVUE_LEGAL_VERSION", "").strip() or default_version).strip()


def load_legal_documents(project_root: Path | None = None) -> list[dict[str, str]]:
    root = _project_root(project_root)
    docs: list[dict[str, str]] = []
    for name, rel_path in LEGAL_DOCUMENTS:
        abs_path = root / rel_path
        if not abs_path.exists():
            raise FileNotFoundError(f"Legal document missing: {abs_path}")
        docs.append(
            {
                "name": name,
                "path": str(rel_path),
                "content": abs_path.read_text(encoding="utf-8"),
            }
        )
    return docs


def compute_legal_document_hash(documents: list[dict[str, str]]) -> str:
    hasher = hashlib.sha256()
    for doc in documents:
        hasher.update(doc["name"].encode("utf-8"))
        hasher.update(b"\n")
        hasher.update(doc["content"].encode("utf-8"))
        hasher.update(b"\n---\n")
    return hasher.hexdigest()


def current_legal_bundle(
    mode: str,
    version: str | None = None,
    project_root: Path | None = None,
) -> dict[str, Any]:
    docs = load_legal_documents(project_root=project_root)
    return {
        "documents": docs,
        "document_hash": compute_legal_document_hash(docs),
        "version": version or legal_version(),
        "mode": mode,
    }


def build_local_acceptance_manifest(
    mode: str = "self-hosted",
    version: str | None = None,
    project_root: Path | None = None,
) -> dict[str, Any]:
    bundle = current_legal_bundle(mode=mode, version=version, project_root=project_root)
    return {
        "accepted": True,
        "timestamp": utc_now_iso(),
        "document_hash": bundle["document_hash"],
        "version": bundle["version"],
        "mode": mode,
    }


def write_local_acceptance_manifest(
    mode: str = "self-hosted",
    output_path: Path | None = None,
    version: str | None = None,
    project_root: Path | None = None,
) -> dict[str, Any]:
    root = _project_root(project_root)
    path = root / (output_path or DEFAULT_ACCEPTANCE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_local_acceptance_manifest(mode=mode, version=version, project_root=root)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def _manifest_has_required_shape(payload: dict[str, Any]) -> bool:
    required_keys = {"accepted", "timestamp", "document_hash", "version", "mode"}
    if set(payload.keys()) != required_keys:
        return False
    if payload.get("accepted") is not True:
        return False
    for key in ("timestamp", "document_hash", "version", "mode"):
        if not isinstance(payload.get(key), str) or not payload.get(key, "").strip():
            return False
    return True


def validate_local_acceptance_manifest(
    mode: str = "self-hosted",
    acceptance_path: Path | None = None,
    version: str | None = None,
    project_root: Path | None = None,
) -> tuple[bool, str, dict[str, Any] | None]:
    root = _project_root(project_root)
    path = root / (acceptance_path or DEFAULT_ACCEPTANCE_PATH)
    if not path.exists():
        return False, f"Acceptance file missing: {path}", None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Acceptance file unreadable/corrupt: {exc}", None
    if not isinstance(payload, dict) or not _manifest_has_required_shape(payload):
        return False, "Acceptance file has invalid structure", None

    expected = build_local_acceptance_manifest(mode=mode, version=version, project_root=root)
    if payload.get("mode") != expected["mode"]:
        return False, "Acceptance mode mismatch", payload
    if payload.get("document_hash") != expected["document_hash"]:
        return False, "Acceptance document hash mismatch", payload
    if payload.get("version") != expected["version"]:
        return False, "Acceptance version mismatch", payload
    return True, "ok", payload
