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

"""Append-only tamper-evident audit log with hash chain and periodic sealing."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any


@dataclass(frozen=True)
class TamperLogSettings:
    log_path: Path
    seal_every: int


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_tamper_log_settings() -> TamperLogSettings:
    path = Path(os.environ.get("VV_TAMPER_LOG_PATH", "/tmp/vectorvue_tamper_audit.jsonl")).resolve()
    seal_every = int(os.environ.get("VV_TAMPER_LOG_SEAL_EVERY", "50"))
    if seal_every < 1:
        raise RuntimeError("VV_TAMPER_LOG_SEAL_EVERY must be >= 1")
    path.parent.mkdir(parents=True, exist_ok=True)
    return TamperLogSettings(log_path=path, seal_every=seal_every)


class TamperEvidentAuditLog:
    def __init__(self, settings: TamperLogSettings):
        self.settings = settings
        self._lock = Lock()

    def append_event(self, *, event_type: str, actor: str, details: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entries = self._read_entries()
            prev_hash = str(entries[-1]["entry_hash"]) if entries else ""
            idx = len(entries) + 1
            entry = {
                "index": idx,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "actor": actor,
                "details": details,
                "previous_hash": prev_hash,
            }
            entry_hash = _sha256(_canonical(entry))
            record = {**entry, "entry_hash": entry_hash}
            self._append_raw(record)

            if idx % self.settings.seal_every == 0:
                self._append_seal(last_entry_hash=entry_hash, index=idx)
            return record

    def verify_integrity(self) -> dict[str, Any]:
        with self._lock:
            entries = self._read_entries()
        previous = ""
        for row in entries:
            base = {
                "index": row["index"],
                "timestamp": row["timestamp"],
                "event_type": row["event_type"],
                "actor": row["actor"],
                "details": row["details"],
                "previous_hash": row["previous_hash"],
            }
            expected = _sha256(_canonical(base))
            if row["entry_hash"] != expected:
                return {"ok": False, "broken_at": row["index"], "reason": "entry_hash_mismatch"}
            if row["previous_hash"] != previous:
                return {"ok": False, "broken_at": row["index"], "reason": "previous_hash_mismatch"}
            previous = str(row["entry_hash"])

        return {"ok": True, "entries": len(entries), "latest_hash": previous}

    def _append_seal(self, *, last_entry_hash: str, index: int) -> None:
        seal_payload = {
            "sealed_index": index,
            "last_entry_hash": last_entry_hash,
            "sealed_at": datetime.now(timezone.utc).isoformat(),
        }
        self._append_raw(
            {
                "index": index,
                "timestamp": seal_payload["sealed_at"],
                "event_type": "log.sealed",
                "actor": "SYSTEM",
                "details": seal_payload,
                "previous_hash": last_entry_hash,
                "entry_hash": _sha256(_canonical({
                    "index": index,
                    "timestamp": seal_payload["sealed_at"],
                    "event_type": "log.sealed",
                    "actor": "SYSTEM",
                    "details": seal_payload,
                    "previous_hash": last_entry_hash,
                })),
            }
        )

    def _append_raw(self, record: dict[str, Any]) -> None:
        with self.settings.log_path.open("a", encoding="utf-8") as f:
            f.write(_canonical(record) + "\n")

    def _read_entries(self) -> list[dict[str, Any]]:
        if not self.settings.log_path.exists():
            return []
        rows: list[dict[str, Any]] = []
        for line in self.settings.log_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
        return rows


def get_tamper_audit_log() -> TamperEvidentAuditLog:
    return TamperEvidentAuditLog(load_tamper_log_settings())
