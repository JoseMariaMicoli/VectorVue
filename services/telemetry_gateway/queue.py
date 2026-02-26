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

"""Secure telemetry queue publisher with integrity hashing and DLQ support."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from threading import Lock
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class QueueSettings:
    backend: str
    nats_url: str
    subject_ingest: str
    subject_dlq: str


class MemoryQueueStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._messages: dict[str, list[dict[str, Any]]] = {}

    def publish(self, subject: str, message: dict[str, Any]) -> None:
        with self._lock:
            self._messages.setdefault(subject, []).append(message)

    def read(self, subject: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._messages.get(subject, []))

    def clear(self) -> None:
        with self._lock:
            self._messages.clear()


_memory_store = MemoryQueueStore()


class SecureQueuePublisher:
    def __init__(self, settings: QueueSettings):
        self.settings = settings
        self._nc = None

    async def publish_ingest(self, payload: dict[str, Any], trace: dict[str, Any]) -> str:
        envelope = self._build_envelope(kind="ingest", payload=payload, trace=trace)
        await self._publish(self.settings.subject_ingest, envelope)
        return str(envelope["integrity_hash"])

    async def publish_dlq(self, raw_body: bytes, error_code: str, error_message: str, trace: dict[str, Any]) -> str:
        try:
            raw_text = raw_body.decode("utf-8")
        except UnicodeDecodeError:
            raw_text = base64.b64encode(raw_body).decode("utf-8")

        payload = {
            "error_code": error_code,
            "error_message": error_message,
            "raw_body": raw_text,
        }
        envelope = self._build_envelope(kind="dead_letter", payload=payload, trace=trace)
        await self._publish(self.settings.subject_dlq, envelope)
        return str(envelope["integrity_hash"])

    async def _publish(self, subject: str, envelope: dict[str, Any]) -> None:
        if self.settings.backend == "memory":
            _memory_store.publish(subject, envelope)
            return

        if self.settings.backend == "nats":
            nc = await self._get_nats_connection()
            raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
            await nc.publish(subject, raw)
            await nc.flush(timeout=1)
            return

        raise RuntimeError(f"Unsupported queue backend: {self.settings.backend}")

    async def _get_nats_connection(self):
        if self._nc is not None and getattr(self._nc, "is_connected", False):
            return self._nc

        import nats

        self._nc = await nats.connect(
            servers=[self.settings.nats_url],
            reconnect_time_wait=1,
            max_reconnect_attempts=2,
            connect_timeout=2,
            name="vectorvue-telemetry-gateway",
        )
        return self._nc

    @staticmethod
    def _build_envelope(kind: str, payload: dict[str, Any], trace: dict[str, Any]) -> dict[str, Any]:
        canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        integrity_hash = sha256(canonical_payload.encode("utf-8")).hexdigest()
        return {
            "message_id": str(uuid4()),
            "kind": kind,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "integrity_hash": integrity_hash,
            "trace": trace,
            "payload": payload,
        }


def load_queue_settings() -> QueueSettings:
    return QueueSettings(
        backend=os.environ.get("VV_TG_QUEUE_BACKEND", "nats").strip().lower(),
        nats_url=os.environ.get("VV_TG_NATS_URL", "nats://nats:4222").strip(),
        subject_ingest=os.environ.get("VV_TG_QUEUE_SUBJECT", "vectorvue.telemetry.ingest").strip(),
        subject_dlq=os.environ.get("VV_TG_DLQ_SUBJECT", "vectorvue.telemetry.dlq").strip(),
    )


def get_memory_messages(subject: str) -> list[dict[str, Any]]:
    return _memory_store.read(subject)


def clear_memory_messages() -> None:
    _memory_store.clear()
