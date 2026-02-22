from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.client_api.spectrastrike_schemas import SpectraStrikeBatchItemResult


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def deterministic_external_id(prefix: str, payload: dict[str, Any], keys: list[str]) -> str:
    """Generate deterministic upstream IDs when provider omits identifiers."""
    subset = {k: payload.get(k) for k in keys}
    canon = json.dumps(subset, sort_keys=True, default=str, separators=(",", ":"))
    digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}_{digest}"


class SpectraStrikeService:
    """Service layer for SpectraStrike persistence and idempotency."""

    def __init__(self, db: Session):
        self.db = db
        self._ensure_tables()

    def _ensure_tables(self) -> None:
        self.db.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS spectrastrike_ingest_requests (
                    request_id UUID PRIMARY KEY,
                    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    endpoint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    total_items INTEGER NOT NULL DEFAULT 0,
                    accepted_items INTEGER NOT NULL DEFAULT 0,
                    failed_items INTEGER NOT NULL DEFAULT 0,
                    failed_references JSONB NOT NULL DEFAULT '[]'::jsonb,
                    idempotency_key TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
        )
        self.db.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS spectrastrike_idempotency (
                    id BIGSERIAL PRIMARY KEY,
                    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    endpoint TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    response_json JSONB NOT NULL,
                    status_code INTEGER NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (tenant_id, endpoint, idempotency_key)
                )
                """
            )
        )
        self.db.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS spectrastrike_events (
                    id BIGSERIAL PRIMARY KEY,
                    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    request_id UUID NOT NULL,
                    event_uid TEXT NOT NULL,
                    source_system TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    occurred_at TIMESTAMPTZ NOT NULL,
                    severity TEXT NOT NULL,
                    asset_ref TEXT NOT NULL,
                    message TEXT NOT NULL,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    raw_payload JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (tenant_id, event_uid)
                )
                """
            )
        )
        self.db.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS spectrastrike_findings (
                    id BIGSERIAL PRIMARY KEY,
                    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
                    request_id UUID NOT NULL,
                    finding_uid TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    first_seen TIMESTAMPTZ NOT NULL,
                    last_seen TIMESTAMPTZ,
                    asset_ref TEXT,
                    recommendation TEXT,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    raw_payload JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (tenant_id, finding_uid)
                )
                """
            )
        )
        self.db.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS idx_spectrastrike_ingest_requests_tenant_created
                ON spectrastrike_ingest_requests (tenant_id, created_at DESC)
                """
            )
        )
        self.db.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS idx_spectrastrike_events_tenant_occurred
                ON spectrastrike_events (tenant_id, occurred_at DESC)
                """
            )
        )
        self.db.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS idx_spectrastrike_findings_tenant_seen
                ON spectrastrike_findings (tenant_id, first_seen DESC)
                """
            )
        )
        self.db.commit()

    def fetch_idempotent_response(
        self,
        *,
        tenant_id: str,
        endpoint: str,
        idempotency_key: str,
    ) -> dict[str, Any] | None:
        row = self.db.execute(
            text(
                """
                SELECT request_hash, response_json, status_code
                FROM spectrastrike_idempotency
                WHERE tenant_id=:tenant_id AND endpoint=:endpoint AND idempotency_key=:idempotency_key
                LIMIT 1
                """
            ),
            {
                "tenant_id": tenant_id,
                "endpoint": endpoint,
                "idempotency_key": idempotency_key,
            },
        ).mappings().first()
        if not row:
            return None
        return {
            "request_hash": str(row["request_hash"]),
            "response_json": row["response_json"],
            "status_code": int(row["status_code"]),
        }

    def store_idempotent_response(
        self,
        *,
        tenant_id: str,
        endpoint: str,
        idempotency_key: str,
        request_hash: str,
        response_json: dict[str, Any],
        status_code: int,
    ) -> None:
        self.db.execute(
            text(
                """
                INSERT INTO spectrastrike_idempotency
                (tenant_id, endpoint, idempotency_key, request_hash, response_json, status_code)
                VALUES (:tenant_id, :endpoint, :idempotency_key, :request_hash, CAST(:response_json AS JSONB), :status_code)
                ON CONFLICT (tenant_id, endpoint, idempotency_key)
                DO UPDATE SET
                    request_hash=EXCLUDED.request_hash,
                    response_json=EXCLUDED.response_json,
                    status_code=EXCLUDED.status_code
                """
            ),
            {
                "tenant_id": tenant_id,
                "endpoint": endpoint,
                "idempotency_key": idempotency_key,
                "request_hash": request_hash,
                "response_json": json.dumps(response_json, default=str),
                "status_code": status_code,
            },
        )
        self.db.commit()

    def record_event(self, *, tenant_id: str, request_id: str, event_uid: str, payload: dict[str, Any]) -> None:
        self.db.execute(
            text(
                """
                INSERT INTO spectrastrike_events
                (tenant_id, request_id, event_uid, source_system, event_type, occurred_at, severity, asset_ref, message, metadata_json, raw_payload)
                VALUES
                (:tenant_id, :request_id, :event_uid, :source_system, :event_type, :occurred_at, :severity, :asset_ref, :message, CAST(:metadata_json AS JSONB), CAST(:raw_payload AS JSONB))
                ON CONFLICT (tenant_id, event_uid) DO NOTHING
                """
            ),
            {
                "tenant_id": tenant_id,
                "request_id": request_id,
                "event_uid": event_uid,
                "source_system": payload["source_system"],
                "event_type": payload["event_type"],
                "occurred_at": payload["occurred_at"],
                "severity": payload["severity"],
                "asset_ref": payload["asset_ref"],
                "message": payload["message"],
                "metadata_json": json.dumps(payload.get("metadata") or {}, default=str),
                "raw_payload": json.dumps(payload, default=str),
            },
        )
        self.db.commit()

    def record_finding(self, *, tenant_id: str, request_id: str, finding_uid: str, payload: dict[str, Any]) -> None:
        self.db.execute(
            text(
                """
                INSERT INTO spectrastrike_findings
                (tenant_id, request_id, finding_uid, title, description, severity, status, first_seen, last_seen, asset_ref, recommendation, metadata_json, raw_payload)
                VALUES
                (:tenant_id, :request_id, :finding_uid, :title, :description, :severity, :status, :first_seen, :last_seen, :asset_ref, :recommendation, CAST(:metadata_json AS JSONB), CAST(:raw_payload AS JSONB))
                ON CONFLICT (tenant_id, finding_uid) DO NOTHING
                """
            ),
            {
                "tenant_id": tenant_id,
                "request_id": request_id,
                "finding_uid": finding_uid,
                "title": payload["title"],
                "description": payload["description"],
                "severity": payload["severity"],
                "status": payload["status"],
                "first_seen": payload["first_seen"],
                "last_seen": payload.get("last_seen"),
                "asset_ref": payload.get("asset_ref"),
                "recommendation": payload.get("recommendation"),
                "metadata_json": json.dumps(payload.get("metadata") or {}, default=str),
                "raw_payload": json.dumps(payload, default=str),
            },
        )
        self.db.commit()

    def record_ingest_status(
        self,
        *,
        request_id: str,
        tenant_id: str,
        endpoint: str,
        status: str,
        total_items: int,
        accepted_items: int,
        failed_items: int,
        failed_references: list[SpectraStrikeBatchItemResult],
        idempotency_key: str | None,
    ) -> None:
        now = _utcnow()
        failed_json = [item.model_dump() for item in failed_references]
        self.db.execute(
            text(
                """
                INSERT INTO spectrastrike_ingest_requests
                (request_id, tenant_id, endpoint, status, total_items, accepted_items, failed_items, failed_references, idempotency_key, created_at, updated_at)
                VALUES
                (:request_id, :tenant_id, :endpoint, :status, :total_items, :accepted_items, :failed_items, CAST(:failed_references AS JSONB), :idempotency_key, :created_at, :updated_at)
                ON CONFLICT (request_id)
                DO UPDATE SET
                    status=EXCLUDED.status,
                    total_items=EXCLUDED.total_items,
                    accepted_items=EXCLUDED.accepted_items,
                    failed_items=EXCLUDED.failed_items,
                    failed_references=EXCLUDED.failed_references,
                    idempotency_key=EXCLUDED.idempotency_key,
                    updated_at=EXCLUDED.updated_at
                """
            ),
            {
                "request_id": request_id,
                "tenant_id": tenant_id,
                "endpoint": endpoint,
                "status": status,
                "total_items": total_items,
                "accepted_items": accepted_items,
                "failed_items": failed_items,
                "failed_references": json.dumps(failed_json, default=str),
                "idempotency_key": idempotency_key,
                "created_at": now,
                "updated_at": now,
            },
        )
        self.db.commit()

    def get_ingest_status(self, *, request_id: str, tenant_id: str) -> dict[str, Any] | None:
        row = self.db.execute(
            text(
                """
                SELECT request_id, endpoint, status, total_items, accepted_items, failed_items, failed_references, created_at, updated_at
                FROM spectrastrike_ingest_requests
                WHERE request_id=:request_id AND tenant_id=:tenant_id
                LIMIT 1
                """
            ),
            {"request_id": request_id, "tenant_id": tenant_id},
        ).mappings().first()
        if not row:
            return None
        failed_raw = row["failed_references"]
        if isinstance(failed_raw, str):
            failed_items = json.loads(failed_raw)
        elif failed_raw is None:
            failed_items = []
        else:
            failed_items = failed_raw
        return {
            "request_id": str(row["request_id"]),
            "endpoint": str(row["endpoint"]),
            "status": str(row["status"]),
            "total_items": int(row["total_items"]),
            "accepted_items": int(row["accepted_items"]),
            "failed_items": int(row["failed_items"]),
            "failed_references": failed_items,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def write_audit_event(
        self,
        *,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        old_value_hash: str = "",
        new_value_hash: str = "",
    ) -> None:
        self.db.execute(
            text(
                """
                INSERT INTO audit_log (id, timestamp, username, action, target_type, target_id, old_value_hash, new_value_hash)
                VALUES (:id, :timestamp, :username, :action, :target_type, :target_id, :old_value_hash, :new_value_hash)
                """
            ),
            {
                "id": str(uuid4()),
                "timestamp": _utcnow().isoformat(),
                "username": actor,
                "action": action,
                "target_type": target_type,
                "target_id": target_id,
                "old_value_hash": old_value_hash,
                "new_value_hash": new_value_hash,
            },
        )
        self.db.commit()
