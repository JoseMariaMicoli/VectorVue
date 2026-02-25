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

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from analytics.db import session_scope


def log_analytics_event(
    tenant_id: str,
    event_type: str,
    entity_type: str,
    entity_id: str | int | None,
    payload: dict[str, Any] | None = None,
    timestamp: datetime | None = None,
) -> str:
    """Append analytics event row (insert-only)."""
    ts = timestamp or datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    event_id = str(uuid.uuid4())
    payload_json = json.dumps(payload or {}, default=str)
    with session_scope() as db:
        db.execute(
            text(
                """INSERT INTO analytics.events
                   (id, tenant_id, event_type, entity_type, entity_id, timestamp, payload)
                   VALUES (:id, :tenant_id, :event_type, :entity_type, :entity_id, :timestamp, CAST(:payload AS JSONB))"""
            ),
            {
                "id": event_id,
                "tenant_id": tenant_id,
                "event_type": (event_type or "").strip().upper(),
                "entity_type": (entity_type or "").strip().lower(),
                "entity_id": str(entity_id) if entity_id is not None else None,
                "timestamp": ts,
                "payload": payload_json,
            },
        )
    return event_id

