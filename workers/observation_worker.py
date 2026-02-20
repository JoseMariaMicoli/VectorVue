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
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from redis import Redis
from rq import Queue, Worker
from sqlalchemy import text

from analytics.config import redis_url
from analytics.db import session_scope
from services.framework_mapper import ensure_framework_catalog


LOGGER = logging.getLogger("vectorvue.compliance_observation_worker")


def _map_confidence(event_type: str) -> float:
    event_type = event_type.strip().upper()
    if event_type in {"DETECTION_LOGGED", "FINDING_ACKNOWLEDGED", "REMEDIATION_COMPLETED"}:
        return 0.9
    if event_type in {"FINDING_VIEWED", "DASHBOARD_VIEWED", "REMEDIATION_OPENED"}:
        return 0.75
    return 0.65


def derive_observations_for_tenant(tenant_id: str, lookback_hours: int = 24) -> dict[str, Any]:
    ensure_framework_catalog()
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=max(1, int(lookback_hours)))
    inserted = 0

    with session_scope() as db:
        mappings = db.execute(
            text(
                """SELECT cm.control_id, cm.source_event_type
                   FROM control_mappings cm
                   WHERE cm.source_event_type <> ''"""
            )
        ).mappings().all()
        control_by_event: dict[str, set[int]] = {}
        for m in mappings:
            event = str(m["source_event_type"]).upper()
            control_by_event.setdefault(event, set()).add(int(m["control_id"]))

        if not control_by_event:
            return {"tenant_id": tenant_id, "inserted": 0, "since": since.isoformat() + "Z"}

        analytics_rows = db.execute(
            text(
                """SELECT id, event_type, timestamp, payload
                   FROM analytics.events
                   WHERE tenant_id=:tenant_id
                     AND timestamp >= :since
                   ORDER BY timestamp ASC"""
            ),
            {"tenant_id": tenant_id, "since": since},
        ).mappings().all()
        client_rows = db.execute(
            text(
                """SELECT id, event_type, timestamp, metadata_json
                   FROM client_activity_events
                   WHERE tenant_id=:tenant_id
                     AND timestamp >= :since
                   ORDER BY timestamp ASC"""
            ),
            {"tenant_id": tenant_id, "since": since},
        ).mappings().all()

        def insert_for_event(source: str, event_id: str, event_type: str, observed_at: datetime, metadata: Any) -> int:
            count = 0
            controls = control_by_event.get(event_type.upper(), set())
            for control_id in controls:
                db.execute(
                    text(
                        """INSERT INTO control_observations
                           (tenant_id, control_id, derived_from_event, result, confidence, observed_at, metadata_json)
                           VALUES (:tenant_id, :control_id, :derived_from_event, :result, :confidence, :observed_at, CAST(:metadata_json AS JSONB))
                           ON CONFLICT (tenant_id, control_id, derived_from_event) DO NOTHING"""
                    ),
                    {
                        "tenant_id": tenant_id,
                        "control_id": control_id,
                        "derived_from_event": f"{source}:{event_id}",
                        "result": "failure" if event_type.upper() in {"REMEDIATION_OPENED"} else "success",
                        "confidence": _map_confidence(event_type),
                        "observed_at": observed_at,
                        "metadata_json": json.dumps({"event_type": event_type, "source": source, "metadata": metadata}, sort_keys=True, default=str),
                    },
                )
                count += 1
            return count

        for row in analytics_rows:
            inserted += insert_for_event(
                source="analytics.events",
                event_id=str(row["id"]),
                event_type=str(row["event_type"]),
                observed_at=row["timestamp"],
                metadata=row.get("payload"),
            )

        for row in client_rows:
            inserted += insert_for_event(
                source="client_activity_events",
                event_id=str(row["id"]),
                event_type=str(row["event_type"]),
                observed_at=row["timestamp"],
                metadata=row.get("metadata_json"),
            )

    return {"tenant_id": tenant_id, "inserted": inserted, "since": since.isoformat() + "Z"}


def derive_observations_job(tenant_id: str, lookback_hours: int = 24) -> dict[str, Any]:
    return derive_observations_for_tenant(tenant_id=tenant_id, lookback_hours=lookback_hours)


def run_worker() -> None:
    logging.basicConfig(
        level=os.environ.get("VV_COMPLIANCE_WORKER_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    conn = Redis.from_url(redis_url())
    queue = Queue("compliance_observation", connection=conn)
    worker = Worker([queue], connection=conn)
    LOGGER.info("compliance observation worker started; queue=compliance_observation")
    worker.work(with_scheduler=False)


if __name__ == "__main__":
    run_worker()
