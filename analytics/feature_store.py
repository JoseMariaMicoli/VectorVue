# Copyright (c) 2026 Jose Maria Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from sqlalchemy import text

from analytics.config import features_storage_dir
from analytics.db import session_scope


def _window_delta(window: str) -> timedelta:
    mapping = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    if window not in mapping:
        raise ValueError("window must be one of 1h|24h|7d|30d")
    return mapping[window]


def _dataset_hash(rows: list[dict[str, Any]]) -> str:
    normalized = json.dumps(sorted(rows, key=lambda x: (x["entity_id"], x["feature_name"])), sort_keys=True, default=str)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def materialize_features(tenant_id: str, window: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    since = now - _window_delta(window)
    version = now.strftime("%Y%m%d%H%M%S")
    rows: list[dict[str, Any]] = []

    with session_scope() as db:
        campaign_ids = [
            str(r[0])
            for r in db.execute(
                text(
                    """SELECT DISTINCT entity_id
                       FROM analytics.events
                       WHERE tenant_id=:tenant_id
                         AND entity_type='campaign'
                         AND timestamp >= :since"""
                ),
                {"tenant_id": tenant_id, "since": since},
            ).all()
            if r[0] is not None
        ]

        for campaign_id in campaign_ids:
            counts = {
                "commands": 0.0,
                "detections": 0.0,
                "successes": 0.0,
                "priv_esc": 0.0,
                "lateral": 0.0,
                "first_ts": None,
                "last_ts": None,
                "mttd_seconds": 0.0,
                "mttd_n": 0.0,
                "techniques": {},
            }

            events = db.execute(
                text(
                    """SELECT event_type, timestamp, payload
                       FROM analytics.events
                       WHERE tenant_id=:tenant_id
                         AND timestamp >= :since
                         AND (
                           (entity_type='campaign' AND entity_id=:campaign_id)
                           OR (payload->>'campaign_id' = :campaign_id)
                         )
                       ORDER BY timestamp ASC"""
                ),
                {"tenant_id": tenant_id, "since": since, "campaign_id": campaign_id},
            ).all()

            last_command_ts = None
            for event_type, ts, payload in events:
                payload = payload or {}
                counts["first_ts"] = ts if counts["first_ts"] is None else min(counts["first_ts"], ts)
                counts["last_ts"] = ts if counts["last_ts"] is None else max(counts["last_ts"], ts)
                et = str(event_type or "").upper()
                if et == "COMMAND_EXECUTED":
                    counts["commands"] += 1
                    if bool(payload.get("success", True)):
                        counts["successes"] += 1
                    technique = str(payload.get("technique", "")).strip()
                    if technique:
                        counts["techniques"][technique] = counts["techniques"].get(technique, 0.0) + 1.0
                    if "T1068" in technique or "T1134" in technique:
                        counts["priv_esc"] += 1
                    if "T1021" in technique or "T1078" in technique:
                        counts["lateral"] += 1
                    last_command_ts = ts
                elif et == "DETECTION_LOGGED":
                    counts["detections"] += 1
                    if last_command_ts is not None:
                        counts["mttd_seconds"] += max(0.0, (ts - last_command_ts).total_seconds())
                        counts["mttd_n"] += 1.0

            duration = 0.0
            if counts["first_ts"] is not None and counts["last_ts"] is not None:
                duration = max(0.0, (counts["last_ts"] - counts["first_ts"]).total_seconds())

            detection_rate = counts["detections"] / counts["commands"] if counts["commands"] else 0.0
            success_rate = counts["successes"] / counts["commands"] if counts["commands"] else 0.0
            technique_usage_frequency = (
                max(counts["techniques"].values()) / counts["commands"] if counts["commands"] and counts["techniques"] else 0.0
            )
            mean_time_to_detect = counts["mttd_seconds"] / counts["mttd_n"] if counts["mttd_n"] else 0.0
            campaign_duration = duration
            lateral_movement_depth = counts["lateral"]
            privilege_escalation_count = counts["priv_esc"]

            feature_map = {
                "detection_rate": detection_rate,
                "success_rate": success_rate,
                "technique_usage_frequency": technique_usage_frequency,
                "mean_time_to_detect": mean_time_to_detect,
                "campaign_duration": campaign_duration,
                "lateral_movement_depth": lateral_movement_depth,
                "privilege_escalation_count": privilege_escalation_count,
            }
            for name, value in feature_map.items():
                rows.append(
                    {
                        "entity_id": campaign_id,
                        "feature_name": name,
                        "value": float(value),
                        "ts": now,
                    }
                )

        dataset_hash = _dataset_hash(rows)
        feature_set_id = int(
            db.execute(
                text(
                    """INSERT INTO analytics.feature_sets (tenant_id, name, version, dataset_hash, "window")
                       VALUES (:tenant_id, :name, :version, :dataset_hash, :window)
                       RETURNING id"""
                ),
                {
                    "tenant_id": tenant_id,
                    "name": "campaign_core_features",
                    "version": version,
                    "dataset_hash": dataset_hash,
                    "window": window,
                },
            ).scalar_one()
        )
        for r in rows:
            db.execute(
                text(
                    """INSERT INTO analytics.features (feature_set_id, entity_id, feature_name, value, ts)
                       VALUES (:feature_set_id, :entity_id, :feature_name, :value, :ts)"""
                ),
                {
                    "feature_set_id": feature_set_id,
                    "entity_id": r["entity_id"],
                    "feature_name": r["feature_name"],
                    "value": r["value"],
                    "ts": r["ts"],
                },
            )

    out_dir = features_storage_dir() / tenant_id
    out_dir.mkdir(parents=True, exist_ok=True)
    parquet_path = out_dir / f"{version}.parquet"
    pd.DataFrame(rows).to_parquet(parquet_path, index=False)
    return {
        "feature_set_id": feature_set_id,
        "tenant_id": tenant_id,
        "version": version,
        "window": window,
        "dataset_hash": dataset_hash,
        "parquet_path": str(parquet_path),
    }
