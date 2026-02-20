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

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from sqlalchemy import text

from analytics.config import datasets_storage_dir
from analytics.db import session_scope


def _hash_dataframe(df: pd.DataFrame) -> str:
    ordered = df.sort_values(list(df.columns)).reset_index(drop=True)
    payload = ordered.to_json(orient="records", date_format="iso")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_training_dataset(tenant_id: str, task_name: str) -> tuple[pd.DataFrame, str, str]:
    """Build point-in-time safe dataset for a task."""
    cutoff = datetime.now(timezone.utc)
    with session_scope() as db:
        feature_set = db.execute(
            text(
                """SELECT id, version
                   FROM analytics.feature_sets
                   WHERE tenant_id=:tenant_id
                   ORDER BY created_at DESC
                   LIMIT 1"""
            ),
            {"tenant_id": tenant_id},
        ).mappings().first()
        if not feature_set:
            return pd.DataFrame(), "", ""

        feature_rows = db.execute(
            text(
                """SELECT entity_id, feature_name, value, ts
                   FROM analytics.features
                   WHERE feature_set_id=:feature_set_id
                     AND ts <= :cutoff"""
            ),
            {"feature_set_id": int(feature_set["id"]), "cutoff": cutoff},
        ).mappings().all()

        events = db.execute(
            text(
                """SELECT entity_type, entity_id, event_type, timestamp, payload
                   FROM analytics.events
                   WHERE tenant_id=:tenant_id
                     AND timestamp <= :cutoff"""
            ),
            {"tenant_id": tenant_id, "cutoff": cutoff},
        ).mappings().all()

    if not feature_rows:
        return pd.DataFrame(), "", ""

    df_features = pd.DataFrame(feature_rows)
    x = df_features.pivot_table(
        index="entity_id",
        columns="feature_name",
        values="value",
        aggfunc="last",
        fill_value=0.0,
    ).reset_index()
    x.columns = [str(c) for c in x.columns]

    # Labels are generated strictly from events <= cutoff (point-in-time correctness).
    labels: dict[str, float] = {}
    for r in events:
        entity_id = str(r["entity_id"] or "")
        et = str(r["event_type"] or "").upper()
        payload = r["payload"] or {}
        if task_name in {"next_step_prediction", "path_success_probability", "operator_efficiency_score"}:
            if et == "COMMAND_EXECUTED":
                labels[entity_id] = labels.get(entity_id, 0.0) + (1.0 if bool(payload.get("success", True)) else 0.0)
        elif task_name in {"control_effectiveness", "residual_risk", "detection_coverage"}:
            if et == "DETECTION_LOGGED":
                labels[entity_id] = labels.get(entity_id, 0.0) + 1.0
        elif task_name == "baseline_behavior":
            labels[entity_id] = labels.get(entity_id, 0.0) + 1.0
        elif task_name == "remediation_priority":
            if et in {"FINDING_CREATED", "FINDING_APPROVED"}:
                labels[entity_id] = float(payload.get("severity_score", 5.0))
        elif task_name in {"attack_probability_forecast", "risk_projection", "defense_improvement_projection"}:
            labels[entity_id] = labels.get(entity_id, 0.0) + 1.0

    x["label"] = x["entity_id"].map(lambda eid: float(labels.get(str(eid), 0.0)))
    x["task_name"] = task_name
    x["tenant_id"] = tenant_id
    x["cutoff_ts"] = cutoff.isoformat()

    dataset_hash = _hash_dataframe(x)
    out_dir = datasets_storage_dir() / tenant_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{task_name}_{dataset_hash[:12]}.parquet"
    x.to_parquet(out_path, index=False)
    return x, dataset_hash, str(out_path)

