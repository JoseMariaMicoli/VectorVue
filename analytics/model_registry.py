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
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from analytics.db import session_scope


def register_model(
    tenant_id: str,
    task: str,
    version: str,
    dataset_hash: str,
    algorithm: str,
    hyperparameters: dict[str, Any],
    metrics: dict[str, Any],
    stage: str = "experimental",
) -> int:
    with session_scope() as db:
        model_id = int(
            db.execute(
                text(
                    """INSERT INTO analytics.models
                       (tenant_id, task, version, dataset_hash, algorithm, hyperparameters, metrics, stage)
                       VALUES (:tenant_id, :task, :version, :dataset_hash, :algorithm, CAST(:hyperparameters AS JSONB), CAST(:metrics AS JSONB), :stage)
                       RETURNING id"""
                ),
                {
                    "tenant_id": tenant_id,
                    "task": task,
                    "version": version,
                    "dataset_hash": dataset_hash,
                    "algorithm": algorithm,
                    "hyperparameters": json.dumps(hyperparameters, default=str),
                    "metrics": json.dumps(metrics, default=str),
                    "stage": stage,
                },
            ).scalar_one()
        )
    return model_id


def promote_model(model_id: int, tenant_id: str) -> None:
    with session_scope() as db:
        row = db.execute(
            text("SELECT id, task FROM analytics.models WHERE id=:id AND tenant_id=:tenant_id"),
            {"id": model_id, "tenant_id": tenant_id},
        ).mappings().first()
        if not row:
            raise ValueError("model not found")
        task = str(row["task"])
        db.execute(
            text(
                """UPDATE analytics.models
                   SET stage='staging'
                   WHERE tenant_id=:tenant_id AND task=:task AND stage='production'"""
            ),
            {"tenant_id": tenant_id, "task": task},
        )
        db.execute(
            text(
                """UPDATE analytics.models
                   SET stage='production'
                   WHERE id=:id AND tenant_id=:tenant_id"""
            ),
            {"id": model_id, "tenant_id": tenant_id},
        )


def get_production_model(tenant_id: str, task: str) -> dict[str, Any] | None:
    with session_scope() as db:
        row = db.execute(
            text(
                """SELECT *
                   FROM analytics.models
                   WHERE tenant_id=:tenant_id AND task=:task AND stage='production'
                   ORDER BY created_at DESC
                   LIMIT 1"""
            ),
            {"tenant_id": tenant_id, "task": task},
        ).mappings().first()
        return dict(row) if row else None


def store_prediction(
    tenant_id: str,
    model_id: int,
    entity_id: str,
    prediction: dict[str, Any],
    explanation: dict[str, Any],
) -> int:
    with session_scope() as db:
        pred_id = int(
            db.execute(
                text(
                    """INSERT INTO analytics.predictions
                       (tenant_id, model_id, entity_id, prediction, explanation)
                       VALUES (:tenant_id, :model_id, :entity_id, CAST(:prediction AS JSONB), CAST(:explanation AS JSONB))
                       RETURNING id"""
                ),
                {
                    "tenant_id": tenant_id,
                    "model_id": model_id,
                    "entity_id": entity_id,
                    "prediction": json.dumps(prediction, default=str),
                    "explanation": json.dumps(explanation, default=str),
                },
            ).scalar_one()
        )
    return pred_id


def get_latest_prediction(tenant_id: str, task: str, entity_id: str) -> dict[str, Any] | None:
    with session_scope() as db:
        row = db.execute(
            text(
                """SELECT p.id, p.tenant_id, p.entity_id, p.prediction, p.explanation, p.created_at, m.version AS model_version
                   FROM analytics.predictions p
                   JOIN analytics.models m ON m.id = p.model_id
                   WHERE p.tenant_id=:tenant_id
                     AND p.entity_id=:entity_id
                     AND m.task=:task
                   ORDER BY p.created_at DESC
                   LIMIT 1"""
            ),
            {"tenant_id": tenant_id, "task": task, "entity_id": entity_id},
        ).mappings().first()
        return dict(row) if row else None


def upsert_tenant_summary(
    tenant_id: str,
    security_posture: dict[str, Any],
    trend: dict[str, Any],
    maturity_level: str,
    generated_by_model_version: str,
) -> None:
    with session_scope() as db:
        db.execute(
            text(
                """INSERT INTO analytics.tenant_security_summary
                   (tenant_id, security_posture, trend, maturity_level, updated_at, generated_by_model_version)
                   VALUES (:tenant_id, CAST(:security_posture AS JSONB), CAST(:trend AS JSONB), :maturity_level, :updated_at, :generated_by_model_version)
                   ON CONFLICT (tenant_id) DO UPDATE SET
                     security_posture=EXCLUDED.security_posture,
                     trend=EXCLUDED.trend,
                     maturity_level=EXCLUDED.maturity_level,
                     updated_at=EXCLUDED.updated_at,
                     generated_by_model_version=EXCLUDED.generated_by_model_version"""
            ),
            {
                "tenant_id": tenant_id,
                "security_posture": json.dumps(security_posture, default=str),
                "trend": json.dumps(trend, default=str),
                "maturity_level": maturity_level,
                "updated_at": datetime.now(timezone.utc),
                "generated_by_model_version": generated_by_model_version,
            },
        )

