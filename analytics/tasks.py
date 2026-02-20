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

from datetime import datetime, timezone
from typing import Any

from analytics.pipelines import monitor_model_health, run_inference, tenant_security_summary, train_model
from analytics.db import session_scope
from sqlalchemy import text


def train_model_job(task_name: str, tenant_id: str) -> dict[str, Any]:
    return train_model(task_name=task_name, tenant_id=tenant_id)


def run_inference_job(task_name: str, tenant_id: str, entity_id: str) -> dict[str, Any]:
    return run_inference(task=task_name, tenant_id=tenant_id, entity_id=entity_id)


def retrain_model_job(task_name: str, tenant_id: str) -> dict[str, Any]:
    result = train_model(task_name=task_name, tenant_id=tenant_id)
    if task_name in {"control_effectiveness", "residual_risk", "detection_coverage"}:
        tenant_security_summary(tenant_id=tenant_id)
    return result


def nightly_retrain_baseline() -> list[dict[str, Any]]:
    jobs: list[dict[str, Any]] = []
    with session_scope() as db:
        tenant_ids = [str(r[0]) for r in db.execute(text("SELECT id FROM tenants WHERE active=TRUE")).all()]
    for tenant_id in tenant_ids:
        jobs.append(train_model(task_name="baseline_behavior", tenant_id=tenant_id))
    return jobs


def tenant_security_summary_job(tenant_id: str) -> dict[str, Any]:
    return tenant_security_summary(tenant_id=tenant_id)


def model_health_job(tenant_id: str, model_id: int) -> dict[str, Any]:
    return monitor_model_health(tenant_id=tenant_id, model_id=model_id)


def schedule_retraining_snapshot() -> list[dict[str, Any]]:
    with session_scope() as db:
        tenants = [str(r[0]) for r in db.execute(text("SELECT id FROM tenants WHERE active=TRUE")).all()]
    tasks = [
        "next_step_prediction",
        "path_success_probability",
        "operator_efficiency_score",
        "control_effectiveness",
        "residual_risk",
        "detection_coverage",
        "baseline_behavior",
        "remediation_priority",
        "attack_probability_forecast",
        "risk_projection",
        "defense_improvement_projection",
    ]
    out = []
    for tenant_id in tenants:
        for task in tasks:
            out.append(
                {
                    "tenant_id": tenant_id,
                    "task": task,
                    "queued_at": datetime.now(timezone.utc).isoformat(),
                }
            )
    return out
