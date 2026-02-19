from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text

from analytics.db import session_scope


STATE_SCORE = {
    "operating": 1.0,
    "degraded": 0.55,
    "failed": 0.0,
    "insufficient_evidence": 0.25,
}


def _safe_ratio(num: float, den: float) -> float:
    if den <= 0:
        return 0.0
    return num / den


def compute_continuous_compliance_score(tenant_id: str, framework: str, period_days: int = 30) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=max(1, int(period_days)))

    with session_scope() as db:
        control_states = db.execute(
            text(
                """SELECT csh.state
                   FROM control_state_history csh
                   JOIN control_mappings cm ON cm.control_id=csh.control_id
                   JOIN frameworks f ON f.id=cm.framework_id
                   WHERE csh.tenant_id=:tenant_id
                     AND csh.evaluated_at >= :since
                     AND f.code=:framework"""
            ),
            {"tenant_id": tenant_id, "framework": framework, "since": since},
        ).mappings().all()
        control_scores = [STATE_SCORE.get(str(r["state"]), 0.2) for r in control_states]
        control_effectiveness = sum(control_scores) / len(control_scores) if control_scores else 0.2

        counts = db.execute(
            text(
                """SELECT
                      COUNT(*) FILTER (WHERE event_type='DETECTION_LOGGED') AS detections,
                      COUNT(*) FILTER (WHERE event_type='COMMAND_EXECUTED') AS commands,
                      COUNT(*) FILTER (WHERE event_type='OPERATOR_ACTION') AS operator_actions
                   FROM analytics.events
                   WHERE tenant_id=:tenant_id
                     AND timestamp >= :since"""
            ),
            {"tenant_id": tenant_id, "since": since},
        ).mappings().first()
        detections = float(counts["detections"] or 0)
        commands = float(counts["commands"] or 0)
        operator_actions = float(counts["operator_actions"] or 0)
        detection_reliability = min(1.0, _safe_ratio(detections + 1.0, commands + 1.0))
        operational_discipline = min(1.0, _safe_ratio(operator_actions + detections + 1.0, commands + 1.0))

        obs_coverage = db.execute(
            text(
                """SELECT COUNT(*) AS obs,
                          COUNT(DISTINCT DATE(observed_at)) AS obs_days
                   FROM control_observations
                   WHERE tenant_id=:tenant_id
                     AND observed_at >= :since"""
            ),
            {"tenant_id": tenant_id, "since": since},
        ).mappings().first()
        obs_days = float(obs_coverage["obs_days"] or 0)
        monitoring_coverage = min(1.0, _safe_ratio(obs_days, float(period_days)))

        response_stats = db.execute(
            text(
                """SELECT
                      COUNT(*) FILTER (WHERE event_type='REMEDIATION_OPENED') AS opened,
                      COUNT(*) FILTER (WHERE event_type='REMEDIATION_COMPLETED') AS completed
                   FROM client_activity_events
                   WHERE tenant_id=:tenant_id
                     AND timestamp >= :since"""
            ),
            {"tenant_id": tenant_id, "since": since},
        ).mappings().first()
        opened = float(response_stats["opened"] or 0)
        completed = float(response_stats["completed"] or 0)
        incident_response = min(1.0, _safe_ratio(completed + 1.0, opened + 1.0))

        stability_stats = db.execute(
            text(
                """SELECT
                      COUNT(*) FILTER (WHERE state='failed') AS failed_count,
                      COUNT(*) AS total_count
                   FROM control_state_history
                   WHERE tenant_id=:tenant_id
                     AND evaluated_at >= :since"""
            ),
            {"tenant_id": tenant_id, "since": since},
        ).mappings().first()
        failed_count = float(stability_stats["failed_count"] or 0)
        total_count = float(stability_stats["total_count"] or 0)
        historical_stability = 1.0 - min(1.0, _safe_ratio(failed_count, total_count if total_count > 0 else 1.0))

        weighted = (
            control_effectiveness * 0.35
            + detection_reliability * 0.15
            + monitoring_coverage * 0.15
            + operational_discipline * 0.1
            + incident_response * 0.15
            + historical_stability * 0.1
        )
        score = round(max(0.0, min(100.0, weighted * 100.0)), 2)
        coverage_percent = round(max(0.0, min(100.0, monitoring_coverage * 100.0)), 2)
        details = {
            "control_effectiveness": round(control_effectiveness, 4),
            "detection_reliability": round(detection_reliability, 4),
            "monitoring_coverage": round(monitoring_coverage, 4),
            "operational_discipline": round(operational_discipline, 4),
            "incident_response": round(incident_response, 4),
            "historical_stability": round(historical_stability, 4),
            "period_days": int(period_days),
        }

        db.execute(
            text(
                """INSERT INTO compliance_scores (tenant_id, framework, score, coverage_percent, calculated_at, details_json)
                   VALUES (:tenant_id, :framework, :score, :coverage_percent, :calculated_at, CAST(:details_json AS JSONB))"""
            ),
            {
                "tenant_id": tenant_id,
                "framework": framework,
                "score": score,
                "coverage_percent": coverage_percent,
                "calculated_at": now,
                "details_json": json.dumps(details, sort_keys=True),
            },
        )
        db.execute(
            text(
                """INSERT INTO compliance_snapshots (tenant_id, framework, score, snapshot_at, metadata_json)
                   VALUES (:tenant_id, :framework, :score, :snapshot_at, CAST(:metadata_json AS JSONB))"""
            ),
            {
                "tenant_id": tenant_id,
                "framework": framework,
                "score": score,
                "snapshot_at": now,
                "metadata_json": json.dumps({"coverage_percent": coverage_percent, "source": "daily_evaluation"}, sort_keys=True),
            },
        )

    return {
        "tenant_id": tenant_id,
        "framework": framework,
        "score": score,
        "coverage_percent": coverage_percent,
        "calculated_at": now.isoformat() + "Z",
        "details": details,
    }

