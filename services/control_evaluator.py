from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text

from analytics.db import session_scope


VALID_STATES = {"operating", "degraded", "failed", "insufficient_evidence"}


def evaluate_control(control_id: int, tenant_id: str, period_days: int) -> dict[str, Any]:
    period_days = max(1, int(period_days))
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=period_days)

    with session_scope() as db:
        policy = db.execute(
            text(
                """SELECT expected_frequency, failure_threshold, observation_window_days, required_coverage_percent
                   FROM control_policies
                   WHERE control_id=:control_id"""
            ),
            {"control_id": control_id},
        ).mappings().first()
        if not policy:
            policy = {
                "expected_frequency": 1,
                "failure_threshold": 0.15,
                "observation_window_days": period_days,
                "required_coverage_percent": 80.0,
            }

        obs_rows = db.execute(
            text(
                """SELECT result, confidence, observed_at
                   FROM control_observations
                   WHERE tenant_id=:tenant_id
                     AND control_id=:control_id
                     AND observed_at >= :since
                   ORDER BY observed_at DESC"""
            ),
            {"tenant_id": tenant_id, "control_id": control_id, "since": since},
        ).mappings().all()
        observations = [dict(r) for r in obs_rows]

        total = len(observations)
        success = sum(1 for r in observations if str(r.get("result")) == "success")
        failures = total - success
        failure_rate = float(failures / total) if total else 1.0
        active_days = len({str(r.get("observed_at"))[:10] for r in observations})
        coverage_percent = (active_days / max(1, period_days)) * 100.0
        expected_frequency = int(policy["expected_frequency"])
        required_coverage = float(policy["required_coverage_percent"])
        threshold = float(policy["failure_threshold"])
        enough_frequency = total >= expected_frequency

        state = "operating"
        if total == 0 or coverage_percent < max(10.0, required_coverage * 0.5):
            state = "insufficient_evidence"
        elif failure_rate > threshold or not enough_frequency:
            state = "failed"
        elif failure_rate > (threshold * 0.5) or coverage_percent < required_coverage:
            state = "degraded"

        last_two = db.execute(
            text(
                """SELECT state
                   FROM control_state_history
                   WHERE tenant_id=:tenant_id AND control_id=:control_id
                   ORDER BY evaluated_at DESC
                   LIMIT 2"""
            ),
            {"tenant_id": tenant_id, "control_id": control_id},
        ).mappings().all()
        regression_detected = False
        if last_two:
            prev = str(last_two[0].get("state", ""))
            if prev == "operating" and state in {"degraded", "failed"}:
                regression_detected = True
            if prev == "degraded" and state == "failed":
                regression_detected = True

        details = {
            "period_days": period_days,
            "window_start": since.isoformat(),
            "window_end": now.isoformat(),
            "total_observations": total,
            "success_observations": success,
            "failure_observations": failures,
            "failure_rate": round(failure_rate, 4),
            "coverage_percent": round(coverage_percent, 2),
            "expected_frequency": expected_frequency,
            "required_coverage_percent": required_coverage,
            "threshold": threshold,
            "regression_detected": regression_detected,
        }

        if state not in VALID_STATES:
            state = "insufficient_evidence"

        db.execute(
            text(
                """INSERT INTO control_state_history (tenant_id, control_id, state, evaluated_at, details_json)
                   VALUES (:tenant_id, :control_id, :state, :evaluated_at, CAST(:details_json AS JSONB))"""
            ),
            {
                "tenant_id": tenant_id,
                "control_id": control_id,
                "state": state,
                "evaluated_at": now,
                "details_json": json.dumps(details, sort_keys=True),
            },
        )

    return {"control_id": control_id, "tenant_id": tenant_id, "state": state, "details": details, "evaluated_at": now.isoformat() + "Z"}

