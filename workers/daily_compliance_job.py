from __future__ import annotations

import logging
import os
import threading
from datetime import date, datetime, timezone
from typing import Any

from redis import Redis
from rq import Queue, Worker
from sqlalchemy import text

from analytics.config import redis_url
from analytics.db import session_scope
from services.compliance_scoring import compute_continuous_compliance_score
from services.control_evaluator import evaluate_control
from services.evidence_engine import append_compliance_event
from services.framework_mapper import ensure_framework_catalog
from workers.observation_worker import derive_observations_for_tenant


LOGGER = logging.getLogger("vectorvue.daily_compliance_job")


def _active_tenants() -> list[str]:
    with session_scope() as db:
        return [str(r[0]) for r in db.execute(text("SELECT id FROM tenants WHERE active=TRUE")).all()]


def _framework_codes() -> list[str]:
    with session_scope() as db:
        return [str(r[0]) for r in db.execute(text("SELECT code FROM frameworks WHERE active=TRUE ORDER BY code")).all()]


def _control_ids_for_framework(framework: str) -> list[int]:
    with session_scope() as db:
        rows = db.execute(
            text(
                """SELECT c.id
                   FROM frameworks f
                   JOIN control_mappings cm ON cm.framework_id=f.id
                   JOIN controls c ON c.id=cm.control_id
                   WHERE f.code=:framework
                   ORDER BY c.id"""
            ),
            {"framework": framework},
        ).all()
    return [int(r[0]) for r in rows]


def run_daily_compliance_job(lookback_hours: int = 48, period_days: int = 30) -> dict[str, Any]:
    ensure_framework_catalog()
    tenant_ids = _active_tenants()
    frameworks = _framework_codes()
    out: list[dict[str, Any]] = []
    for tenant_id in tenant_ids:
        obs_result = derive_observations_for_tenant(tenant_id=tenant_id, lookback_hours=lookback_hours)
        framework_results = []
        for framework in frameworks:
            controls = _control_ids_for_framework(framework)
            control_states = []
            for control_id in controls:
                evaluation = evaluate_control(control_id=control_id, tenant_id=tenant_id, period_days=period_days)
                control_states.append(evaluation)
                append_compliance_event(
                    tenant_id=tenant_id,
                    framework=framework,
                    control_id=control_id,
                    status=evaluation["state"],
                    payload={"evaluation": evaluation["details"], "source": "daily_compliance_job"},
                )
            score = compute_continuous_compliance_score(tenant_id=tenant_id, framework=framework, period_days=period_days)
            framework_results.append({"framework": framework, "controls": len(controls), "score": score["score"]})
        out.append({"tenant_id": tenant_id, "observations": obs_result, "frameworks": framework_results})
    return {"ran_at": datetime.now(timezone.utc).isoformat() + "Z", "tenants": out}


def daily_compliance_job_task() -> dict[str, Any]:
    return run_daily_compliance_job()


def _schedule_loop(stop: threading.Event) -> None:
    last_run: date | None = None
    conn = Redis.from_url(redis_url())
    queue = Queue("compliance_daily", connection=conn)
    while not stop.is_set():
        now = datetime.now(timezone.utc)
        if now.hour == 3 and (last_run is None or last_run != now.date()):
            queue.enqueue("workers.daily_compliance_job.daily_compliance_job_task")
            last_run = now.date()
            LOGGER.info("queued daily compliance evaluation job")
        stop.wait(timeout=60)


def run_worker() -> None:
    logging.basicConfig(
        level=os.environ.get("VV_COMPLIANCE_WORKER_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    conn = Redis.from_url(redis_url())
    stop = threading.Event()
    sched = threading.Thread(target=_schedule_loop, args=(stop,), daemon=True)
    sched.start()
    queues = [Queue("compliance_daily", connection=conn)]
    worker = Worker(queues, connection=conn)
    LOGGER.info("daily compliance worker started; queue=compliance_daily")
    try:
        worker.work(with_scheduler=False)
    finally:
        stop.set()


if __name__ == "__main__":
    run_worker()
