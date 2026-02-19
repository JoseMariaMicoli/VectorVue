from __future__ import annotations

import logging
import os
import threading
import time
from datetime import date, datetime, timezone

from redis import Redis
from rq import Connection, Queue, Worker

from analytics.config import redis_url
from analytics.queue import enqueue_retrain_model
from analytics.tasks import schedule_retraining_snapshot


LOGGER = logging.getLogger("vectorvue.ml_worker")


def _schedule_loop(stop: threading.Event) -> None:
    """Nightly retraining scheduler (no HTTP, enqueue only)."""
    last_run: date | None = None
    while not stop.is_set():
        now = datetime.now(timezone.utc)
        if now.hour == 2 and (last_run is None or last_run != now.date()):
            for item in schedule_retraining_snapshot():
                enqueue_retrain_model(item["task"], item["tenant_id"])
            last_run = now.date()
            LOGGER.info("queued nightly retraining jobs")
        stop.wait(timeout=60)


def run_worker() -> None:
    logging.basicConfig(
        level=os.environ.get("VV_ML_WORKER_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    conn = Redis.from_url(redis_url())
    stop = threading.Event()
    sched_thread = threading.Thread(target=_schedule_loop, args=(stop,), daemon=True)
    sched_thread.start()
    queues = [Queue("train_model", connection=conn), Queue("run_inference", connection=conn), Queue("retrain_model", connection=conn)]
    with Connection(conn):
        worker = Worker(queues)
        LOGGER.info("ml-worker started; queues=train_model,run_inference,retrain_model")
        try:
            worker.work(with_scheduler=False)
        finally:
            stop.set()


if __name__ == "__main__":
    run_worker()

