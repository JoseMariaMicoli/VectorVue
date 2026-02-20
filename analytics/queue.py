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

from redis import Redis
from rq import Queue

from analytics.config import redis_url


def redis_conn() -> Redis:
    return Redis.from_url(redis_url())


def get_queue(name: str) -> Queue:
    return Queue(name, connection=redis_conn(), default_timeout=3600)


def enqueue_train_model(task_name: str, tenant_id: str):
    return get_queue("train_model").enqueue("analytics.tasks.train_model_job", task_name, tenant_id)


def enqueue_run_inference(task_name: str, tenant_id: str, entity_id: str):
    return get_queue("run_inference").enqueue("analytics.tasks.run_inference_job", task_name, tenant_id, entity_id)


def enqueue_retrain_model(task_name: str, tenant_id: str):
    return get_queue("retrain_model").enqueue("analytics.tasks.retrain_model_job", task_name, tenant_id)

