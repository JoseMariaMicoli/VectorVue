# Copyright (c) 2026 Jose Maria Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

"""Shared dependencies for Phase 7A client API router."""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException, Request
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker


def _db_url() -> str:
    env_url = os.environ.get("VV_DB_URL", "").strip()
    if env_url:
        url = make_url(env_url)
        if url.get_backend_name() == "postgresql" and url.drivername != "postgresql+psycopg":
            url = url.set(drivername="postgresql+psycopg")
        return url.render_as_string(hide_password=False)

    user = os.environ.get("VV_DB_USER", os.environ.get("POSTGRES_USER", "vectorvue"))
    password = os.environ.get("VV_DB_PASSWORD", os.environ.get("POSTGRES_PASSWORD", "strongpassword"))
    host = os.environ.get("VV_DB_HOST", "postgres")
    port = os.environ.get("VV_DB_PORT", "5432")
    name = os.environ.get("VV_DB_NAME", os.environ.get("POSTGRES_DB", "vectorvue_db"))
    return make_url(f"postgresql+psycopg://{user}:{password}@{host}:{port}/{name}").render_as_string(
        hide_password=False
    )


engine = create_engine(_db_url(), pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
_rate_lock = Lock()
_rate_buckets: dict[str, deque[float]] = defaultdict(deque)
_rate_window_seconds = 60
_rate_max_requests = 240


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def client_rate_limit(_request: Request) -> None:
    """Basic in-memory per-client IP limiter to protect read-only client endpoints."""
    host = (_request.client.host if _request.client else "unknown").strip()
    now = time.time()
    with _rate_lock:
        bucket = _rate_buckets[host]
        while bucket and now - bucket[0] > _rate_window_seconds:
            bucket.popleft()
        if len(bucket) >= _rate_max_requests:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        bucket.append(now)
