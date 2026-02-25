from __future__ import annotations

import os
from pathlib import Path


def analytics_storage_root() -> Path:
    root = Path(os.environ.get("VV_ANALYTICS_STORAGE_DIR", "/storage"))
    root.mkdir(parents=True, exist_ok=True)
    return root


def features_storage_dir() -> Path:
    d = analytics_storage_root() / "features"
    d.mkdir(parents=True, exist_ok=True)
    return d


def datasets_storage_dir() -> Path:
    d = analytics_storage_root() / "datasets"
    d.mkdir(parents=True, exist_ok=True)
    return d


def models_storage_dir() -> Path:
    d = analytics_storage_root() / "models"
    d.mkdir(parents=True, exist_ok=True)
    return d


def redis_url() -> str:
    return os.environ.get("VV_REDIS_URL", "redis://:strongpassword@redis:6379/0").strip()


def pg_url() -> str:
    return os.environ.get("VV_DB_URL", "postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db").strip()


def drift_threshold() -> float:
    try:
        return float(os.environ.get("VV_ML_DRIFT_THRESHOLD", "0.25"))
    except Exception:
        return 0.25
