# Copyright (c) 2026 Jose Maria Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

"""Public client API response contracts (backward-compatible)."""

from __future__ import annotations

from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field


T = TypeVar("T")


class Paginated(BaseModel, Generic[T]):
    """Generic paginated response wrapper."""

    model_config = ConfigDict(extra="forbid")

    items: list[T] = Field(default_factory=list)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    total: int = Field(ge=0)


class RiskSummary(BaseModel):
    """Tenant-scoped risk posture snapshot."""

    model_config = ConfigDict(extra="forbid")

    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    score: float = Field(default=0.0, ge=0.0)
    last_updated: datetime | None = None


class RemediationStatus(BaseModel):
    """Aggregated remediation status for client-safe presentation."""

    model_config = ConfigDict(extra="forbid")

    total_tasks: int = Field(default=0, ge=0)
    open_tasks: int = Field(default=0, ge=0)
    in_progress_tasks: int = Field(default=0, ge=0)
    completed_tasks: int = Field(default=0, ge=0)
    blocked_tasks: int = Field(default=0, ge=0)
