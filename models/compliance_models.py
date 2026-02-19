from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SignatureEnvelope(BaseModel):
    algorithm: str = "HMAC-SHA256"
    key_id: str = "vv-compliance-v1"
    signed_at: str
    signature: str


class FrameworkItem(BaseModel):
    code: str
    name: str
    version: str
    latest_score: float | None = None
    latest_coverage_percent: float | None = None
    latest_calculated_at: str | None = None


class ControlStateItem(BaseModel):
    control_id: int
    control_code: str
    control_title: str
    requirement_ref: str
    state: str
    evaluated_at: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class FrameworkScoreOut(BaseModel):
    framework: str
    score: float
    coverage_percent: float
    calculated_at: str
    details: dict[str, Any] = Field(default_factory=dict)


class FrameworkReportOut(BaseModel):
    framework: str
    window_days: int
    generated_at: str
    summary: dict[str, Any]
    controls: list[ControlStateItem]
    compliance_events_count: int
    dataset_hash: str


class AuditWindowOut(BaseModel):
    framework: str
    from_ts: str
    to_ts: str
    observations: int
    controls_evaluated: int
    evidence_events: int
    score: float | None = None


class AuditSessionRequest(BaseModel):
    ttl_minutes: int = Field(default=60, ge=5, le=720)
    purpose: str = Field(default="external_audit", min_length=3, max_length=128)


class AuditSessionResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    expires_at: str
    signature: SignatureEnvelope | None = None


class SignedResponse(BaseModel):
    data: dict[str, Any]
    signature: SignatureEnvelope


def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"
