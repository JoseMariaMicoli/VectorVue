from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator


T = TypeVar("T")


class SpectraStrikeTelemetryEvent(BaseModel):
    """Inbound SpectraStrike telemetry event contract."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "source_system": "spectrastrike-sensor",
                "event_type": "PROCESS_ANOMALY",
                "occurred_at": "2026-02-22T10:00:00Z",
                "severity": "high",
                "asset_ref": "host-nyc-01",
                "message": "Unexpected parent-child process chain",
                "metadata": {"pid": 2244},
            }
        },
    )

    event_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    source_system: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    event_type: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    occurred_at: datetime
    severity: str = Field(min_length=2, max_length=16)
    asset_ref: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=1024)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {"info", "low", "medium", "high", "critical"}
        if normalized not in allowed:
            raise ValueError("severity must be one of info|low|medium|high|critical")
        return normalized


class SpectraStrikeFinding(BaseModel):
    """Inbound SpectraStrike finding contract."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "title": "Suspicious PowerShell Script",
                "description": "Encoded command observed in endpoint telemetry",
                "severity": "critical",
                "status": "open",
                "first_seen": "2026-02-22T09:45:00Z",
                "asset_ref": "host-nyc-01",
                "recommendation": "Block script hash and isolate endpoint",
            }
        },
    )

    finding_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    title: str = Field(min_length=3, max_length=256)
    description: str = Field(min_length=1, max_length=4096)
    severity: str = Field(min_length=2, max_length=16)
    status: str = Field(default="open", min_length=2, max_length=32)
    first_seen: datetime
    last_seen: datetime | None = None
    asset_ref: str | None = Field(default=None, max_length=128)
    recommendation: str | None = Field(default=None, max_length=2048)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def normalize_severity(cls, value: str) -> str:
        mapping = {
            "informational": "info",
            "info": "info",
            "low": "low",
            "medium": "medium",
            "med": "medium",
            "high": "high",
            "critical": "critical",
        }
        normalized = mapping.get(value.strip().lower())
        if not normalized:
            raise ValueError("severity must be one of informational|info|low|medium|high|critical")
        return normalized

    @field_validator("status")
    @classmethod
    def normalize_status(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {"open", "in_progress", "resolved", "closed"}
        if normalized not in allowed:
            raise ValueError("status must be one of open|in_progress|resolved|closed")
        return normalized


class SpectraStrikeBatchItemResult(BaseModel):
    """Per-item outcome for batch ingestion."""

    model_config = ConfigDict(extra="forbid")

    index: int = Field(ge=0)
    item_id: str | None = None
    status: Literal["accepted", "failed", "replayed"]
    error_code: str | None = None
    error_message: str | None = None


class SpectraStrikeIngestSummary(BaseModel):
    """Aggregated batch/single ingest summary."""

    model_config = ConfigDict(extra="forbid")

    total: int = Field(ge=0)
    accepted: int = Field(ge=0)
    failed: int = Field(ge=0)


class SpectraStrikeStatusResponse(BaseModel):
    """Polling response for async/recorded ingest request status."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    status: Literal["accepted", "partial", "failed", "replayed"]
    endpoint: str
    counts: SpectraStrikeIngestSummary
    failed_items: list[SpectraStrikeBatchItemResult] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class EnvelopeSignature(BaseModel):
    model_config = ConfigDict(extra="forbid")

    algorithm: str
    signed_at: str
    signature: str


class IntegrationError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str


class IntegrationEnvelope(BaseModel, Generic[T]):
    """Standard integration response envelope."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    status: Literal["accepted", "partial", "failed", "replayed"]
    data: T
    errors: list[IntegrationError] = Field(default_factory=list)
    signature: EnvelopeSignature | None = None


class SpectraStrikeSingleEventOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str


class SpectraStrikeSingleFindingOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str


class SpectraStrikeBatchOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: SpectraStrikeIngestSummary
    results: list[SpectraStrikeBatchItemResult] = Field(default_factory=list)
