"""Pydantic schemas for Phase 7A client public API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ClientEvidenceGalleryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    finding_id: int
    artifact_type: str
    description: str | None = None
    collected_at: datetime | None = None
    approval_status: str
    download_url: str


class ClientReportItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    title: str
    report_date: datetime | None = None
    status: str
    download_url: str


class ClientRemediationTask(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    finding_id: int | None = None
    title: str
    status: str
    priority: str | None = None
    due_date: datetime | None = None


class ClientFindingDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    title: str
    description: str | None = None
    severity: str | None = None
    status: str
    cvss_score: float | None = None
    mitre_id: str | None = None
    visibility_status: str
    approval_status: str


class ClientEvidenceGalleryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: int
    items: list[ClientEvidenceGalleryItem] = Field(default_factory=list)


class ClientRemediationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ClientRemediationTask] = Field(default_factory=list)
