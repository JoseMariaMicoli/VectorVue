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

"""Client-safe schemas with internal fields removed by contract."""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, ConfigDict


class ClientSafeBase(BaseModel):
    """Shared serializer base for customer-facing sanitized data."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")


class ClientFinding(ClientSafeBase):
    id: int
    title: str
    severity: str | None = None
    cvss_score: float | None = None
    mitre_id: str | None = None
    created_at: datetime | None = None
    visibility_status: str
    approval_status: str


class ClientEvidence(ClientSafeBase):
    id: int
    finding_id: int | None = None
    label: str
    collected_at: datetime | None = None
    hash_sha256: str | None = None
    visibility_status: str
    approval_status: str


class ClientReport(ClientSafeBase):
    id: int
    title: str
    created_at: datetime | None = None
    summary: str | None = None
    visibility_status: str
    approval_status: str


class ClientThemeOut(ClientSafeBase):
    company_name: str
    logo_url: str | None = None
    colors: dict[str, str]
    platform_brand_locked: bool = True
    platform_attribution: dict[str, str]
