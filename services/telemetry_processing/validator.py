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

"""Canonical telemetry schema + MITRE ATT&CK mapping validation."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CanonicalTelemetryPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    event_type: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    source_system: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    severity: str = Field(min_length=2, max_length=16)
    observed_at: datetime
    mitre_techniques: list[str] = Field(min_length=1, max_length=32)
    mitre_tactics: list[str] = Field(default_factory=list, max_length=32)
    attributes: dict[str, str | int | float | bool | None] = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {"info", "low", "medium", "high", "critical"}
        if normalized not in allowed:
            raise ValueError("severity must be one of info|low|medium|high|critical")
        return normalized

    @field_validator("mitre_techniques")
    @classmethod
    def validate_techniques(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or not isinstance(item, str):
                raise ValueError("mitre_techniques entries must be non-empty strings")
            # ATT&CK TTP format: T#### or T####.###
            import re

            if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", item.strip().upper()):
                raise ValueError("mitre_techniques entries must match T#### or T####.###")
        return [i.strip().upper() for i in value]

    @field_validator("mitre_tactics")
    @classmethod
    def validate_tactics(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or not isinstance(item, str):
                raise ValueError("mitre_tactics entries must be non-empty strings")
            import re

            if not re.fullmatch(r"TA\d{4}", item.strip().upper()):
                raise ValueError("mitre_tactics entries must match TA####")
        return [i.strip().upper() for i in value]


def validate_canonical_payload(payload: dict) -> CanonicalTelemetryPayload:
    return CanonicalTelemetryPayload.model_validate(payload)
