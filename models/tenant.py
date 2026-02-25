"""Tenant-aware data models for Phase 6.5.

This module is additive and does not modify existing operator-centric storage logic.
It defines a tenant model and tenant-scoped entities required for customer isolation.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for tenant-aware models."""


class Tenant(Base):
    """Tenant account boundary used to isolate customer data."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class TenantScopedMixin:
    """Mixin for models requiring non-null tenant ownership."""

    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )


class Finding(Base, TenantScopedMixin):
    """Client-facing finding record with tenant boundary."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    visibility_status: Mapped[str] = mapped_column(String(64), default="restricted", nullable=False)
    approval_status: Mapped[str] = mapped_column(String(64), default="pending", nullable=False)


class Evidence(Base, TenantScopedMixin):
    """Evidence metadata with tenant boundary."""

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    finding_id: Mapped[int | None] = mapped_column(nullable=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    visibility_status: Mapped[str] = mapped_column(String(64), default="restricted", nullable=False)
    approval_status: Mapped[str] = mapped_column(String(64), default="pending", nullable=False)


class Campaign(Base, TenantScopedMixin):
    """Campaign metadata with tenant boundary."""

    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)


class Report(Base, TenantScopedMixin):
    """Generated report metadata with tenant boundary."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    rendered_markdown: Mapped[str] = mapped_column(Text, nullable=False)
    visibility_status: Mapped[str] = mapped_column(String(64), default="restricted", nullable=False)
    approval_status: Mapped[str] = mapped_column(String(64), default="pending", nullable=False)


class RemediationTask(Base, TenantScopedMixin):
    """Remediation workflow task with tenant boundary."""

    __tablename__ = "remediation_tasks"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    finding_id: Mapped[int | None] = mapped_column(nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(64), default="open", nullable=False)


def migration_safe_default_sql(default_tenant_name: str = "legacy-default") -> list[str]:
    """Generate SQL statements for migration-safe tenant defaulting.

    The sequence keeps existing rows valid by creating a default tenant, backfilling
    tenant_id values, and enforcing NOT NULL + foreign key constraints.
    """

    return [
        """
        CREATE TABLE IF NOT EXISTS tenants (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            active BOOLEAN NOT NULL DEFAULT TRUE
        )
        """.strip(),
        f"""
        INSERT INTO tenants (id, name, created_at, active)
        VALUES ('00000000-0000-0000-0000-000000000001', '{default_tenant_name}', NOW(), TRUE)
        ON CONFLICT (id) DO NOTHING
        """.strip(),
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS tenant_id UUID",
        "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS tenant_id UUID",
        "ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS tenant_id UUID",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS tenant_id UUID",
        "ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS tenant_id UUID",
        "UPDATE findings SET tenant_id='00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL",
        "UPDATE evidence SET tenant_id='00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL",
        "UPDATE campaigns SET tenant_id='00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL",
        "UPDATE reports SET tenant_id='00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL",
        "UPDATE remediation_tasks SET tenant_id='00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL",
        "ALTER TABLE findings ALTER COLUMN tenant_id SET NOT NULL",
        "ALTER TABLE evidence ALTER COLUMN tenant_id SET NOT NULL",
        "ALTER TABLE campaigns ALTER COLUMN tenant_id SET NOT NULL",
        "ALTER TABLE reports ALTER COLUMN tenant_id SET NOT NULL",
        "ALTER TABLE remediation_tasks ALTER COLUMN tenant_id SET NOT NULL",
        (
            "ALTER TABLE findings ADD CONSTRAINT findings_tenant_fk "
            "FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT"
        ),
        (
            "ALTER TABLE evidence ADD CONSTRAINT evidence_tenant_fk "
            "FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT"
        ),
        (
            "ALTER TABLE campaigns ADD CONSTRAINT campaigns_tenant_fk "
            "FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT"
        ),
        (
            "ALTER TABLE reports ADD CONSTRAINT reports_tenant_fk "
            "FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT"
        ),
        (
            "ALTER TABLE remediation_tasks ADD CONSTRAINT remediation_tasks_tenant_fk "
            "FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT"
        ),
    ]
