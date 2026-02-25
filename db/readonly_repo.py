"""Read-only tenant-enforced repository for client-safe access."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session
from sqlalchemy.sql import Select

from db.tenant_session import SecurityError, TenantSession


class ReadOnlyViolation(SecurityError):
    """Raised when a write operation is attempted in read-only mode."""


class ReadOnlyTenantRepository:
    """SELECT-only data access layer with mandatory tenant isolation."""

    def __init__(self, session: Session, tenant_id: UUID | str):
        self._tenant_session = TenantSession(session=session, tenant_id=tenant_id)

    def execute(self, statement, *args, **kwargs):
        if not isinstance(statement, Select):
            raise ReadOnlyViolation("Read-only repository accepts SELECT statements only")
        return self._tenant_session.execute(statement, *args, **kwargs)

    def scalars(self, statement, *args, **kwargs):
        return self.execute(statement, *args, **kwargs).scalars()

    def scalar(self, statement, *args, **kwargs):
        return self.execute(statement, *args, **kwargs).scalar()

    def add(self, *_args, **_kwargs):
        raise ReadOnlyViolation("Read-only repository does not permit inserts")

    def delete(self, *_args, **_kwargs):
        raise ReadOnlyViolation("Read-only repository does not permit deletes")

    def commit(self):
        raise ReadOnlyViolation("Read-only repository does not permit commit")
