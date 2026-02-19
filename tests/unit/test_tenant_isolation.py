# Copyright (c) 2026 Jose Maria Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

"""Phase 6.5 tenant isolation tests."""

from __future__ import annotations

import unittest

from sqlalchemy import create_engine, delete, select, update
from sqlalchemy.orm import Session

from db.readonly_repo import ReadOnlyTenantRepository, ReadOnlyViolation
from db.tenant_session import SecurityError, TenantSession
from models.tenant import Base, Finding, Tenant


class TenantIsolationTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
        Base.metadata.create_all(self.engine)
        self.session = Session(self.engine)

        self.tenant_a = Tenant(id="00000000-0000-0000-0000-00000000000a", name="Tenant A")
        self.tenant_b = Tenant(id="00000000-0000-0000-0000-00000000000b", name="Tenant B")
        self.session.add_all([self.tenant_a, self.tenant_b])
        self.session.flush()

        self.session.add_all(
            [
                Finding(
                    tenant_id=self.tenant_a.id,
                    title="A Finding",
                    visibility_status="customer_visible",
                    approval_status="approved",
                ),
                Finding(
                    tenant_id=self.tenant_b.id,
                    title="B Finding",
                    visibility_status="customer_visible",
                    approval_status="approved",
                ),
            ]
        )
        self.session.commit()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def test_tenant_a_cannot_read_tenant_b_finding(self):
        guarded = TenantSession(self.session, tenant_id=self.tenant_a.id)
        rows = guarded.scalars(select(Finding).order_by(Finding.id)).all()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].title, "A Finding")
        self.assertEqual(rows[0].tenant_id, self.tenant_a.id)

    def test_cross_tenant_select_filter_raises(self):
        guarded = TenantSession(self.session, tenant_id=self.tenant_a.id)
        stmt = select(Finding).where(Finding.tenant_id == self.tenant_b.id)
        with self.assertRaises(SecurityError):
            guarded.scalars(stmt).all()

    def test_update_without_explicit_tenant_filter_is_blocked(self):
        guarded = TenantSession(self.session, tenant_id=self.tenant_a.id)
        stmt = update(Finding).where(Finding.title == "A Finding").values(title="Mutated")
        with self.assertRaises(SecurityError):
            guarded.execute(stmt)

    def test_delete_with_cross_tenant_filter_is_blocked(self):
        guarded = TenantSession(self.session, tenant_id=self.tenant_a.id)
        stmt = delete(Finding).where(Finding.tenant_id == self.tenant_b.id)
        with self.assertRaises(SecurityError):
            guarded.execute(stmt)

    def test_readonly_repo_blocks_write(self):
        ro = ReadOnlyTenantRepository(self.session, tenant_id=self.tenant_a.id)
        with self.assertRaises(ReadOnlyViolation):
            ro.execute(update(Finding).where(Finding.tenant_id == self.tenant_a.id).values(title="x"))


if __name__ == "__main__":
    unittest.main()
