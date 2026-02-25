"""
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
"""

import os
import unittest
from datetime import datetime

from vv_core import Database, SessionCrypto, Role


@unittest.skipUnless(os.environ.get("VV_DB_BACKEND", "") == "postgres", "postgres backend required")
class PostgresSmokeTests(unittest.TestCase):
    def setUp(self):
        self.crypto = SessionCrypto()
        self.crypto.derive_key("VectorVueTestPassphrase!")
        self.db = Database(self.crypto)
        self.username = "pg_smoke_admin"
        self.password = "SmokePass123!"
        ok, _ = self.db.authenticate_user(self.username, self.password)
        if not ok:
            self.db.register_user(
                self.username,
                self.password,
                role=Role.ADMIN,
                group_name="default",
                bypass_legal=True,
            )
            ok, msg = self.db.authenticate_user(self.username, self.password)
            self.assertTrue(ok, msg)

    def tearDown(self):
        self.db.close()

    def test_auth_and_campaign_crud(self):
        campaign_name = f"PG_SMOKE_CAMPAIGN_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
        ok, _ = self.db.create_campaign(campaign_name, "DEFAULT")
        self.assertTrue(ok)
        campaign = self.db.get_campaign_by_name(campaign_name)
        self.assertIsNotNone(campaign)

    def test_findings_roundtrip(self):
        from vv_core import Finding

        f = Finding(
            id=None,
            title="PG Smoke Finding",
            description="desc",
            cvss_score=5.0,
            mitre_id="T1003",
            tactic_id="",
            status="Open",
            evidence="",
            remediation="",
            project_id="DEFAULT",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            evidence_hash="",
            created_by=None,
            last_modified_by=None,
            assigned_to=None,
            visibility="group",
            tags="",
            approval_status="pending",
            approved_by=None,
            approval_timestamp="",
        )
        fid = self.db.add_finding(f)
        self.assertIsNotNone(fid)
        rows = self.db.get_findings("DEFAULT")
        self.assertTrue(any(r.id == fid for r in rows))


if __name__ == "__main__":
    unittest.main()
