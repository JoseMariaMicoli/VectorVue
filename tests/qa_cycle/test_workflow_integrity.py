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

from __future__ import annotations

import concurrent.futures
import json
import time
import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import psycopg
import requests

from tests.qa_cycle.common import ACME_LEAD, ACME_VIEWER, BASE_URL, PG_URL, auth_headers, login


class TestWorkflowIntegrityAndPerformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.viewer_token, _ = login(ACME_VIEWER)
        cls.lead_token, _ = login(ACME_LEAD)
        cls.viewer_headers = auth_headers(cls.viewer_token)
        cls.lead_headers = auth_headers(cls.lead_token)
        cls.tenant_id = ACME_VIEWER.tenant_id

    def test_event_ingestion_and_db_persistence(self):
        with psycopg.connect(PG_URL) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM client_activity_events WHERE tenant_id=%s",
                (self.tenant_id,),
            )
            before = int(cur.fetchone()[0])

        payload = {
            "event_type": "DASHBOARD_VIEWED",
            "object_type": "dashboard",
            "object_id": "qa-overview",
            "metadata_json": {"screen": "overview", "ip": "should_be_filtered"},
        }
        r = requests.post(
            f"{BASE_URL}/api/v1/client/events",
            headers=self.viewer_headers,
            json=payload,
            timeout=10,
        )
        self.assertEqual(r.status_code, 202, r.text[:200])
        time.sleep(0.7)

        with psycopg.connect(PG_URL) as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT COUNT(*), metadata_json
                   FROM client_activity_events
                   WHERE tenant_id=%s
                   GROUP BY metadata_json
                   ORDER BY COUNT(*) DESC
                   LIMIT 1""",
                (self.tenant_id,),
            )
            row = cur.fetchone()
            self.assertIsNotNone(row)
            cur.execute(
                "SELECT COUNT(*) FROM client_activity_events WHERE tenant_id=%s",
                (self.tenant_id,),
            )
            after = int(cur.fetchone()[0])
        self.assertGreaterEqual(after, before + 1, "event insert did not persist")

    def test_workflow_no_orphan_remediation_records(self):
        with psycopg.connect(PG_URL) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM remediation_tasks rt
                LEFT JOIN findings f ON f.id = rt.finding_id AND f.tenant_id = rt.tenant_id
                WHERE rt.tenant_id = %s
                  AND rt.finding_id IS NOT NULL
                  AND f.id IS NULL
                """,
                (self.tenant_id,),
            )
            orphan_count = int(cur.fetchone()[0])
        self.assertEqual(orphan_count, 0, f"orphan remediation rows found: {orphan_count}")

    def test_compliance_report_and_audit_download(self):
        report = requests.get(
            f"{BASE_URL}/compliance/ISO27001/report",
            headers=self.lead_headers,
            timeout=20,
        )
        self.assertEqual(report.status_code, 200, report.text[:200])
        wrapped = report.json()
        self.assertIn("data", wrapped)
        self.assertIn("signature", wrapped)
        self.assertIn("dataset_hash", wrapped["data"])

        sess = requests.post(
            f"{BASE_URL}/audit/session",
            headers=self.lead_headers,
            json={"ttl_minutes": 30},
            timeout=20,
        )
        self.assertEqual(sess.status_code, 200, sess.text[:200])
        audit_token = sess.json()["token"]
        d = requests.get(
            f"{BASE_URL}/compliance/ISO27001/report/download?tenant_id={self.tenant_id}&days=30",
            headers={"Authorization": f"Bearer {audit_token}"},
            timeout=25,
        )
        self.assertEqual(d.status_code, 200, d.text[:200])
        self.assertEqual(d.headers.get("content-type"), "application/zip")
        self.assertTrue(d.headers.get("X-VectorVue-Dataset-Hash"))

    def test_expired_session_rejected(self):
        import jwt

        # Build a short-lived invalid token with expired exp and known signing key.
        secret = "vectorvue-client-secret"
        claims = {
            "sub": "qa-expired",
            "tenant_id": self.tenant_id,
            "role": "viewer",
            "iat": int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp()),
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),
        }
        token = jwt.encode(claims, secret, algorithm="HS256")
        r = requests.get(
            f"{BASE_URL}/api/v1/client/findings",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        self.assertEqual(r.status_code, 401, r.text[:200])

    def test_data_integrity_compliance_hash_chain(self):
        with psycopg.connect(PG_URL) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, previous_event_hash, chain_hash
                FROM compliance_events
                WHERE tenant_id=%s AND framework='ISO27001'
                ORDER BY created_at ASC
                LIMIT 200
                """,
                (self.tenant_id,),
            )
            rows = cur.fetchall()
        # No rows is acceptable in fresh tenants; if rows exist, chain refs must be populated.
        for i, (_id, prev_hash, chain_hash) in enumerate(rows):
            self.assertTrue(chain_hash, f"chain_hash missing for row index {i}")
            if i > 0:
                self.assertTrue(prev_hash, f"previous_event_hash missing at chain index {i}")

    def test_snapshot_reproducibility_same_window(self):
        r1 = requests.get(
            f"{BASE_URL}/compliance/ISO27001/report?days=30",
            headers=self.lead_headers,
            timeout=20,
        )
        r2 = requests.get(
            f"{BASE_URL}/compliance/ISO27001/report?days=30",
            headers=self.lead_headers,
            timeout=20,
        )
        self.assertEqual(r1.status_code, 200, r1.text[:200])
        self.assertEqual(r2.status_code, 200, r2.text[:200])
        h1 = r1.json()["data"]["dataset_hash"]
        h2 = r2.json()["data"]["dataset_hash"]
        self.assertEqual(h1, h2, "dataset hash changed for same tenant/framework/window")

    def test_timestamp_consistency_no_future_drift(self):
        with psycopg.connect(PG_URL) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM client_activity_events
                WHERE tenant_id=%s
                  AND timestamp > (NOW() + INTERVAL '5 minutes')
                """,
                (self.tenant_id,),
            )
            future_events = int(cur.fetchone()[0])
        self.assertEqual(future_events, 0, f"future-dated client_activity_events found: {future_events}")

    def test_performance_simulate_10k_events_and_parallel_exports(self):
        # Bulk append to analytics.events for 10k-row performance scenario.
        tenant_ids = [
            "10000000-0000-0000-0000-000000000001",
            "20000000-0000-0000-0000-000000000002",
        ]
        now = datetime.now(timezone.utc)
        batch = []
        for i in range(10_000):
            tid = tenant_ids[i % 2]
            batch.append(
                (
                    str(uuid4()),
                    tid,
                    "FINDING_VIEWED",
                    "finding",
                    str((i % 500) + 1),
                    now,
                    json.dumps({"source": "qa_perf", "n": i}),
                    now,
                )
            )
        with psycopg.connect(PG_URL) as conn, conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO analytics.events
                (id, tenant_id, event_type, entity_type, entity_id, timestamp, payload, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                """,
                batch,
            )
            conn.commit()

        def _download_once() -> int:
            sess = requests.post(
                f"{BASE_URL}/audit/session",
                headers=self.lead_headers,
                json={"ttl_minutes": 15},
                timeout=20,
            )
            if sess.status_code != 200:
                return sess.status_code
            tok = sess.json()["token"]
            d = requests.get(
                f"{BASE_URL}/compliance/ISO27001/report/download?tenant_id={self.tenant_id}&days=30",
                headers={"Authorization": f"Bearer {tok}"},
                timeout=30,
            )
            return d.status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            codes = list(ex.map(lambda _: _download_once(), range(4)))
        self.assertTrue(all(c == 200 for c in codes), f"parallel exports failed: {codes}")


if __name__ == "__main__":
    unittest.main()
