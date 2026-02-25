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

import unittest

import requests

from tests.qa_cycle.common import ACME_VIEWER, BASE_URL, GLOBEX_VIEWER, auth_headers, login


class TestApiVerificationAndSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.acme_token, _ = login(ACME_VIEWER)
        cls.globex_token, _ = login(GLOBEX_VIEWER)

    def test_openapi_contains_frontend_used_routes(self):
        r = requests.get(f"{BASE_URL}/openapi.json", timeout=20)
        self.assertEqual(r.status_code, 200, r.text[:300])
        paths = set(r.json().get("paths", {}).keys())
        required = {
            "/api/v1/client/auth/login",
            "/api/v1/client/findings",
            "/api/v1/client/findings/{finding_id}",
            "/api/v1/client/reports",
            "/api/v1/client/reports/{report_id}/download",
            "/api/v1/client/risk",
            "/api/v1/client/risk-trend",
            "/api/v1/client/remediation",
            "/api/v1/client/remediation-status",
            "/api/v1/client/theme",
            "/api/v1/client/events",
            "/ml/client/security-score",
            "/ml/client/risk",
            "/ml/client/detection-gaps",
            "/ml/client/anomalies",
            "/ml/client/simulate",
            "/compliance/frameworks",
        }
        missing = sorted(required - paths)
        self.assertFalse(missing, f"missing OpenAPI paths: {missing}")

    def test_auth_is_enforced_for_client_read_routes(self):
        protected = [
            "/api/v1/client/findings",
            "/api/v1/client/risk",
            "/api/v1/client/reports",
            "/api/v1/client/remediation",
            "/api/v1/client/theme",
            "/compliance/frameworks",
        ]
        for path in protected:
            with self.subTest(path=path):
                r = requests.get(f"{BASE_URL}{path}", timeout=10)
                self.assertEqual(r.status_code, 401, f"{path} returned {r.status_code}")

    def test_findings_and_reports_pagination_contract(self):
        h = auth_headers(self.acme_token)
        for path in ["/api/v1/client/findings?page=1&page_size=25", "/api/v1/client/reports?page=1&page_size=25"]:
            with self.subTest(path=path):
                r = requests.get(f"{BASE_URL}{path}", headers=h, timeout=10)
                self.assertEqual(r.status_code, 200, r.text[:200])
                payload = r.json()
                for key in ("items", "page", "page_size", "total"):
                    self.assertIn(key, payload, f"{path} missing pagination key {key}")
                self.assertLessEqual(int(payload["page_size"]), 200)

    def test_tenant_isolation_cross_access_denied(self):
        ha = auth_headers(self.acme_token)
        hg = auth_headers(self.globex_token)
        acme_findings = requests.get(
            f"{BASE_URL}/api/v1/client/findings?page=1&page_size=1", headers=ha, timeout=10
        ).json()["items"]
        globex_findings = requests.get(
            f"{BASE_URL}/api/v1/client/findings?page=1&page_size=1", headers=hg, timeout=10
        ).json()["items"]
        self.assertTrue(acme_findings and globex_findings)
        globex_id = globex_findings[0]["id"]
        cross = requests.get(f"{BASE_URL}/api/v1/client/findings/{globex_id}", headers=ha, timeout=10)
        self.assertEqual(cross.status_code, 404, cross.text[:200])

    def test_invalid_token_rejected(self):
        r = requests.get(
            f"{BASE_URL}/api/v1/client/findings",
            headers={"Authorization": "Bearer invalid.token.value"},
            timeout=10,
        )
        self.assertEqual(r.status_code, 401, r.text[:200])


if __name__ == "__main__":
    unittest.main()

