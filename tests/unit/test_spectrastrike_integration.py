from __future__ import annotations

import os
import unittest
import json
import base64
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.client_api.spectrastrike_router import get_spectrastrike_service
from app.client_api.spectrastrike_schemas import SpectraStrikeBatchItemResult
from vv_client_api import app


TENANT_A = "10000000-0000-0000-0000-000000000001"
TENANT_B = "20000000-0000-0000-0000-000000000002"


class FakeSpectraStrikeService:
    def __init__(self):
        self.idempotency: dict[tuple[str, str, str], dict] = {}
        self.statuses: dict[tuple[str, str], dict] = {}
        self.audit_events: list[dict] = []
        self.events: list[dict] = []
        self.findings: list[dict] = []

    def fetch_idempotent_response(self, *, tenant_id: str, endpoint: str, idempotency_key: str):
        return self.idempotency.get((tenant_id, endpoint, idempotency_key))

    def store_idempotent_response(
        self,
        *,
        tenant_id: str,
        endpoint: str,
        idempotency_key: str,
        request_hash: str,
        response_json: dict,
        status_code: int,
    ):
        self.idempotency[(tenant_id, endpoint, idempotency_key)] = {
            "request_hash": request_hash,
            "response_json": response_json,
            "status_code": status_code,
        }

    def record_event(self, *, tenant_id: str, request_id: str, event_uid: str, payload: dict):
        self.events.append({"tenant_id": tenant_id, "request_id": request_id, "event_uid": event_uid, "payload": payload})

    def record_finding(self, *, tenant_id: str, request_id: str, finding_uid: str, payload: dict):
        self.findings.append(
            {"tenant_id": tenant_id, "request_id": request_id, "finding_uid": finding_uid, "payload": payload}
        )

    def record_ingest_status(
        self,
        *,
        request_id: str,
        tenant_id: str,
        endpoint: str,
        status: str,
        total_items: int,
        accepted_items: int,
        failed_items: int,
        failed_references: list[SpectraStrikeBatchItemResult],
        idempotency_key: str | None,
    ):
        now = datetime.now(timezone.utc)
        self.statuses[(request_id, tenant_id)] = {
            "request_id": request_id,
            "endpoint": endpoint,
            "status": status,
            "total_items": total_items,
            "accepted_items": accepted_items,
            "failed_items": failed_items,
            "failed_references": [item.model_dump() for item in failed_references],
            "created_at": now,
            "updated_at": now,
            "idempotency_key": idempotency_key,
        }

    def get_ingest_status(self, *, request_id: str, tenant_id: str):
        return self.statuses.get((request_id, tenant_id))

    def write_audit_event(
        self,
        *,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        old_value_hash: str = "",
        new_value_hash: str = "",
    ):
        self.audit_events.append(
            {
                "actor": actor,
                "action": action,
                "target_type": target_type,
                "target_id": target_id,
                "old_value_hash": old_value_hash,
                "new_value_hash": new_value_hash,
            }
        )


class SpectraStrikeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["VV_CLIENT_JWT_SECRET"] = ""
        os.environ["VV_CLIENT_JWT_ALLOW_UNSIGNED"] = "1"

    def setUp(self):
        self.fake_service = FakeSpectraStrikeService()
        app.dependency_overrides[get_spectrastrike_service] = lambda: self.fake_service
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()

    def _token(self, tenant_id: str | None) -> str:
        payload = {
            "sub": "integration-bot",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(datetime.now(timezone.utc).timestamp()) + 3600,
        }
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        header = {"alg": "none", "typ": "JWT"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).decode("utf-8").rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
        return f"{header_b64}.{payload_b64}."

    def _headers(self, tenant_id: str | None = TENANT_A, **extra) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token(tenant_id)}", **extra}

    def _event_payload(self) -> dict:
        return {
            "source_system": "spectrastrike-sensor",
            "event_type": "PROCESS_ANOMALY",
            "occurred_at": "2026-02-22T10:00:00Z",
            "severity": "high",
            "asset_ref": "host-nyc-01",
            "message": "Unexpected parent-child process chain",
        }

    def _finding_payload(self) -> dict:
        return {
            "title": "Suspicious PowerShell Script",
            "description": "Encoded command observed in endpoint telemetry",
            "severity": "critical",
            "status": "open",
            "first_seen": "2026-02-22T09:45:00Z",
            "asset_ref": "host-nyc-01",
        }

    def test_auth_required_and_tenant_claim_required(self):
        unauth = self.client.post("/api/v1/integrations/spectrastrike/events", json=self._event_payload())
        self.assertEqual(unauth.status_code, 401)

        no_tenant = self.client.post(
            "/api/v1/integrations/spectrastrike/events",
            headers=self._headers(None),
            json=self._event_payload(),
        )
        self.assertEqual(no_tenant.status_code, 401)

    def test_cross_tenant_access_blocked_for_status(self):
        created = self.client.post(
            "/api/v1/integrations/spectrastrike/events",
            headers=self._headers(TENANT_A),
            json=self._event_payload(),
        )
        self.assertEqual(created.status_code, 202)
        request_id = created.json()["request_id"]

        cross = self.client.get(
            f"/api/v1/integrations/spectrastrike/ingest/status/{request_id}",
            headers=self._headers(TENANT_B),
        )
        self.assertEqual(cross.status_code, 404)

    def test_single_ingest_success_event_and_finding(self):
        event_res = self.client.post(
            "/api/v1/integrations/spectrastrike/events",
            headers=self._headers(TENANT_A),
            json=self._event_payload(),
        )
        self.assertEqual(event_res.status_code, 202)
        self.assertEqual(event_res.json()["status"], "accepted")
        self.assertTrue(event_res.json()["data"]["event_id"])

        finding_res = self.client.post(
            "/api/v1/integrations/spectrastrike/findings",
            headers=self._headers(TENANT_A),
            json=self._finding_payload(),
        )
        self.assertEqual(finding_res.status_code, 202)
        self.assertEqual(finding_res.json()["status"], "accepted")
        self.assertTrue(finding_res.json()["data"]["finding_id"])

    def test_batch_partial_failure_semantics(self):
        payload = [self._event_payload(), {"event_type": "MISSING_FIELDS"}]
        res = self.client.post(
            "/api/v1/integrations/spectrastrike/events/batch",
            headers=self._headers(TENANT_A),
            json=payload,
        )
        self.assertEqual(res.status_code, 202)
        body = res.json()
        self.assertEqual(body["status"], "partial")
        self.assertEqual(body["data"]["summary"], {"total": 2, "accepted": 1, "failed": 1})
        self.assertEqual(body["data"]["results"][1]["status"], "failed")

    def test_idempotency_replay_behavior(self):
        headers = self._headers(TENANT_A, **{"Idempotency-Key": "idem-001"})
        first = self.client.post(
            "/api/v1/integrations/spectrastrike/events",
            headers=headers,
            json=self._event_payload(),
        )
        self.assertEqual(first.status_code, 202)

        second = self.client.post(
            "/api/v1/integrations/spectrastrike/events",
            headers=headers,
            json=self._event_payload(),
        )
        self.assertEqual(second.status_code, 202)
        self.assertEqual(second.headers.get("X-Idempotent-Replay"), "true")
        self.assertEqual(first.json(), second.json())

    def test_status_endpoint_for_accepted_partial_failed(self):
        accepted = self.client.post(
            "/api/v1/integrations/spectrastrike/events",
            headers=self._headers(TENANT_A),
            json=self._event_payload(),
        ).json()["request_id"]

        partial = self.client.post(
            "/api/v1/integrations/spectrastrike/findings/batch",
            headers=self._headers(TENANT_A),
            json=[self._finding_payload(), {"title": "bad"}],
        ).json()["request_id"]

        failed = self.client.post(
            "/api/v1/integrations/spectrastrike/events/batch",
            headers=self._headers(TENANT_A),
            json=[{"source_system": "x"}, {"source_system": "y"}],
        ).json()["request_id"]

        for rid, expected in [(accepted, "accepted"), (partial, "partial"), (failed, "failed")]:
            res = self.client.get(f"/api/v1/integrations/spectrastrike/ingest/status/{rid}", headers=self._headers(TENANT_A))
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()["data"]["status"], expected)

    def test_validation_failure_returns_expected_error_envelope(self):
        invalid = self.client.post(
            "/api/v1/integrations/spectrastrike/findings",
            headers=self._headers(TENANT_A),
            json={"title": "x"},
        )
        self.assertEqual(invalid.status_code, 422)
        body = invalid.json()
        self.assertEqual(body["status"], "failed")
        self.assertEqual(body["errors"][0]["code"], "validation_failed")

    def test_audit_log_hook_called_for_key_operations(self):
        self.client.post(
            "/api/v1/integrations/spectrastrike/events",
            headers=self._headers(TENANT_A),
            json=self._event_payload(),
        )
        self.client.post(
            "/api/v1/integrations/spectrastrike/events/batch",
            headers=self._headers(TENANT_A),
            json=[self._event_payload(), {"source_system": "bad"}],
        )
        self.client.post(
            "/api/v1/integrations/spectrastrike/findings",
            headers=self._headers(TENANT_A),
            json={"title": "bad"},
        )

        actions = {entry["action"] for entry in self.fake_service.audit_events}
        self.assertIn("SPECTRASTRIKE_INGEST_ACCEPTED", actions)
        self.assertIn("SPECTRASTRIKE_BATCH_PARTIAL_FAILURE", actions)
        self.assertIn("SPECTRASTRIKE_SCHEMA_REJECTED", actions)


if __name__ == "__main__":
    unittest.main()
