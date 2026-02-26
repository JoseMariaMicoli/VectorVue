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

import base64
import json
import os
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from services.telemetry_gateway.main import _clear_replay_cache_for_tests, app
from services.telemetry_gateway.queue import get_memory_messages


class TelemetryGatewaySecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._env_backup = dict(os.environ)
        self.private_key = Ed25519PrivateKey.generate()
        public_key_raw = self.private_key.public_key().public_bytes_raw()
        self.public_key_b64 = base64.b64encode(public_key_raw).decode("utf-8")

        os.environ["VV_TG_SPECTRASTRIKE_CERT_SHA256"] = "a" * 64
        os.environ["VV_TG_SPECTRASTRIKE_ED25519_PUBKEY"] = self.public_key_b64
        os.environ["VV_TG_REQUIRE_MTLS"] = "1"
        os.environ["VV_TG_REQUIRE_PAYLOAD_SIGNATURE"] = "1"
        os.environ["VV_TG_ALLOWED_CLOCK_SKEW_SECONDS"] = "30"
        os.environ["VV_TG_NONCE_TTL_SECONDS"] = "120"
        os.environ["VV_TG_NONCE_BACKEND"] = "memory"
        os.environ["VV_TG_RATE_LIMIT_BACKEND"] = "memory"
        os.environ["VV_TG_RATE_LIMIT_PER_MINUTE"] = "2"
        os.environ["VV_TG_QUEUE_BACKEND"] = "memory"
        os.environ["VV_TG_QUEUE_SUBJECT"] = "vectorvue.telemetry.ingest"
        os.environ["VV_TG_DLQ_SUBJECT"] = "vectorvue.telemetry.dlq"

        _clear_replay_cache_for_tests()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        _clear_replay_cache_for_tests()
        os.environ.clear()
        os.environ.update(self._env_backup)

    def _payload(self, nonce: str, ts: int | None = None) -> dict:
        now = int(time.time()) if ts is None else ts
        return {
            "operator_id": "op-001",
            "campaign_id": "cmp-001",
            "execution_hash": "f" * 64,
            "timestamp": now,
            "nonce": nonce,
            "payload": {
                "event_id": f"evt-{nonce}",
                "event_type": "PROCESS_ANOMALY",
                "source_system": "spectrastrike-sensor",
                "severity": "high",
                "observed_at": "2026-02-26T12:00:00Z",
                "mitre_techniques": ["T1059.001"],
                "mitre_tactics": ["TA0002"],
                "attributes": {"asset_ref": "host-nyc-01"},
            },
        }

    def _signed_headers(self, payload: dict, cert_fp: str = "a" * 64) -> dict[str, str]:
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        msg = f"{payload['timestamp']}.{payload['nonce']}.".encode("utf-8") + raw
        signature = self.private_key.sign(msg)
        return {
            "X-Client-Cert-Sha256": cert_fp,
            "X-Telemetry-Timestamp": str(payload["timestamp"]),
            "X-Telemetry-Nonce": payload["nonce"],
            "X-Telemetry-Signature": base64.b64encode(signature).decode("utf-8"),
            "Content-Type": "application/json",
        }

    def test_rejects_missing_client_cert_header(self):
        payload = self._payload("nonce-001")
        headers = self._signed_headers(payload)
        headers.pop("X-Client-Cert-Sha256")
        res = self.client.post("/internal/v1/telemetry", headers=headers, json=payload)
        self.assertEqual(res.status_code, 401)

    def test_rejects_mismatched_client_cert_fingerprint(self):
        payload = self._payload("nonce-002")
        res = self.client.post(
            "/internal/v1/telemetry",
            headers=self._signed_headers(payload, cert_fp="b" * 64),
            json=payload,
        )
        self.assertEqual(res.status_code, 401)

    def test_rejects_unsigned_payload(self):
        payload = self._payload("nonce-003")
        headers = {
            "X-Client-Cert-Sha256": "a" * 64,
            "X-Telemetry-Timestamp": str(payload["timestamp"]),
            "X-Telemetry-Nonce": payload["nonce"],
            "Content-Type": "application/json",
        }
        res = self.client.post("/internal/v1/telemetry", headers=headers, json=payload)
        self.assertEqual(res.status_code, 401)

    def test_accepts_valid_mtls_pinned_and_signed_payload(self):
        payload = self._payload("nonce-004")
        res = self.client.post("/internal/v1/telemetry", headers=self._signed_headers(payload), json=payload)
        self.assertEqual(res.status_code, 202)
        self.assertTrue(res.json().get("accepted"))
        queued = get_memory_messages("vectorvue.telemetry.ingest")
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0]["kind"], "ingest")
        self.assertEqual(len(queued[0]["integrity_hash"]), 64)

    def test_rejects_replay_nonce(self):
        payload = self._payload("nonce-005")
        headers = self._signed_headers(payload)

        first = self.client.post("/internal/v1/telemetry", headers=headers, json=payload)
        self.assertEqual(first.status_code, 202)

        second = self.client.post("/internal/v1/telemetry", headers=headers, json=payload)
        self.assertEqual(second.status_code, 409)

    def test_rejects_expired_timestamp(self):
        expired_ts = int(time.time()) - 360
        payload = self._payload("nonce-006", ts=expired_ts)
        res = self.client.post("/internal/v1/telemetry", headers=self._signed_headers(payload), json=payload)
        self.assertEqual(res.status_code, 401)

    def test_rejects_forged_signature(self):
        forged_key = Ed25519PrivateKey.generate()
        payload = self._payload("nonce-007")
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        msg = f"{payload['timestamp']}.{payload['nonce']}.".encode("utf-8") + raw
        bad_sig = forged_key.sign(msg)
        headers = {
            "X-Client-Cert-Sha256": "a" * 64,
            "X-Telemetry-Timestamp": str(payload["timestamp"]),
            "X-Telemetry-Nonce": payload["nonce"],
            "X-Telemetry-Signature": base64.b64encode(bad_sig).decode("utf-8"),
            "Content-Type": "application/json",
        }
        res = self.client.post("/internal/v1/telemetry", headers=headers, json=payload)
        self.assertEqual(res.status_code, 401)

    def test_rate_limit_blocks_operator_burst(self):
        first = self._payload("nonce-008")
        second = self._payload("nonce-009")
        third = self._payload("nonce-010")

        r1 = self.client.post("/internal/v1/telemetry", headers=self._signed_headers(first), json=first)
        self.assertEqual(r1.status_code, 202)
        r2 = self.client.post("/internal/v1/telemetry", headers=self._signed_headers(second), json=second)
        self.assertEqual(r2.status_code, 202)
        r3 = self.client.post("/internal/v1/telemetry", headers=self._signed_headers(third), json=third)
        self.assertEqual(r3.status_code, 429)

    def test_malformed_payload_goes_to_dlq(self):
        malformed = {
            "timestamp": int(time.time()),
            "nonce": "nonce-011",
            "payload": {"event_type": "x"},
        }
        res = self.client.post("/internal/v1/telemetry", headers=self._signed_headers(malformed), json=malformed)
        self.assertEqual(res.status_code, 422)
        dlq = get_memory_messages("vectorvue.telemetry.dlq")
        self.assertEqual(len(dlq), 1)
        self.assertEqual(dlq[0]["kind"], "dead_letter")
        self.assertEqual(len(dlq[0]["integrity_hash"]), 64)

    def test_rejects_additional_canonical_properties(self):
        payload = self._payload("nonce-012")
        payload["payload"]["unexpected_field"] = "not-allowed"
        res = self.client.post("/internal/v1/telemetry", headers=self._signed_headers(payload), json=payload)
        self.assertEqual(res.status_code, 422)
        dlq = get_memory_messages("vectorvue.telemetry.dlq")
        self.assertEqual(len(dlq), 1)

    def test_rejects_invalid_mitre_ttp_code(self):
        payload = self._payload("nonce-013")
        payload["payload"]["mitre_techniques"] = ["TX9999"]
        res = self.client.post("/internal/v1/telemetry", headers=self._signed_headers(payload), json=payload)
        self.assertEqual(res.status_code, 422)
        dlq = get_memory_messages("vectorvue.telemetry.dlq")
        self.assertEqual(len(dlq), 1)


if __name__ == "__main__":
    unittest.main()
