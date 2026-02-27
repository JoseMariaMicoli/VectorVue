# Copyright (c) 2026 NyxeraLabs
# Author: Jose Maria Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-22 -> Apache-2.0

from __future__ import annotations

import base64
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from security.tamper_log import TamperEvidentAuditLog, TamperLogSettings

try:
    from fastapi.testclient import TestClient
    from services.telemetry_gateway.main import _clear_replay_cache_for_tests, app
    from services.telemetry_gateway.queue import get_memory_messages

    HAS_GATEWAY_DEPS = True
except ModuleNotFoundError:
    HAS_GATEWAY_DEPS = False


@unittest.skipUnless(HAS_GATEWAY_DEPS, "phase 9 red-team suite requires fastapi and telemetry gateway dependencies")
class Phase9Sprint91GatewayAttackSimulationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._env_backup = dict(os.environ)
        self.private_key = Ed25519PrivateKey.generate()
        self.feedback_private_key = Ed25519PrivateKey.generate()
        self.cert_fp = "a" * 64
        self.public_key_b64 = base64.b64encode(self.private_key.public_key().public_bytes_raw()).decode("utf-8")

        os.environ["VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON"] = (
            '{"spectrastrike-producer":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
        )
        os.environ["VV_TG_SPECTRASTRIKE_ED25519_PUBKEY"] = self.public_key_b64
        os.environ["VV_TG_REQUIRE_MTLS"] = "1"
        os.environ["VV_TG_REQUIRE_PAYLOAD_SIGNATURE"] = "1"
        os.environ["VV_TG_FEEDBACK_ACTIVE_KID"] = "kid-001"
        with open("/tmp/vv_feedback_ed25519_phase9.key", "wb") as f:
            f.write(self.feedback_private_key.private_bytes_raw())
        os.environ["VV_TG_FEEDBACK_ED25519_KEYS_JSON"] = '{"kid-001":"/tmp/vv_feedback_ed25519_phase9.key"}'
        os.environ["VV_TG_ALLOWED_CLOCK_SKEW_SECONDS"] = "30"
        os.environ["VV_TG_NONCE_TTL_SECONDS"] = "120"
        os.environ["VV_TG_NONCE_BACKEND"] = "memory"
        os.environ["VV_TG_RATE_LIMIT_BACKEND"] = "memory"
        os.environ["VV_TG_RATE_LIMIT_PER_MINUTE"] = "2"
        os.environ["VV_TG_QUEUE_BACKEND"] = "memory"
        os.environ["VV_TG_QUEUE_SUBJECT"] = "vectorvue.telemetry.ingest"
        os.environ["VV_TG_DLQ_SUBJECT"] = "vectorvue.telemetry.dlq"
        os.environ["VV_TG_OPERATOR_TENANT_MAP"] = '{"op-001":"10000000-0000-0000-0000-000000000001"}'
        os.environ["VV_SERVICE_IDENTITY_CERT_PATH"] = "/tmp/vv_identity_server.crt"
        os.environ["VV_SERVICE_IDENTITY_KEY_PATH"] = "/tmp/vv_identity_server.key"
        os.environ["VV_SERVICE_IDENTITY_CA_PATH"] = "/tmp/vv_identity_ca.crt"
        for path in (
            "/tmp/vv_identity_server.crt",
            "/tmp/vv_identity_server.key",
            "/tmp/vv_identity_ca.crt",
        ):
            with open(path, "w", encoding="utf-8") as f:
                f.write("test-cert")

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
            "tenant_id": "10000000-0000-0000-0000-000000000001",
            "execution_hash": "f" * 64,
            "timestamp": now,
            "nonce": nonce,
            "signed_metadata": {
                "tenant_id": "10000000-0000-0000-0000-000000000001",
                "operator_id": "op-001",
                "campaign_id": "cmp-001",
            },
            "payload": {
                "event_id": f"evt-{nonce}",
                "event_type": "PROCESS_ANOMALY",
                "source_system": "spectrastrike-sensor",
                "severity": "high",
                "observed_at": "2026-02-26T12:00:00Z",
                "mitre_techniques": ["T1059.001"],
                "mitre_tactics": ["TA0002"],
                "description": "Observed suspicious process chain",
                "attributes": {
                    "asset_ref": "host-nyc-01",
                    "schema_version": "1.0",
                    "attestation_measurement_hash": "b" * 64,
                },
            },
        }

    def _signed_headers(self, payload: dict, cert_fp: str | None = None, sign_with: Ed25519PrivateKey | None = None) -> dict[str, str]:
        key = sign_with or self.private_key
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        msg = f"{payload['timestamp']}.{payload['nonce']}.".encode("utf-8") + raw
        signature = key.sign(msg)
        return {
            "X-Service-Identity": "spectrastrike-producer",
            "X-Client-Cert-Sha256": cert_fp or self.cert_fp,
            "X-Telemetry-Timestamp": str(payload["timestamp"]),
            "X-Telemetry-Nonce": payload["nonce"],
            "X-Telemetry-Signature": base64.b64encode(signature).decode("utf-8"),
            "Content-Type": "application/json",
        }

    def test_replay_attack_is_rejected(self) -> None:
        payload = self._payload("phase9-nonce-001")
        headers = self._signed_headers(payload)
        first = self.client.post("/internal/v1/telemetry", headers=headers, json=payload)
        second = self.client.post("/internal/v1/telemetry", headers=headers, json=payload)
        self.assertEqual(first.status_code, 202)
        self.assertEqual(second.status_code, 409)

    def test_signature_forgery_is_rejected(self) -> None:
        forged = Ed25519PrivateKey.generate()
        payload = self._payload("phase9-nonce-002")
        res = self.client.post(
            "/internal/v1/telemetry",
            headers=self._signed_headers(payload, sign_with=forged),
            json=payload,
        )
        self.assertEqual(res.status_code, 401)

    def test_mitm_fingerprint_mismatch_is_rejected(self) -> None:
        payload = self._payload("phase9-nonce-003")
        res = self.client.post(
            "/internal/v1/telemetry",
            headers=self._signed_headers(payload, cert_fp="b" * 64),
            json=payload,
        )
        self.assertEqual(res.status_code, 401)

    def test_cross_tenant_access_attempt_is_rejected(self) -> None:
        payload = self._payload("phase9-nonce-004")
        payload["tenant_id"] = "20000000-0000-0000-0000-000000000002"
        payload["signed_metadata"]["tenant_id"] = payload["tenant_id"]
        res = self.client.post("/internal/v1/telemetry", headers=self._signed_headers(payload), json=payload)
        self.assertEqual(res.status_code, 403)

    def test_log_tampering_is_detected(self) -> None:
        # Kept here for full suite parity when gateway deps are available.
        with tempfile.TemporaryDirectory(prefix="vv_phase9_tamper_") as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            log = TamperEvidentAuditLog(TamperLogSettings(log_path=log_path, seal_every=10))
            log.append_event(event_type="telemetry.accepted", actor="gateway", details={"request_id": "r1"})
            log.append_event(event_type="telemetry.rejected", actor="gateway", details={"request_id": "r2"})

            rows = log_path.read_text(encoding="utf-8").splitlines()
            record = json.loads(rows[1])
            record["details"]["request_id"] = "modified-by-attacker"
            rows[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
            log_path.write_text("\n".join(rows) + "\n", encoding="utf-8")

            verify = log.verify_integrity()
            self.assertFalse(verify["ok"])
            self.assertEqual(verify["reason"], "entry_hash_mismatch")

    def test_queue_poisoning_attempt_is_sent_to_dlq(self) -> None:
        malformed = {
            "timestamp": int(time.time()),
            "nonce": "phase9-nonce-005",
            "payload": {"event_type": "x"},
        }
        res = self.client.post(
            "/internal/v1/telemetry",
            headers=self._signed_headers(malformed),
            json=malformed,
        )
        self.assertEqual(res.status_code, 422)
        dlq = get_memory_messages("vectorvue.telemetry.dlq")
        self.assertEqual(len(dlq), 1)
        self.assertEqual(dlq[0]["kind"], "dead_letter")

    def test_rate_limit_exhaustion_is_rejected(self) -> None:
        p1 = self._payload("phase9-nonce-006")
        p2 = self._payload("phase9-nonce-007")
        p3 = self._payload("phase9-nonce-008")
        r1 = self.client.post("/internal/v1/telemetry", headers=self._signed_headers(p1), json=p1)
        r2 = self.client.post("/internal/v1/telemetry", headers=self._signed_headers(p2), json=p2)
        r3 = self.client.post("/internal/v1/telemetry", headers=self._signed_headers(p3), json=p3)
        self.assertEqual(r1.status_code, 202)
        self.assertEqual(r2.status_code, 202)
        self.assertEqual(r3.status_code, 429)


class Phase9Sprint91TamperLogSimulationTests(unittest.TestCase):
    def test_log_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vv_phase9_tamper_") as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            log = TamperEvidentAuditLog(TamperLogSettings(log_path=log_path, seal_every=10))
            log.append_event(event_type="telemetry.accepted", actor="gateway", details={"request_id": "r1"})
            log.append_event(event_type="telemetry.rejected", actor="gateway", details={"request_id": "r2"})

            rows = log_path.read_text(encoding="utf-8").splitlines()
            record = json.loads(rows[1])
            record["details"]["request_id"] = "modified-by-attacker"
            rows[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
            log_path.write_text("\n".join(rows) + "\n", encoding="utf-8")

            verify = log.verify_integrity()
            self.assertFalse(verify["ok"])
            self.assertEqual(verify["reason"], "entry_hash_mismatch")


if __name__ == "__main__":
    unittest.main()
