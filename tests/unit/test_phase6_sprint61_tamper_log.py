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

import json
import tempfile
import unittest
from pathlib import Path

from security.tamper_log import TamperEvidentAuditLog, TamperLogSettings


class Phase6Sprint61TamperLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="vv_tamper_log_")
        self.log_path = Path(self.tempdir.name) / "audit.jsonl"
        self.log = TamperEvidentAuditLog(TamperLogSettings(log_path=self.log_path, seal_every=2))

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_append_only_hash_chain_verifies(self):
        self.log.append_event(event_type="telemetry.accepted", actor="gateway", details={"request_id": "r1"})
        self.log.append_event(event_type="telemetry.rejected", actor="gateway", details={"request_id": "r2"})
        result = self.log.verify_integrity()
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(result["entries"], 3)  # 2 entries + 1 seal entry

    def test_detects_tampering(self):
        self.log.append_event(event_type="telemetry.accepted", actor="gateway", details={"request_id": "r1"})
        self.log.append_event(event_type="telemetry.rejected", actor="gateway", details={"request_id": "r2"})

        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["details"]["request_id"] = "tampered"
        lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        self.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = self.log.verify_integrity()
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "entry_hash_mismatch")


if __name__ == "__main__":
    unittest.main()
