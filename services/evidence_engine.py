from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import text

from analytics.db import session_scope


def _signing_key() -> str:
    return os.environ.get("VV_COMPLIANCE_SIGNING_KEY", os.environ.get("VV_AUTH_SECRET", "vectorvue-compliance-dev-key"))


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _hmac(raw: str) -> str:
    return hmac.new(_signing_key().encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()


def append_compliance_event(
    tenant_id: str,
    framework: str,
    control_id: int,
    status: str,
    payload: dict[str, Any],
    retention_days: int = 365 * 3,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    payload_json = _canonical_json(payload)
    dataset_hash = _sha256(payload_json)

    with session_scope() as db:
        prev = db.execute(
            text(
                """SELECT chain_hash
                   FROM compliance_events
                   WHERE tenant_id=:tenant_id AND framework=:framework
                   ORDER BY created_at DESC
                   LIMIT 1"""
            ),
            {"tenant_id": tenant_id, "framework": framework},
        ).mappings().first()
        previous_event_hash = str(prev["chain_hash"]) if prev else ""
        evidence_hash = _sha256(f"{tenant_id}|{framework}|{control_id}|{status}|{dataset_hash}")
        chain_hash = _sha256(f"{previous_event_hash}|{evidence_hash}|{dataset_hash}|{now.isoformat()}")
        timestamp_signature = _hmac(f"{tenant_id}|{framework}|{control_id}|{status}|{now.isoformat()}")

        event_id = str(uuid.uuid4())
        db.execute(
            text(
                """INSERT INTO compliance_events
                   (id, tenant_id, framework, control_id, status, evidence_hash, dataset_hash, timestamp_signature,
                    previous_event_hash, chain_hash, payload_json, retention_until, created_at)
                   VALUES (:id, :tenant_id, :framework, :control_id, :status, :evidence_hash, :dataset_hash,
                           :timestamp_signature, :previous_event_hash, :chain_hash, CAST(:payload_json AS JSONB),
                           :retention_until, :created_at)"""
            ),
            {
                "id": event_id,
                "tenant_id": tenant_id,
                "framework": framework,
                "control_id": control_id,
                "status": status,
                "evidence_hash": evidence_hash,
                "dataset_hash": dataset_hash,
                "timestamp_signature": timestamp_signature,
                "previous_event_hash": previous_event_hash or None,
                "chain_hash": chain_hash,
                "payload_json": payload_json,
                "retention_until": now + timedelta(days=max(30, retention_days)),
                "created_at": now,
            },
        )
    return {
        "id": event_id,
        "evidence_hash": evidence_hash,
        "dataset_hash": dataset_hash,
        "timestamp_signature": timestamp_signature,
        "previous_event_hash": previous_event_hash,
        "chain_hash": chain_hash,
        "created_at": now.isoformat() + "Z",
    }


def verify_framework_chain(tenant_id: str, framework: str) -> dict[str, Any]:
    with session_scope() as db:
        rows = db.execute(
            text(
                """SELECT id, control_id, status, evidence_hash, dataset_hash, timestamp_signature,
                          previous_event_hash, chain_hash, created_at
                   FROM compliance_events
                   WHERE tenant_id=:tenant_id AND framework=:framework
                   ORDER BY created_at ASC"""
            ),
            {"tenant_id": tenant_id, "framework": framework},
        ).mappings().all()

    prev = ""
    broken_at = None
    for r in rows:
        expected = _sha256(f"{prev}|{r['evidence_hash']}|{r['dataset_hash']}|{r['created_at'].isoformat()}")
        if expected != str(r["chain_hash"]):
            broken_at = str(r["id"])
            break
        prev = str(r["chain_hash"])
    return {"ok": broken_at is None, "events": len(rows), "broken_at": broken_at}


def build_audit_package(tenant_id: str, framework: str, start_ts: datetime, end_ts: datetime) -> dict[str, Any]:
    with session_scope() as db:
        controls = [
            dict(r)
            for r in db.execute(
                text(
                    """SELECT c.id, c.code, c.title, cm.requirement_ref
                       FROM frameworks f
                       JOIN control_mappings cm ON cm.framework_id=f.id
                       JOIN controls c ON c.id=cm.control_id
                       WHERE f.code=:framework
                       ORDER BY c.code"""
                ),
                {"framework": framework},
            ).mappings().all()
        ]
        events = [
            dict(r)
            for r in db.execute(
                text(
                    """SELECT id, control_id, status, evidence_hash, dataset_hash, timestamp_signature,
                              previous_event_hash, chain_hash, payload_json, created_at
                       FROM compliance_events
                       WHERE tenant_id=:tenant_id
                         AND framework=:framework
                         AND created_at BETWEEN :start_ts AND :end_ts
                       ORDER BY created_at ASC"""
                ),
                {"tenant_id": tenant_id, "framework": framework, "start_ts": start_ts, "end_ts": end_ts},
            ).mappings().all()
        ]
        latest_score = db.execute(
            text(
                """SELECT framework, score, coverage_percent, calculated_at, details_json
                   FROM compliance_scores
                   WHERE tenant_id=:tenant_id AND framework=:framework
                   ORDER BY calculated_at DESC
                   LIMIT 1"""
            ),
            {"tenant_id": tenant_id, "framework": framework},
        ).mappings().first()

    metadata = {
        "tenant_id": tenant_id,
        "framework": framework,
        "window_start": start_ts.isoformat(),
        "window_end": end_ts.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events_count": len(events),
        "controls_count": len(controls),
        "latest_score": dict(latest_score) if latest_score else None,
        "chain_verification": verify_framework_chain(tenant_id, framework),
    }
    controls_json = _canonical_json(controls)
    events_json = _canonical_json(events)
    metadata_json = _canonical_json(metadata)
    # Keep dataset hash reproducible across repeated exports when underlying data is unchanged.
    # Use only exported data rows (controls + events), excluding volatile metadata/window timestamps.
    dataset_hash = _sha256(_canonical_json({"controls": controls, "events": events}))

    base_dir = Path(os.environ.get("VV_COMPLIANCE_EXPORT_DIR", "/tmp/vectorvue_compliance_exports"))
    base_dir.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix="audit_pkg_", dir=str(base_dir)))
    (temp_dir / "controls.json").write_text(controls_json, encoding="utf-8")
    (temp_dir / "evidence.json").write_text(events_json, encoding="utf-8")
    (temp_dir / "metadata.json").write_text(metadata_json, encoding="utf-8")

    checksums = {
        "controls.json": _sha256(controls_json),
        "evidence.json": _sha256(events_json),
        "metadata.json": _sha256(metadata_json),
        "dataset_hash": dataset_hash,
    }
    checksums_txt = "\n".join([f"{k}={v}" for k, v in checksums.items()]) + "\n"
    (temp_dir / "checksums.txt").write_text(checksums_txt, encoding="utf-8")
    signature_text = _hmac(checksums_txt)
    (temp_dir / "signature.txt").write_text(signature_text, encoding="utf-8")

    # Include microseconds + random suffix to avoid concurrent writers clobbering the same ZIP path.
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    zip_path = base_dir / f"audit_{tenant_id}_{framework}_{ts}_{uuid.uuid4().hex[:8]}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(temp_dir / "controls.json", arcname="controls.json")
        zf.write(temp_dir / "evidence.json", arcname="evidence.json")
        zf.write(temp_dir / "metadata.json", arcname="metadata.json")
        zf.write(temp_dir / "checksums.txt", arcname="checksums.txt")
        zf.write(temp_dir / "signature.txt", arcname="signature.txt")

    return {
        "zip_path": str(zip_path),
        "dataset_hash": dataset_hash,
        "signature": signature_text,
        "checksums": checksums,
        "events_count": len(events),
        "controls_count": len(controls),
    }
