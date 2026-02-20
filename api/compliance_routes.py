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

import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import text

from analytics.db import session_scope
from models.compliance_models import (
    AuditSessionRequest,
    AuditSessionResponse,
    AuditWindowOut,
    ControlStateItem,
    FrameworkItem,
    FrameworkReportOut,
    FrameworkScoreOut,
    now_iso,
)
from security.tenant_auth import get_current_tenant
from services.compliance_scoring import compute_continuous_compliance_score
from services.evidence_engine import build_audit_package
from services.framework_mapper import ensure_framework_catalog, list_framework_controls, list_frameworks_with_latest_scores


def _auth_secret() -> str:
    # Keep compliance routes aligned with existing tenant JWT verification.
    return os.environ.get("VV_CLIENT_JWT_SECRET", os.environ.get("VV_AUTH_SECRET", "vectorvue-client-secret"))


def _signing_key() -> str:
    return os.environ.get("VV_COMPLIANCE_SIGNING_KEY", _auth_secret())


def _canon(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def _sign_payload(path: str, tenant_id: str, data: Any) -> dict[str, str]:
    signed_at = now_iso()
    raw = f"{path}|{tenant_id}|{signed_at}|{_canon(data)}"
    signature = hmac.new(_signing_key().encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "algorithm": "HMAC-SHA256",
        "key_id": "vv-compliance-v1",
        "signed_at": signed_at,
        "signature": signature,
    }


def _signed_response(path: str, tenant_id: str, data: Any) -> dict[str, Any]:
    return {"data": data, "signature": _sign_payload(path=path, tenant_id=tenant_id, data=data)}


def _extract_auth_role(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    try:
        claims = jwt.decode(token, _auth_secret(), algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    return str(claims.get("role", "viewer")).strip().lower()


def _require_auditor_role(request: Request) -> str:
    role = _extract_auth_role(request)
    if role not in {"auditor", "admin", "lead"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Auditor role required")
    return role


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _extract_bearer_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    return auth.split(" ", 1)[1].strip()


def _validate_audit_token(token: str, tenant_id: str) -> None:
    now = datetime.now(timezone.utc)
    with session_scope() as db:
        row = db.execute(
            text(
                """SELECT id
                   FROM audit_sessions
                   WHERE tenant_id=:tenant_id
                     AND token_hash=:token_hash
                     AND expires_at > :now
                   LIMIT 1"""
            ),
            {"tenant_id": tenant_id, "token_hash": _hash_token(token), "now": now},
        ).mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired audit session")


def _save_audit_session(tenant_id: str, username: str, role: str, token: str, expires_at: datetime) -> None:
    with session_scope() as db:
        db.execute(
            text(
                """INSERT INTO audit_sessions (id, tenant_id, username, role, token_hash, expires_at, created_at)
                   VALUES (:id, :tenant_id, :username, :role, :token_hash, :expires_at, :created_at)"""
            ),
            {
                "id": str(uuid.uuid4()),
                "tenant_id": tenant_id,
                "username": username,
                "role": role,
                "token_hash": _hash_token(token),
                "expires_at": expires_at,
                "created_at": datetime.now(timezone.utc),
            },
        )


def _resolve_latest_score(tenant_id: str, framework: str) -> dict[str, Any] | None:
    with session_scope() as db:
        row = db.execute(
            text(
                """SELECT framework, score, coverage_percent, calculated_at, details_json
                   FROM compliance_scores
                   WHERE tenant_id=:tenant_id AND framework=:framework
                   ORDER BY calculated_at DESC
                   LIMIT 1"""
            ),
            {"tenant_id": tenant_id, "framework": framework},
        ).mappings().first()
        return dict(row) if row else None


router = APIRouter(tags=["compliance"])


@router.post("/audit/session", response_model=AuditSessionResponse)
def create_audit_session(payload: AuditSessionRequest, request: Request):
    tenant_id = str(get_current_tenant(request))
    role = _require_auditor_role(request)
    token = _extract_bearer_token(request)
    claims = jwt.decode(token, _auth_secret(), algorithms=["HS256"])
    username = str(claims.get("sub", "unknown"))
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=payload.ttl_minutes)
    audit_token = f"audit_{tenant_id}_{secrets.token_urlsafe(32)}"
    _save_audit_session(tenant_id=tenant_id, username=username, role=role, token=audit_token, expires_at=expires_at)
    base = {"token": audit_token, "token_type": "bearer", "expires_at": expires_at.isoformat() + "Z"}
    return AuditSessionResponse(**base, signature=_sign_payload("/audit/session", tenant_id, base))


@router.get("/compliance/frameworks")
def list_frameworks(request: Request):
    tenant_id = str(get_current_tenant(request))
    ensure_framework_catalog()
    items = []
    for row in list_frameworks_with_latest_scores(tenant_id):
        clean = dict(row)
        if clean.get("latest_calculated_at") is not None:
            clean["latest_calculated_at"] = str(clean["latest_calculated_at"])
        items.append(FrameworkItem(**clean).model_dump())
    return _signed_response(path="/compliance/frameworks", tenant_id=tenant_id, data={"frameworks": items})


@router.get("/compliance/{framework}/controls")
def framework_controls(framework: str, request: Request):
    tenant_id = str(get_current_tenant(request))
    ensure_framework_catalog()
    rows = list_framework_controls(tenant_id=tenant_id, framework_code=framework)
    items = [
        ControlStateItem(
            control_id=int(r["control_id"]),
            control_code=str(r["control_code"]),
            control_title=str(r["control_title"]),
            requirement_ref=str(r["requirement_ref"]),
            state=str(r["state"]),
            evaluated_at=str(r["evaluated_at"]) if r.get("evaluated_at") else None,
            details=dict(r.get("details_json") or {}),
        ).model_dump()
        for r in rows
    ]
    return _signed_response(path=f"/compliance/{framework}/controls", tenant_id=tenant_id, data={"framework": framework, "controls": items})


@router.get("/compliance/{framework}/score")
def framework_score(framework: str, request: Request, period_days: int = Query(default=30, ge=1, le=365)):
    tenant_id = str(get_current_tenant(request))
    ensure_framework_catalog()
    current = _resolve_latest_score(tenant_id=tenant_id, framework=framework)
    if not current:
        current = compute_continuous_compliance_score(tenant_id=tenant_id, framework=framework, period_days=period_days)
    if "details" not in current:
        current["details"] = dict(current.get("details_json") or {})
    out = FrameworkScoreOut(
        framework=str(current["framework"]),
        score=float(current["score"]),
        coverage_percent=float(current["coverage_percent"]),
        calculated_at=str(current["calculated_at"]),
        details=dict(current.get("details") or {}),
    ).model_dump()
    return _signed_response(path=f"/compliance/{framework}/score", tenant_id=tenant_id, data=out)


@router.get("/compliance/{framework}/report")
def framework_report(
    framework: str,
    request: Request,
    days: int = Query(default=30, ge=1, le=365),
):
    tenant_id = str(get_current_tenant(request))
    ensure_framework_catalog()
    now = datetime.now(timezone.utc)
    start_ts = now - timedelta(days=days)
    controls = list_framework_controls(tenant_id=tenant_id, framework_code=framework)
    pkg = build_audit_package(tenant_id=tenant_id, framework=framework, start_ts=start_ts, end_ts=now)
    score = _resolve_latest_score(tenant_id=tenant_id, framework=framework)
    summary = {
        "framework": framework,
        "controls_total": len(controls),
        "operating_controls": sum(1 for c in controls if c.get("state") == "operating"),
        "degraded_controls": sum(1 for c in controls if c.get("state") == "degraded"),
        "failed_controls": sum(1 for c in controls if c.get("state") == "failed"),
        "insufficient_evidence_controls": sum(1 for c in controls if c.get("state") == "insufficient_evidence"),
        "latest_score": float(score["score"]) if score else None,
    }
    report = FrameworkReportOut(
        framework=framework,
        window_days=days,
        generated_at=now.isoformat() + "Z",
        summary=summary,
        controls=[
            ControlStateItem(
                control_id=int(r["control_id"]),
                control_code=str(r["control_code"]),
                control_title=str(r["control_title"]),
                requirement_ref=str(r["requirement_ref"]),
                state=str(r["state"]),
                evaluated_at=str(r["evaluated_at"]) if r.get("evaluated_at") else None,
                details=dict(r.get("details_json") or {}),
            )
            for r in controls
        ],
        compliance_events_count=int(pkg["events_count"]),
        dataset_hash=str(pkg["dataset_hash"]),
    ).model_dump()
    report["audit_package"] = {"path": pkg["zip_path"], "signature": pkg["signature"]}
    return _signed_response(path=f"/compliance/{framework}/report", tenant_id=tenant_id, data=report)


@router.get("/compliance/audit-window")
def compliance_audit_window(
    request: Request,
    framework: str = Query(..., min_length=2, max_length=32),
    days: int = Query(default=90, ge=1, le=365),
):
    tenant_id = str(get_current_tenant(request))
    now = datetime.now(timezone.utc)
    start_ts = now - timedelta(days=days)
    with session_scope() as db:
        obs = int(
            db.execute(
                text(
                    """SELECT COUNT(*)
                       FROM control_observations
                       WHERE tenant_id=:tenant_id
                         AND observed_at BETWEEN :start_ts AND :end_ts"""
                ),
                {"tenant_id": tenant_id, "start_ts": start_ts, "end_ts": now},
            ).scalar_one()
        )
        controls_eval = int(
            db.execute(
                text(
                    """SELECT COUNT(*)
                       FROM control_state_history csh
                       JOIN control_mappings cm ON cm.control_id=csh.control_id
                       JOIN frameworks f ON f.id=cm.framework_id
                       WHERE csh.tenant_id=:tenant_id
                         AND f.code=:framework
                         AND csh.evaluated_at BETWEEN :start_ts AND :end_ts"""
                ),
                {"tenant_id": tenant_id, "framework": framework, "start_ts": start_ts, "end_ts": now},
            ).scalar_one()
        )
        evidence_events = int(
            db.execute(
                text(
                    """SELECT COUNT(*)
                       FROM compliance_events
                       WHERE tenant_id=:tenant_id
                         AND framework=:framework
                         AND created_at BETWEEN :start_ts AND :end_ts"""
                ),
                {"tenant_id": tenant_id, "framework": framework, "start_ts": start_ts, "end_ts": now},
            ).scalar_one()
        )
    score = _resolve_latest_score(tenant_id=tenant_id, framework=framework)
    payload = AuditWindowOut(
        framework=framework,
        from_ts=start_ts.isoformat() + "Z",
        to_ts=now.isoformat() + "Z",
        observations=obs,
        controls_evaluated=controls_eval,
        evidence_events=evidence_events,
        score=float(score["score"]) if score else None,
    ).model_dump()
    return _signed_response(path="/compliance/audit-window", tenant_id=tenant_id, data=payload)


@router.get("/compliance/{framework}/report/download")
def download_framework_report(
    framework: str,
    request: Request,
    tenant_id: str = Query(..., min_length=36, max_length=36),
    days: int = Query(default=90, ge=1, le=365),
):
    token = _extract_bearer_token(request)
    _validate_audit_token(token=token, tenant_id=tenant_id)
    now = datetime.now(timezone.utc)
    start_ts = now - timedelta(days=days)
    pkg = build_audit_package(tenant_id=tenant_id, framework=framework, start_ts=start_ts, end_ts=now)
    response = FileResponse(
        pkg["zip_path"],
        media_type="application/zip",
        filename=f"{framework}_{tenant_id}_{days}d_audit.zip",
    )
    signature = _sign_payload(
        path=f"/compliance/{framework}/report/download",
        tenant_id=tenant_id,
        data={"dataset_hash": pkg["dataset_hash"], "zip_path": pkg["zip_path"], "days": days},
    )
    response.headers["X-VectorVue-Signature"] = signature["signature"]
    response.headers["X-VectorVue-Signed-At"] = signature["signed_at"]
    response.headers["X-VectorVue-Signature-Alg"] = signature["algorithm"]
    response.headers["X-VectorVue-Dataset-Hash"] = str(pkg["dataset_hash"])
    return response
