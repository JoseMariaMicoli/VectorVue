# Copyright (c) 2026 Jose Maria Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

"""VectorVue client-safe REST API (Phase 6.5).

This module is additive and does not modify operator routes/TUI behavior.
It serves tenant-isolated read-only endpoints for future public portal usage.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from collections import defaultdict, deque
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any
from uuid import uuid4

import jwt
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import MetaData, Table, and_, create_engine, or_, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from api_contract.client_api_models import Paginated, RemediationStatus, RiskSummary
from api.compliance_routes import router as compliance_router
from app.client_api.schemas import (
    ClientEvidenceGalleryItem,
    ClientEvidenceGalleryResponse,
    ClientFindingDetail,
    ClientRemediationResponse,
    ClientRemediationTask,
    ClientReportItem,
)
from schemas.client_safe import ClientEvidence, ClientFinding, ClientReport, ClientThemeOut
from security.tenant_auth import get_current_tenant
from utils.tenant_assets import resolve_tenant_asset
from utils.url_builder import build_public_url
from vv_core import SessionCrypto
from vv_core_postgres import _check_postgres, _check_redis
from analytics.model_registry import get_latest_prediction, promote_model
from analytics.queue import enqueue_run_inference, enqueue_train_model


APP_TITLE = "VectorVue Client API"
APP_VERSION = "4.1"
JWT_ALGORITHM = "HS256"
JWT_TTL_SECONDS = 12 * 60 * 60
EVENT_RATE_LIMIT_WINDOW_SECONDS = 60
EVENT_RATE_LIMIT_MAX = 120
ALLOWED_EVENT_TYPES = {
    "FINDING_VIEWED",
    "FINDING_ACKNOWLEDGED",
    "REMEDIATION_OPENED",
    "REMEDIATION_COMPLETED",
    "REPORT_DOWNLOADED",
    "DASHBOARD_VIEWED",
}
ALLOWED_OBJECT_TYPES = {"finding", "report", "dashboard", "remediation"}
SENSITIVE_METADATA_KEYS = {
    "ip",
    "ip_address",
    "ipaddr",
    "user_agent",
    "ua",
    "keystrokes",
    "keypress",
    "keyboard",
}
DEFAULT_THEME = {
    "company_name": "VectorVue Customer",
    "logo_path": "",
    "primary_color": "#0f172a",
    "accent_color": "#22d3ee",
    "background_color": "#0b0e14",
    "foreground_color": "#e5e7eb",
    "danger_color": "#ef4444",
    "success_color": "#22c55e",
    "updated_at": "",
}


def _db_url() -> str:
    env_url = os.environ.get("VV_DB_URL", "").strip()
    if env_url:
        url = make_url(env_url)
        if url.get_backend_name() == "postgresql" and url.drivername != "postgresql+psycopg":
            url = url.set(drivername="postgresql+psycopg")
        return url.render_as_string(hide_password=False)
    user = os.environ.get("VV_DB_USER", os.environ.get("POSTGRES_USER", "vectorvue"))
    password = os.environ.get("VV_DB_PASSWORD", os.environ.get("POSTGRES_PASSWORD", "strongpassword"))
    host = os.environ.get("VV_DB_HOST", "postgres")
    port = os.environ.get("VV_DB_PORT", "5432")
    name = os.environ.get("VV_DB_NAME", os.environ.get("POSTGRES_DB", "vectorvue_db"))
    return make_url(f"postgresql+psycopg://{user}:{password}@{host}:{port}/{name}").render_as_string(
        hide_password=False
    )


engine = create_engine(_db_url(), pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
metadata = MetaData()


app = FastAPI(title=APP_TITLE, version=APP_VERSION)
app.include_router(compliance_router)
_event_rate_limit_lock = Lock()
_event_rate_limit_buckets: dict[str, deque[float]] = defaultdict(deque)


class ClientAuthLoginRequest(BaseModel):
    username: str
    password: str
    tenant_id: str | None = None


class ClientAuthLoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    tenant_id: str
    username: str


class RiskTrendPoint(BaseModel):
    day: str
    score: float


class ClientActivityEventIn(BaseModel):
    event_type: str = Field(..., min_length=3, max_length=64)
    object_type: str = Field(..., min_length=3, max_length=32)
    object_id: str | None = Field(default=None, max_length=128)
    severity: str | None = Field(default=None, max_length=32)
    timestamp: datetime | None = None
    metadata_json: dict[str, Any] | None = None


class ClientActivityEventAccepted(BaseModel):
    accepted: bool = True


class ModelPromoteResponse(BaseModel):
    promoted: bool = True
    model_id: int


class ClientMLResponse(BaseModel):
    score: float
    confidence: float
    explanation: str
    model_version: str
    generated_at: str


def _get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _load_table(name: str) -> Table:
    return Table(name, metadata, autoload_with=engine)


def _require_tenant_column(table: Table) -> None:
    if "tenant_id" not in table.c:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Table '{table.name}' is missing tenant_id. Apply Phase 6.5 migration.",
        )


def _safe_scalar(row: Any, key: str, default: Any = None) -> Any:
    if row is None:
        return default
    try:
        return row[key]
    except Exception:
        return default


def _client_visible_findings_predicate(findings: Table, tenant_id: str):
    return and_(
        findings.c.tenant_id == tenant_id,
        findings.c.approval_status == "approved",
        or_(findings.c.visibility.is_(None), findings.c.visibility != "hidden"),
    )


def _client_visible_reports_predicate(reports: Table, tenant_id: str):
    return and_(
        reports.c.tenant_id == tenant_id,
        reports.c.status.in_(("approved", "published", "final")),
    )


def _theme_payload(row: dict[str, Any], request: Request) -> dict[str, Any]:
    logo_url = None
    if _safe_scalar(row, "logo_path", ""):
        logo_url = build_public_url("/api/v1/client/theme/logo", request)
    return {
        "company_name": _safe_scalar(row, "company_name", DEFAULT_THEME["company_name"]),
        "logo_url": logo_url,
        "colors": {
            "primary": _safe_scalar(row, "primary_color", DEFAULT_THEME["primary_color"]),
            "accent": _safe_scalar(row, "accent_color", DEFAULT_THEME["accent_color"]),
            "background": _safe_scalar(row, "background_color", DEFAULT_THEME["background_color"]),
            "foreground": _safe_scalar(row, "foreground_color", DEFAULT_THEME["foreground_color"]),
            "danger": _safe_scalar(row, "danger_color", DEFAULT_THEME["danger_color"]),
            "success": _safe_scalar(row, "success_color", DEFAULT_THEME["success_color"]),
        },
    }


def _to_day(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    raw = str(value).strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(raw).date()
    except Exception:
        if len(raw) >= 10:
            try:
                return date.fromisoformat(raw[:10])
            except Exception:
                return None
        return None


def _auth_secret() -> str:
    secret = os.environ.get("VV_CLIENT_JWT_SECRET", "").strip()
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="VV_CLIENT_JWT_SECRET is not configured",
        )
    return secret


def _extract_bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    return token


def _decode_client_jwt_payload(request: Request) -> dict[str, Any]:
    token = _extract_bearer_token(request)
    allow_unsigned = os.environ.get("VV_CLIENT_JWT_ALLOW_UNSIGNED", "0").strip() == "1"
    try:
        if os.environ.get("VV_CLIENT_JWT_SECRET", "").strip():
            return jwt.decode(token, key=_auth_secret(), algorithms=[JWT_ALGORITHM], options={"verify_aud": False})
        if allow_unsigned:
            return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT verification misconfigured on server",
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid JWT") from exc


def _sanitize_metadata(raw: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    clean: dict[str, Any] = {}
    for k, v in raw.items():
        key = str(k).strip()
        if not key:
            continue
        if key.lower() in SENSITIVE_METADATA_KEYS:
            continue
        if len(clean) >= 24:
            break
        if isinstance(v, (str, int, float, bool)) or v is None:
            clean[key[:80]] = v
        else:
            clean[key[:80]] = str(v)[:512]
    return clean


def _event_rate_limit_key(tenant_id: str, username: str | None) -> str:
    return f"{tenant_id}:{(username or 'anonymous').strip().lower()}"


def _enforce_event_rate_limit(rate_key: str) -> None:
    now = time.time()
    with _event_rate_limit_lock:
        bucket = _event_rate_limit_buckets[rate_key]
        while bucket and now - bucket[0] > EVENT_RATE_LIMIT_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= EVENT_RATE_LIMIT_MAX:
            raise HTTPException(status_code=429, detail="Event rate limit exceeded")
        bucket.append(now)


def _insert_client_activity_event(record: dict[str, Any]) -> None:
    try:
        with SessionLocal() as db:
            db.execute(
                text(
                    """INSERT INTO client_activity_events
                       (id, tenant_id, user_id, event_type, object_type, object_id, severity, timestamp, metadata_json)
                       VALUES (:id, :tenant_id, :user_id, :event_type, :object_type, :object_id, :severity, :timestamp, CAST(:metadata_json AS JSONB))"""
                ),
                record,
            )
            db.commit()
    except Exception:
        # Telemetry must never block or break the portal UX.
        return


def _resolve_login_tenant(db: Session, requested_tenant_id: str | None) -> str:
    try:
        tenants = _load_table("tenants")
        if requested_tenant_id:
            row = db.execute(
                select(tenants.c.id, tenants.c.active).where(tenants.c.id == requested_tenant_id)
            ).mappings().first()
            if not row:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown tenant_id")
            if not bool(row["active"]):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant is inactive")
            return str(row["id"])

        rows = db.execute(select(tenants.c.id).where(tenants.c.active.is_(True))).mappings().all()
        if len(rows) == 1:
            return str(rows[0]["id"])
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="tenant_id is required for multi-tenant login",
        )
    except SQLAlchemyError as exc:
        # Clear signal for operators when Phase 6.5 schema is missing after reset/seed.
        if "relation \"tenants\" does not exist" in str(exc):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Tenant schema missing. Run make phase65-migrate and retry.",
            ) from exc
        raise


def _enforce_user_tenant_access(db: Session, user_id: int, username: str, tenant_id: str) -> None:
    """Enforce per-user tenant access when mapping table is available and populated."""
    try:
        uta = _load_table("user_tenant_access")
    except SQLAlchemyError:
        return

    total_rows = db.execute(select(text("COUNT(*)")).select_from(uta)).scalar_one()
    if int(total_rows) == 0:
        return

    mapping = db.execute(
        select(uta.c.id, uta.c.active).where(
            uta.c.tenant_id == tenant_id,
            or_(
                uta.c.user_id == int(user_id),
                uta.c.username == username,
            ),
        )
    ).mappings().first()
    if not mapping or not bool(mapping.get("active", False)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not authorized for tenant")


@app.post("/api/v1/client/auth/login", response_model=ClientAuthLoginResponse, tags=["client-auth"])
def client_login(payload: ClientAuthLoginRequest, db: Session = Depends(_get_db)):
    username = (payload.username or "").strip()
    password = payload.password or ""
    if not username or not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="username and password are required")

    users = _load_table("users")
    row = db.execute(
        select(users.c.id, users.c.username, users.c.password_hash, users.c.salt, users.c.role)
        .where(users.c.username == username)
        .limit(1)
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    try:
        user_salt = base64.b64decode(str(row["salt"]))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored credential salt is invalid") from exc

    crypto = SessionCrypto()
    if not crypto.verify_password(password, str(row["password_hash"]), user_salt):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    tenant_id = _resolve_login_tenant(db, payload.tenant_id)
    _enforce_user_tenant_access(db, int(row["id"]), str(row["username"]), tenant_id)
    now = datetime.utcnow()
    expires_at = now.timestamp() + JWT_TTL_SECONDS
    token = jwt.encode(
        {
            "sub": str(row["username"]),
            "tenant_id": tenant_id,
            "role": str(row.get("role", "viewer")),
            "iat": int(now.timestamp()),
            "exp": int(expires_at),
            "iss": "vectorvue-client-api",
        },
        _auth_secret(),
        algorithm=JWT_ALGORITHM,
    )
    return ClientAuthLoginResponse(
        access_token=token,
        expires_in=JWT_TTL_SECONDS,
        tenant_id=tenant_id,
        username=str(row["username"]),
    )


@app.get("/", tags=["system"])
def root_health() -> dict[str, Any]:
    pg_ok, pg_msg = _check_postgres()
    redis_ok, redis_msg = _check_redis()
    return {
        "status": "healthy" if pg_ok and redis_ok else "degraded",
        "version": APP_VERSION,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "checks": {
            "postgres": {"ok": pg_ok, "detail": pg_msg},
            "redis": {"ok": redis_ok, "detail": redis_msg},
        },
    }


@app.get("/healthz", tags=["system"])
def healthz() -> dict[str, Any]:
    return root_health()


@app.post(
    "/api/v1/client/events",
    response_model=ClientActivityEventAccepted,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["client"],
)
def create_client_event(
    payload: ClientActivityEventIn,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(_get_db),
):
    tenant_id = str(get_current_tenant(request))
    event_type = (payload.event_type or "").strip().upper()
    object_type = (payload.object_type or "").strip().lower()
    if event_type not in ALLOWED_EVENT_TYPES:
        raise HTTPException(status_code=422, detail=f"Unsupported event_type: {payload.event_type}")
    if object_type not in ALLOWED_OBJECT_TYPES:
        raise HTTPException(status_code=422, detail=f"Unsupported object_type: {payload.object_type}")

    jwt_payload = _decode_client_jwt_payload(request)
    username = str(jwt_payload.get("sub", "")).strip() or None
    _enforce_event_rate_limit(_event_rate_limit_key(tenant_id, username))

    user_id: int | None = None
    if username:
        users = _load_table("users")
        row = db.execute(select(users.c.id).where(users.c.username == username).limit(1)).mappings().first()
        if row:
            user_id = int(row["id"])

    event_ts = payload.timestamp or datetime.now(timezone.utc)
    if event_ts.tzinfo is None:
        event_ts = event_ts.replace(tzinfo=timezone.utc)

    background_tasks.add_task(
        _insert_client_activity_event,
        {
            "id": str(uuid4()),
            "tenant_id": tenant_id,
            "user_id": user_id,
            "event_type": event_type,
            "object_type": object_type,
            "object_id": payload.object_id,
            "severity": (payload.severity or "").strip().lower() or None,
            "timestamp": event_ts,
            "metadata_json": json.dumps(_sanitize_metadata(payload.metadata_json)),
        },
    )
    return ClientActivityEventAccepted(accepted=True)


def _prediction_to_client_contract(row: dict[str, Any] | None, fallback_explanation: str) -> ClientMLResponse:
    if not row:
        return ClientMLResponse(
            score=0.0,
            confidence=0.0,
            explanation=fallback_explanation,
            model_version="pending",
            generated_at=datetime.utcnow().isoformat() + "Z",
        )
    prediction = row.get("prediction") or {}
    explanation = row.get("explanation") or {}
    score = float(prediction.get("score", 0.0))
    confidence = float(prediction.get("confidence", 0.0))
    readable = fallback_explanation
    if isinstance(explanation, dict):
        top = explanation.get("top_factors") or []
        if isinstance(top, list) and top:
            labels = [str(t.get("feature", "factor")) for t in top[:3] if isinstance(t, dict)]
            if labels:
                readable = f"Primary drivers: {', '.join(labels)}."
    return ClientMLResponse(
        score=round(score, 4),
        confidence=round(confidence, 4),
        explanation=readable,
        model_version=str(row.get("model_version", "unknown")),
        generated_at=str(row.get("created_at", datetime.utcnow().isoformat() + "Z")),
    )


@app.post("/ml/models/{model_id}/promote", response_model=ModelPromoteResponse, tags=["ml"])
def ml_promote_model(model_id: int, request: Request):
    tenant_id = str(get_current_tenant(request))
    promote_model(model_id=model_id, tenant_id=tenant_id)
    return ModelPromoteResponse(promoted=True, model_id=model_id)


@app.get("/ml/operator/suggestions/{campaign_id}", response_model=ClientMLResponse, tags=["ml"])
def ml_operator_suggestions(campaign_id: int, request: Request):
    tenant_id = str(get_current_tenant(request))
    entity_id = str(campaign_id)
    tasks = ["next_step_prediction", "path_success_probability", "operator_efficiency_score"]
    rows = []
    for task in tasks:
        row = get_latest_prediction(tenant_id=tenant_id, task=task, entity_id=entity_id)
        if not row:
            enqueue_run_inference(task_name=task, tenant_id=tenant_id, entity_id=entity_id)
        else:
            rows.append(row)
    if not rows:
        return _prediction_to_client_contract(None, "Operator suggestions are being prepared for this campaign.")
    scores = []
    versions = []
    factors: list[str] = []
    for row in rows:
        pred = row.get("prediction") or {}
        scores.append(float(pred.get("score", 0.0)))
        versions.append(str(row.get("model_version", "unknown")))
        ex = row.get("explanation") or {}
        for factor in ex.get("top_factors", []) if isinstance(ex, dict) else []:
            if isinstance(factor, dict) and factor.get("feature"):
                factors.append(str(factor["feature"]))
    explanation = "Suggested next steps based on campaign behavior."
    if factors:
        top = ", ".join(sorted(set(factors))[:3])
        explanation = f"Suggested next steps prioritize: {top}."
    return ClientMLResponse(
        score=round(sum(scores) / len(scores), 4),
        confidence=0.78,
        explanation=explanation,
        model_version=", ".join(sorted(set(versions))),
        generated_at=datetime.utcnow().isoformat() + "Z",
    )


@app.get("/ml/client/security-score", response_model=ClientMLResponse, tags=["ml"])
def ml_client_security_score(request: Request):
    tenant_id = str(get_current_tenant(request))
    row = get_latest_prediction(tenant_id=tenant_id, task="control_effectiveness", entity_id=tenant_id)
    if not row:
        enqueue_run_inference(task_name="control_effectiveness", tenant_id=tenant_id, entity_id=tenant_id)
    return _prediction_to_client_contract(row, "Security score is being generated from current tenant telemetry.")


@app.get("/ml/client/risk", response_model=ClientMLResponse, tags=["ml"])
def ml_client_risk(request: Request):
    tenant_id = str(get_current_tenant(request))
    row = get_latest_prediction(tenant_id=tenant_id, task="residual_risk", entity_id=tenant_id)
    if not row:
        enqueue_run_inference(task_name="residual_risk", tenant_id=tenant_id, entity_id=tenant_id)
    return _prediction_to_client_contract(row, "Residual risk estimation is being generated.")


@app.get("/ml/client/detection-gaps", response_model=ClientMLResponse, tags=["ml"])
def ml_client_detection_gaps(request: Request):
    tenant_id = str(get_current_tenant(request))
    row = get_latest_prediction(tenant_id=tenant_id, task="detection_coverage", entity_id=tenant_id)
    if not row:
        enqueue_run_inference(task_name="detection_coverage", tenant_id=tenant_id, entity_id=tenant_id)
    return _prediction_to_client_contract(row, "Detection gap analysis is being generated.")


@app.get("/ml/client/anomalies", response_model=ClientMLResponse, tags=["ml"])
def ml_client_anomalies(request: Request):
    tenant_id = str(get_current_tenant(request))
    row = get_latest_prediction(tenant_id=tenant_id, task="baseline_behavior", entity_id=tenant_id)
    if not row:
        enqueue_run_inference(task_name="baseline_behavior", tenant_id=tenant_id, entity_id=tenant_id)
    return _prediction_to_client_contract(row, "Anomaly analysis is being generated from behavioral baseline.")


class ClientSimulationRequest(BaseModel):
    scenario: str = "baseline"
    controls_improvement: float = 0.0
    detection_improvement: float = 0.0


@app.post("/ml/client/simulate", response_model=ClientMLResponse, tags=["ml"])
def ml_client_simulate(payload: ClientSimulationRequest, request: Request):
    tenant_id = str(get_current_tenant(request))
    enqueue_train_model(task_name="defense_improvement_projection", tenant_id=tenant_id)
    row = get_latest_prediction(tenant_id=tenant_id, task="defense_improvement_projection", entity_id=tenant_id)
    if not row:
        enqueue_run_inference(task_name="defense_improvement_projection", tenant_id=tenant_id, entity_id=tenant_id)
    return _prediction_to_client_contract(
        row,
        f"Simulation queued for scenario '{payload.scenario}'. Updated projection will be available shortly.",
    )


@app.get("/api/v1/client/findings", response_model=Paginated[ClientFinding], tags=["client"])
def list_client_findings(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    db: Session = Depends(_get_db),
):
    tenant_id = str(get_current_tenant(request))
    findings = _load_table("findings")
    _require_tenant_column(findings)

    offset = (page - 1) * page_size

    try:
        visible_predicate = _client_visible_findings_predicate(findings, tenant_id)
        total_stmt = select(text("COUNT(*)")).select_from(findings).where(visible_predicate)
        total = int(db.execute(total_stmt).scalar_one())

        stmt = (
            select(
                findings.c.id,
                findings.c.title,
                findings.c.cvss_score,
                findings.c.mitre_id,
                findings.c.approval_status,
                findings.c.visibility.label("visibility_status"),
            )
            .where(visible_predicate)
            .order_by(findings.c.id.desc())
            .limit(page_size)
            .offset(offset)
        )
        rows = db.execute(stmt).mappings().all()

        items = [
            ClientFinding(
                id=int(r["id"]),
                title=str(r["title"]),
                cvss_score=float(r["cvss_score"]) if r["cvss_score"] is not None else None,
                mitre_id=_safe_scalar(r, "mitre_id"),
                approval_status=_safe_scalar(r, "approval_status", "pending"),
                visibility_status=_safe_scalar(r, "visibility_status", "restricted"),
            )
            for r in rows
        ]
        return Paginated[ClientFinding](items=items, page=page, page_size=page_size, total=total)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail=f"Database error: {exc}") from exc


@app.get("/api/v1/client/findings/{finding_id}", response_model=ClientFindingDetail, tags=["client"])
def get_client_finding(
    finding_id: int,
    request: Request,
    db: Session = Depends(_get_db),
):
    tenant_id = str(get_current_tenant(request))
    findings = _load_table("findings")
    _require_tenant_column(findings)
    row = db.execute(
        select(
            findings.c.id,
            findings.c.title,
            findings.c.description,
            findings.c.status,
            findings.c.cvss_score,
            findings.c.mitre_id,
            findings.c.approval_status,
            findings.c.visibility.label("visibility_status"),
        ).where(
            findings.c.id == finding_id,
            _client_visible_findings_predicate(findings, tenant_id),
        )
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    return ClientFindingDetail(
        id=int(row["id"]),
        title=str(row["title"]),
        description=_safe_scalar(row, "description"),
        status=_safe_scalar(row, "status", "Open"),
        cvss_score=float(row["cvss_score"]) if row["cvss_score"] is not None else None,
        mitre_id=_safe_scalar(row, "mitre_id"),
        visibility_status=_safe_scalar(row, "visibility_status", "restricted"),
        approval_status=_safe_scalar(row, "approval_status", "pending"),
    )


@app.get("/api/v1/client/evidence", response_model=Paginated[ClientEvidence], tags=["client"])
def list_client_evidence(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    db: Session = Depends(_get_db),
):
    tenant_id = str(get_current_tenant(request))
    evidence = _load_table("evidence_items")
    findings = _load_table("findings")
    _require_tenant_column(evidence)
    _require_tenant_column(findings)
    visible_findings = select(findings.c.id).where(
        _client_visible_findings_predicate(findings, tenant_id)
    )

    offset = (page - 1) * page_size

    total_stmt = (
        select(text("COUNT(*)"))
        .select_from(evidence)
        .where(
            evidence.c.tenant_id == tenant_id,
            evidence.c.approval_status == "approved",
            evidence.c.finding_id.in_(visible_findings),
        )
    )
    total = int(db.execute(total_stmt).scalar_one())

    stmt = (
        select(
            evidence.c.id,
            evidence.c.finding_id,
            evidence.c.description.label("label"),
            evidence.c.sha256_hash.label("hash_sha256"),
            evidence.c.collected_timestamp.label("collected_at"),
            evidence.c.approval_status,
        )
        .where(
            evidence.c.tenant_id == tenant_id,
            evidence.c.approval_status == "approved",
            evidence.c.finding_id.in_(visible_findings),
        )
        .order_by(evidence.c.id.desc())
        .limit(page_size)
        .offset(offset)
    )
    rows = db.execute(stmt).mappings().all()

    items = [
        ClientEvidence(
            id=int(r["id"]),
            finding_id=_safe_scalar(r, "finding_id"),
            label=_safe_scalar(r, "label", "evidence"),
            hash_sha256=_safe_scalar(r, "hash_sha256"),
            collected_at=None,
            approval_status=_safe_scalar(r, "approval_status", "pending"),
            visibility_status="restricted",
        )
        for r in rows
    ]
    return Paginated[ClientEvidence](items=items, page=page, page_size=page_size, total=total)


@app.get("/api/v1/client/evidence/{finding_id}", response_model=ClientEvidenceGalleryResponse, tags=["client"])
def list_client_evidence_for_finding(
    finding_id: int,
    request: Request,
    db: Session = Depends(_get_db),
):
    tenant_id = str(get_current_tenant(request))
    evidence = _load_table("evidence_items")
    findings = _load_table("findings")
    _require_tenant_column(evidence)
    _require_tenant_column(findings)
    visible_findings = select(findings.c.id).where(
        _client_visible_findings_predicate(findings, tenant_id)
    )
    rows = db.execute(
        select(
            evidence.c.id,
            evidence.c.finding_id,
            evidence.c.artifact_type,
            evidence.c.description,
            evidence.c.approval_status,
        ).where(
            evidence.c.tenant_id == tenant_id,
            evidence.c.finding_id == finding_id,
            evidence.c.approval_status == "approved",
            evidence.c.finding_id.in_(visible_findings),
        )
    ).mappings().all()
    items = [
        ClientEvidenceGalleryItem(
            id=int(r["id"]),
            finding_id=int(r["finding_id"]) if r["finding_id"] is not None else finding_id,
            artifact_type=_safe_scalar(r, "artifact_type", "artifact"),
            description=_safe_scalar(r, "description"),
            approval_status=_safe_scalar(r, "approval_status", "pending"),
            download_url=build_public_url(f"/api/v1/client/evidence/{finding_id}?evidence_id={int(r['id'])}", request),
        )
        for r in rows
    ]
    return ClientEvidenceGalleryResponse(finding_id=finding_id, items=items)


@app.get("/api/v1/client/reports", response_model=Paginated[ClientReportItem], tags=["client"])
def list_client_reports(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    db: Session = Depends(_get_db),
):
    tenant_id = str(get_current_tenant(request))
    reports = _load_table("client_reports")
    _require_tenant_column(reports)
    report_predicate = _client_visible_reports_predicate(reports, tenant_id)

    offset = (page - 1) * page_size
    total_stmt = select(text("COUNT(*)")).select_from(reports).where(report_predicate)
    total = int(db.execute(total_stmt).scalar_one())

    stmt = (
        select(
            reports.c.id,
            reports.c.report_title.label("title"),
            reports.c.created_at,
            reports.c.status.label("approval_status"),
        )
        .where(report_predicate)
        .order_by(reports.c.id.desc())
        .limit(page_size)
        .offset(offset)
    )
    rows = db.execute(stmt).mappings().all()

    items = [
        ClientReportItem(
            id=int(r["id"]),
            title=_safe_scalar(r, "title", "Untitled report"),
            report_date=None,
            status=_safe_scalar(r, "approval_status", "draft"),
            download_url=build_public_url(f"/api/v1/client/reports/{int(r['id'])}/download", request),
        )
        for r in rows
    ]
    return Paginated[ClientReportItem](items=items, page=page, page_size=page_size, total=total)


@app.get("/api/v1/client/reports/{report_id}/download", tags=["client"])
def download_client_report(
    report_id: int,
    request: Request,
    db: Session = Depends(_get_db),
):
    tenant_id = str(get_current_tenant(request))
    reports = _load_table("client_reports")
    _require_tenant_column(reports)
    report_predicate = _client_visible_reports_predicate(reports, tenant_id)
    row = db.execute(
        select(reports.c.id, reports.c.report_title, reports.c.file_path).where(
            reports.c.id == report_id,
            report_predicate,
        )
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    file_path = _safe_scalar(row, "file_path", "")
    if not file_path:
        raise HTTPException(status_code=404, detail="Report file unavailable")
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        raise HTTPException(status_code=404, detail="Report file missing")
    return FileResponse(path=str(p), filename=f"{_safe_scalar(row, 'report_title', 'report')}.pdf")


@app.get("/api/v1/client/risk-summary", response_model=RiskSummary, tags=["client"])
def risk_summary(request: Request, db: Session = Depends(_get_db)):
    tenant_id = str(get_current_tenant(request))
    findings = _load_table("findings")
    _require_tenant_column(findings)

    stmt = (
        select(findings.c.cvss_score)
        .where(_client_visible_findings_predicate(findings, tenant_id))
    )
    scores = [float(r[0]) for r in db.execute(stmt).all() if r[0] is not None]

    critical = sum(1 for s in scores if s >= 9.0)
    high = sum(1 for s in scores if 7.0 <= s < 9.0)
    medium = sum(1 for s in scores if 4.0 <= s < 7.0)
    low = sum(1 for s in scores if 0.0 <= s < 4.0)
    avg = (sum(scores) / len(scores)) if scores else 0.0

    return RiskSummary(
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        score=round(avg, 2),
        last_updated=datetime.utcnow(),
    )


@app.get("/api/v1/client/risk-trend", response_model=list[RiskTrendPoint], tags=["client"])
def risk_trend(request: Request, db: Session = Depends(_get_db)):
    tenant_id = str(get_current_tenant(request))
    findings = _load_table("findings")
    _require_tenant_column(findings)

    if "created_at" not in findings.c:
        return []

    rows = db.execute(
        select(findings.c.created_at, findings.c.cvss_score).where(
            _client_visible_findings_predicate(findings, tenant_id)
        )
    ).all()
    if not rows:
        return []

    since = datetime.utcnow().date() - timedelta(days=29)
    buckets: dict[date, list[float]] = {}
    for created_at, cvss_score in rows:
        day = _to_day(created_at)
        if day is None or day < since:
            continue
        score = float(cvss_score) if cvss_score is not None else 0.0
        buckets.setdefault(day, []).append(score)

    points: list[RiskTrendPoint] = []
    for day in sorted(buckets.keys()):
        values = buckets[day]
        avg = round(sum(values) / len(values), 2) if values else 0.0
        points.append(RiskTrendPoint(day=day.isoformat(), score=avg))
    return points


@app.get("/api/v1/client/risk", response_model=RiskSummary, tags=["client"])
def risk_summary_alias(request: Request, db: Session = Depends(_get_db)):
    return risk_summary(request, db)


@app.get("/api/v1/client/remediation-status", response_model=RemediationStatus, tags=["client"])
def remediation_status(request: Request, db: Session = Depends(_get_db)):
    tenant_id = str(get_current_tenant(request))

    # Primary source: remediation_tasks table (created by Phase 6.5 migration if missing).
    remediation = _load_table("remediation_tasks")
    findings = _load_table("findings")
    _require_tenant_column(remediation)
    _require_tenant_column(findings)
    visible_findings = select(findings.c.id).where(
        _client_visible_findings_predicate(findings, tenant_id)
    )

    stmt = select(remediation.c.status).where(
        remediation.c.tenant_id == tenant_id,
        or_(
            remediation.c.finding_id.is_(None),
            remediation.c.finding_id.in_(visible_findings),
        ),
    )
    statuses = [str(r[0]).lower() for r in db.execute(stmt).all() if r[0] is not None]

    total = len(statuses)
    open_tasks = sum(1 for s in statuses if s in {"open", "todo"})
    in_progress = sum(1 for s in statuses if s in {"in_progress", "doing", "active"})
    completed = sum(1 for s in statuses if s in {"done", "completed", "closed"})
    blocked = sum(1 for s in statuses if s in {"blocked", "stalled"})

    return RemediationStatus(
        total_tasks=total,
        open_tasks=open_tasks,
        in_progress_tasks=in_progress,
        completed_tasks=completed,
        blocked_tasks=blocked,
    )


@app.get("/api/v1/client/remediation", response_model=ClientRemediationResponse, tags=["client"])
def remediation_tasks(request: Request, db: Session = Depends(_get_db)):
    tenant_id = str(get_current_tenant(request))
    remediation = _load_table("remediation_tasks")
    findings = _load_table("findings")
    _require_tenant_column(remediation)
    _require_tenant_column(findings)
    visible_findings = select(findings.c.id).where(
        _client_visible_findings_predicate(findings, tenant_id)
    )
    rows = db.execute(
        select(remediation.c.id, remediation.c.finding_id, remediation.c.title, remediation.c.status).where(
            remediation.c.tenant_id == tenant_id,
            or_(
                remediation.c.finding_id.is_(None),
                remediation.c.finding_id.in_(visible_findings),
            ),
        )
    ).mappings().all()
    items = [
        ClientRemediationTask(
            id=int(r["id"]),
            finding_id=_safe_scalar(r, "finding_id"),
            title=_safe_scalar(r, "title", "Task"),
            status=_safe_scalar(r, "status", "open"),
            priority="medium",
            due_date=(
                datetime.fromisoformat(_safe_scalar(r, "created_at", "").replace("Z", ""))
                + timedelta(days=30)
            )
            if _safe_scalar(r, "created_at")
            else None,
        )
        for r in rows
    ]
    return ClientRemediationResponse(items=items)


@app.get("/api/v1/client/theme", response_model=ClientThemeOut, tags=["client"])
def get_client_theme(
    request: Request,
    response: Response,
    db: Session = Depends(_get_db),
):
    tenant_id = str(get_current_tenant(request))
    try:
        themes = _load_table("tenant_theme")
        row = db.execute(select(themes).where(themes.c.tenant_id == tenant_id)).mappings().first()
    except SQLAlchemyError:
        row = None

    source = dict(DEFAULT_THEME)
    if row:
        source.update(dict(row))

    payload = _theme_payload(source, request)
    etag_source = f"{tenant_id}:{source.get('updated_at', '')}:{source.get('logo_path', '')}:{payload['colors']}"
    etag = '"' + hashlib.sha256(etag_source.encode("utf-8")).hexdigest() + '"'
    incoming = request.headers.get("if-none-match", "")
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "private, max-age=300"
    if incoming == etag:
        return JSONResponse(status_code=304, content=None, headers={"ETag": etag, "Cache-Control": "private, max-age=300"})
    return payload


@app.get("/api/v1/client/theme/logo", tags=["client"])
def get_client_theme_logo(
    request: Request,
    db: Session = Depends(_get_db),
):
    tenant_id = str(get_current_tenant(request))
    try:
        themes = _load_table("tenant_theme")
        row = db.execute(
            select(themes.c.logo_path).where(themes.c.tenant_id == tenant_id)
        ).mappings().first()
    except SQLAlchemyError:
        row = None

    logo_name = _safe_scalar(row, "logo_path", "") if row else ""
    if not logo_name:
        raise HTTPException(status_code=404, detail="Logo not configured")

    try:
        logo_path = resolve_tenant_asset(tenant_id, logo_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid logo path") from exc

    if not logo_path.exists() or not logo_path.is_file():
        raise HTTPException(status_code=404, detail="Logo not found")

    suffix = logo_path.suffix.lower()
    media_type = "application/octet-stream"
    if suffix in {".png"}:
        media_type = "image/png"
    elif suffix in {".jpg", ".jpeg"}:
        media_type = "image/jpeg"
    elif suffix == ".svg":
        media_type = "image/svg+xml"
    return FileResponse(path=str(logo_path), media_type=media_type)
