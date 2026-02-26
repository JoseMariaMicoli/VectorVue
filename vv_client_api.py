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

"""VectorVue client-safe REST API (Phase 6.5).

This module is additive and does not modify operator routes/TUI behavior.
It serves tenant-isolated read-only endpoints for future public portal usage.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
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
from utils.legal_acceptance import current_legal_bundle
from analytics.model_registry import get_latest_prediction, promote_model
from analytics.queue import enqueue_run_inference, enqueue_train_model


APP_TITLE = "VectorVue Client API"
APP_VERSION = "4.1"
JWT_ALGORITHM = "HS256"
JWT_TTL_SECONDS = 12 * 60 * 60
DEFAULT_THEME = {
    "company_name": "VectorVue Customer",
    "logo_path": "",
    "primary_color": "#121735",
    "accent_color": "#8A2BE2",
    "background_color": "#0A0F2D",
    "foreground_color": "#E6E9F2",
    "danger_color": "#FF4D4F",
    "success_color": "#00C896",
    "updated_at": "",
}
PLATFORM_ATTRIBUTION = {
    "line1": "VectorVue by Nyxera Labs",
    "line2": "© 2026 Nyxera Labs. All rights reserved.",
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


class LegalDocumentItem(BaseModel):
    name: str
    path: str
    content: str


class LegalDocumentsResponse(BaseModel):
    documents: list[LegalDocumentItem]
    document_hash: str
    version: str
    deployment_mode: str


class LegalAcceptanceRequest(BaseModel):
    username: str
    tenant_id: str | None = None
    deployment_mode: str = "self-hosted"
    accepted: bool
    document_hash: str
    version: str


class LegalAcceptanceResponse(BaseModel):
    acceptance_id: int
    username: str
    deployment_mode: str
    document_hash: str
    version: str
    accepted_at: str


class ClientAuthRegisterRequest(BaseModel):
    username: str
    password: str
    tenant_id: str | None = None
    role: str | None = None
    deployment_mode: str = "self-hosted"
    legal_acceptance_id: int


class ClientAuthRegisterResponse(BaseModel):
    created: bool = True
    user_id: int
    username: str
    role: str
    tenant_id: str


class RiskTrendPoint(BaseModel):
    day: str
    score: float


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
    def _valid_hex(value: Any, fallback: str) -> str:
        raw = _safe_scalar({"v": value}, "v", fallback)
        text = str(raw or "").strip()
        if len(text) == 7 and text.startswith("#"):
            try:
                int(text[1:], 16)
                return text
            except Exception:
                return fallback
        return fallback

    def _safe_company_name(value: Any) -> str:
        name = str(value or "").strip()
        if not name:
            return DEFAULT_THEME["company_name"]
        # Guard against rendering abuse in tenant-provided branding labels.
        return name[:80]

    logo_url = None
    if _safe_scalar(row, "logo_path", ""):
        logo_url = build_public_url("/api/v1/client/theme/logo", request)
    return {
        "company_name": _safe_company_name(_safe_scalar(row, "company_name", DEFAULT_THEME["company_name"])),
        "logo_url": logo_url,
        "colors": {
            "primary": _valid_hex(_safe_scalar(row, "primary_color", DEFAULT_THEME["primary_color"]), DEFAULT_THEME["primary_color"]),
            "accent": _valid_hex(_safe_scalar(row, "accent_color", DEFAULT_THEME["accent_color"]), DEFAULT_THEME["accent_color"]),
            "background": _valid_hex(_safe_scalar(row, "background_color", DEFAULT_THEME["background_color"]), DEFAULT_THEME["background_color"]),
            "foreground": _valid_hex(_safe_scalar(row, "foreground_color", DEFAULT_THEME["foreground_color"]), DEFAULT_THEME["foreground_color"]),
            "danger": _valid_hex(_safe_scalar(row, "danger_color", DEFAULT_THEME["danger_color"]), DEFAULT_THEME["danger_color"]),
            "success": _valid_hex(_safe_scalar(row, "success_color", DEFAULT_THEME["success_color"]), DEFAULT_THEME["success_color"]),
        },
        "platform_brand_locked": True,
        "platform_attribution": dict(PLATFORM_ATTRIBUTION),
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


def _client_ip(request: Request) -> str:
    forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if forwarded:
        return forwarded
    if request.client and request.client.host:
        return request.client.host.strip()
    return ""


def _ensure_legal_acceptance_schema(db: Session) -> None:
    db.execute(
        text(
            """CREATE TABLE IF NOT EXISTS legal_acceptances (
                   id BIGSERIAL PRIMARY KEY,
                   user_id BIGINT NULL,
                   username TEXT NOT NULL,
                   tenant_id UUID NULL,
                   deployment_mode TEXT NOT NULL,
                   document_hash TEXT NOT NULL,
                   legal_version TEXT NOT NULL,
                   accepted BOOLEAN NOT NULL DEFAULT TRUE,
                   accepted_at TIMESTAMPTZ NOT NULL,
                   ip_address TEXT NULL,
                   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
               )"""
        )
    )
    db.execute(
        text(
            """CREATE INDEX IF NOT EXISTS idx_legal_acceptances_user_mode_version
               ON legal_acceptances (username, deployment_mode, legal_version)"""
        )
    )
    db.execute(
        text(
            """CREATE INDEX IF NOT EXISTS idx_legal_acceptances_hash_version
               ON legal_acceptances (document_hash, legal_version)"""
        )
    )
    db.commit()


def _current_legal_for_mode(mode: str) -> dict[str, Any]:
    if mode not in {"self-hosted", "saas"}:
        raise HTTPException(status_code=422, detail="deployment_mode must be self-hosted|saas")
    return current_legal_bundle(mode=mode)


def _verify_legal_hash_and_version(mode: str, document_hash: str, version: str) -> dict[str, Any]:
    bundle = _current_legal_for_mode(mode)
    if document_hash != bundle["document_hash"]:
        raise HTTPException(status_code=409, detail="Legal document hash mismatch; re-acceptance is required")
    if version != bundle["version"]:
        raise HTTPException(status_code=409, detail="Legal version mismatch; re-acceptance is required")
    return bundle


def _resolve_register_role(db: Session, requested_role: str | None) -> str:
    user_count = int(db.execute(text("SELECT COUNT(*) FROM users")).scalar_one())
    if user_count == 0:
        return "admin"
    role = (requested_role or "operator").strip().lower()
    if role not in {"viewer", "operator", "lead", "admin"}:
        raise HTTPException(status_code=422, detail="role must be viewer|operator|lead|admin")
    return role


def _ensure_default_group(db: Session) -> int:
    groups = _load_table("groups")
    row = db.execute(select(groups.c.id).where(groups.c.name == "default").limit(1)).mappings().first()
    if row:
        return int(row["id"])
    inserted = db.execute(
        text("INSERT INTO groups (name, description) VALUES (:name, :description) RETURNING id"),
        {"name": "default", "description": "Default group"},
    ).mappings().first()
    if not inserted:
        raise HTTPException(status_code=500, detail="Unable to create default group")
    return int(inserted["id"])


@app.get("/api/v1/client/legal/documents", response_model=LegalDocumentsResponse, tags=["client-legal"])
def legal_documents(mode: str = Query(default="self-hosted")):
    bundle = _current_legal_for_mode(mode)
    docs = [LegalDocumentItem(name=d["name"], path=d["path"], content=d["content"]) for d in bundle["documents"]]
    return LegalDocumentsResponse(
        documents=docs,
        document_hash=bundle["document_hash"],
        version=bundle["version"],
        deployment_mode=mode,
    )


@app.post("/api/v1/client/legal/accept", response_model=LegalAcceptanceResponse, tags=["client-legal"])
def legal_accept(payload: LegalAcceptanceRequest, request: Request, db: Session = Depends(_get_db)):
    _ensure_legal_acceptance_schema(db)
    username = (payload.username or "").strip()
    if not username:
        raise HTTPException(status_code=422, detail="username is required")
    if payload.accepted is not True:
        raise HTTPException(status_code=422, detail="Legal acceptance checkbox must be checked")
    bundle = _verify_legal_hash_and_version(payload.deployment_mode, payload.document_hash, payload.version)
    users = _load_table("users")
    user_row = db.execute(select(users.c.id).where(users.c.username == username).limit(1)).mappings().first()
    user_id = int(user_row["id"]) if user_row else None
    ip_address = _client_ip(request) if payload.deployment_mode == "saas" else None
    accepted_at = datetime.utcnow().isoformat() + "Z"
    row = db.execute(
        text(
            """INSERT INTO legal_acceptances
               (user_id, username, tenant_id, deployment_mode, document_hash, legal_version, accepted, accepted_at, ip_address)
               VALUES (:user_id, :username, CAST(:tenant_id AS UUID), :deployment_mode, :document_hash, :legal_version, TRUE, :accepted_at, :ip_address)
               RETURNING id"""
        ),
        {
            "user_id": user_id,
            "username": username,
            "tenant_id": payload.tenant_id,
            "deployment_mode": payload.deployment_mode,
            "document_hash": bundle["document_hash"],
            "legal_version": bundle["version"],
            "accepted_at": accepted_at,
            "ip_address": ip_address,
        },
    ).mappings().first()
    db.commit()
    if not row:
        raise HTTPException(status_code=500, detail="Unable to persist legal acceptance")
    return LegalAcceptanceResponse(
        acceptance_id=int(row["id"]),
        username=username,
        deployment_mode=payload.deployment_mode,
        document_hash=bundle["document_hash"],
        version=bundle["version"],
        accepted_at=accepted_at,
    )


@app.post("/api/v1/client/auth/register", response_model=ClientAuthRegisterResponse, tags=["client-auth"])
def client_register(payload: ClientAuthRegisterRequest, db: Session = Depends(_get_db)):
    _ensure_legal_acceptance_schema(db)
    username = (payload.username or "").strip()
    password = payload.password or ""
    if not username or not password:
        raise HTTPException(status_code=422, detail="username and password are required")
    if len(password) < 8:
        raise HTTPException(status_code=422, detail="password must be at least 8 characters")

    bundle = _current_legal_for_mode(payload.deployment_mode)
    users = _load_table("users")
    existing = db.execute(select(users.c.id).where(users.c.username == username).limit(1)).mappings().first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Username '{username}' already exists")

    legal_row = db.execute(
        text(
            """SELECT id, user_id, username, tenant_id, deployment_mode, document_hash, legal_version, accepted
               FROM legal_acceptances
               WHERE id = :id"""
        ),
        {"id": payload.legal_acceptance_id},
    ).mappings().first()
    if not legal_row:
        raise HTTPException(status_code=403, detail="Legal acceptance record not found")
    if str(legal_row["username"]).strip() != username:
        raise HTTPException(status_code=403, detail="Legal acceptance does not belong to this username")
    if legal_row["accepted"] is not True:
        raise HTTPException(status_code=403, detail="Legal acceptance is invalid")
    if str(legal_row["deployment_mode"]) != payload.deployment_mode:
        raise HTTPException(status_code=403, detail="Legal acceptance deployment mode mismatch")
    if str(legal_row["document_hash"]) != bundle["document_hash"]:
        raise HTTPException(status_code=409, detail="Legal documents changed; re-acceptance is required")
    if str(legal_row["legal_version"]) != bundle["version"]:
        raise HTTPException(status_code=409, detail="Legal version changed; re-acceptance is required")

    tenant_id = _resolve_login_tenant(db, payload.tenant_id)
    role = _resolve_register_role(db, payload.role)
    group_id = _ensure_default_group(db)
    user_salt = os.urandom(32)
    salt_b64 = base64.b64encode(user_salt).decode("utf-8")
    crypto = SessionCrypto()
    pw_hash = crypto.derive_user_password_hash(password, user_salt)
    now = datetime.utcnow().isoformat() + "Z"

    created = db.execute(
        text(
            """INSERT INTO users (username, password_hash, salt, role, group_id, created_at, last_login)
               VALUES (:username, :password_hash, :salt, :role, :group_id, :created_at, :last_login)
               RETURNING id"""
        ),
        {
            "username": username,
            "password_hash": pw_hash,
            "salt": salt_b64,
            "role": role,
            "group_id": group_id,
            "created_at": now,
            "last_login": "",
        },
    ).mappings().first()
    if not created:
        raise HTTPException(status_code=500, detail="User registration failed")
    user_id = int(created["id"])

    db.execute(
        text(
            """INSERT INTO user_capabilities (user_id, capability_profile, updated_at, updated_by)
               VALUES (:user_id, :capability_profile, :updated_at, :updated_by)
               ON CONFLICT (user_id) DO NOTHING"""
        ),
        {
            "user_id": user_id,
            "capability_profile": "admin-full" if role == "admin" else "operator-core",
            "updated_at": now,
            "updated_by": "SYSTEM",
        },
    )

    db.execute(
        text(
            """UPDATE legal_acceptances
               SET user_id = :user_id, tenant_id = CAST(:tenant_id AS UUID)
               WHERE id = :id"""
        ),
        {"user_id": user_id, "tenant_id": tenant_id, "id": payload.legal_acceptance_id},
    )
    db.commit()

    return ClientAuthRegisterResponse(
        created=True,
        user_id=user_id,
        username=username,
        role=role,
        tenant_id=tenant_id,
    )


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
    media_type = "application/pdf" if p.suffix.lower() == ".pdf" else "application/octet-stream"
    return FileResponse(
        path=str(p),
        filename=f"{_safe_scalar(row, 'report_title', 'report')}.pdf",
        media_type=media_type,
    )


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
        select(
            remediation.c.id,
            remediation.c.finding_id,
            remediation.c.title,
            remediation.c.status,
            remediation.c.created_at,
        ).where(
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
                datetime.combine(_to_day(_safe_scalar(r, "created_at")), datetime.min.time(), tzinfo=timezone.utc)
                + timedelta(days=30)
            )
            if _to_day(_safe_scalar(r, "created_at"))
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
