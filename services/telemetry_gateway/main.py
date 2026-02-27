# Copyright (c) 2026 NyxeraLabs
# Author: Jose Maria Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-22 -> Apache-2.0
#
# You may:
# Study
# Modify
# Use for internal security testing
#
# You may NOT:
# Offer as a commercial service
# Sell derived competing products

"""Internal-only telemetry gateway with mTLS identity + cert pinning."""

from __future__ import annotations

import base64
import hmac
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
from dataclasses import dataclass
from threading import Lock
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from redis import Redis
from redis.exceptions import RedisError
from services.federation.schemas import SignedEvidenceBundle
from services.federation.verifier import federation_bundle_hash, verify_proof_of_origin
from security.tamper_log import get_tamper_audit_log
from services.telemetry_gateway.queue import SecureQueuePublisher, clear_memory_messages, load_queue_settings
from services.telemetry_processing.validator import validate_canonical_payload


HEX_64_RE = re.compile(r"^[a-fA-F0-9]{64}$")
B64_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9+/=]+$")


class TelemetryIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operator_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(pattern=r"^[a-fA-F0-9-]{36}$")
    execution_hash: str = Field(min_length=64, max_length=64)
    timestamp: int
    nonce: str = Field(min_length=8, max_length=128)
    signed_metadata: "SignedTenantMetadata"
    payload: dict[str, Any]


class SignedTenantMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(pattern=r"^[a-fA-F0-9-]{36}$")
    operator_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=128)


class TelemetryIngestResponse(BaseModel):
    accepted: bool
    request_id: str


class ExecutionGraphMetadataRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operator_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(pattern=r"^[a-fA-F0-9-]{36}$")
    execution_fingerprint: str = Field(min_length=64, max_length=64, pattern=r"^[a-fA-F0-9]{64}$")
    timestamp: int
    nonce: str = Field(min_length=8, max_length=128)
    schema_version: str = Field(min_length=1, max_length=32)
    graph: dict[str, Any]


class FeedbackQueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operator_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(pattern=r"^[a-fA-F0-9-]{36}$")
    timestamp: int
    nonce: str = Field(min_length=8, max_length=128)
    limit: int = Field(default=100, ge=1, le=1000)


class FeedbackAdjustment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(pattern=r"^[a-fA-F0-9-]{36}$")
    execution_fingerprint: str = Field(min_length=64, max_length=64, pattern=r"^[a-fA-F0-9]{64}$")
    target_urn: str = Field(min_length=1, max_length=512)
    action: str = Field(min_length=1, max_length=32)
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=1, max_length=2048)
    control: str = Field(default="execution", min_length=1, max_length=64)
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    timestamp: int
    schema_version: str = Field(min_length=1, max_length=32)


class FederationVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle: SignedEvidenceBundle


class FederationVerifyResponse(BaseModel):
    accepted: bool
    bundle_hash: str


@dataclass(frozen=True)
class GatewaySettings:
    require_mtls: bool
    allowed_service_identities: dict[str, str]
    identity_cert_path: str
    identity_key_path: str
    identity_ca_path: str
    require_payload_signature: bool
    spectrastrike_ed25519_public_key_b64: str
    allowed_clock_skew_seconds: int
    nonce_ttl_seconds: int
    nonce_backend: str
    redis_url: str
    rate_limit_per_minute: int
    rate_limit_backend: str
    queue_backend: str
    operator_tenant_map: dict[str, str]
    enforce_schema_version: bool
    allowed_schema_version: str
    feedback_signing_secret: str


class ReplayGuard:
    def __init__(self) -> None:
        self._lock = Lock()
        self._nonces: dict[str, float] = {}

    def register(self, key: str, ttl_seconds: int) -> bool:
        now = time.time()
        with self._lock:
            self._nonces = {k: exp for k, exp in self._nonces.items() if exp > now}
            if key in self._nonces:
                return False
            self._nonces[key] = now + float(ttl_seconds)
            return True

    def clear(self) -> None:
        with self._lock:
            self._nonces.clear()


_replay_guard = ReplayGuard()


class MemoryRateLimiter:
    def __init__(self) -> None:
        self._lock = Lock()
        self._buckets: dict[str, tuple[int, float]] = {}

    def hit(self, key: str, limit: int, ttl_seconds: int) -> bool:
        now = time.time()
        with self._lock:
            self._buckets = {k: v for k, v in self._buckets.items() if v[1] > now}
            count, exp = self._buckets.get(key, (0, now + float(ttl_seconds)))
            count += 1
            self._buckets[key] = (count, exp)
            return count <= limit

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()


_rate_limiter = MemoryRateLimiter()
_graph_store_lock = Lock()
_execution_graph_store: dict[str, list[ExecutionGraphMetadataRequest]] = {}


def _get_redis_client(settings: GatewaySettings) -> Redis:
    if not settings.redis_url:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Telemetry gateway Redis URL is not configured")
    try:
        client = Redis.from_url(settings.redis_url, decode_responses=True)
        client.ping()
        return client
    except RedisError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Telemetry gateway Redis backend unavailable") from exc


def _parse_bool(name: str, default: str = "1") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _load_settings() -> GatewaySettings:
    allowed_identities = _load_allowed_service_identities()
    cert_path = os.environ.get("VV_SERVICE_IDENTITY_CERT_PATH", "/etc/vectorvue/certs/server.crt").strip()
    key_path = os.environ.get("VV_SERVICE_IDENTITY_KEY_PATH", "/etc/vectorvue/certs/server.key").strip()
    ca_path = os.environ.get("VV_SERVICE_IDENTITY_CA_PATH", "/etc/vectorvue/certs/ca.crt").strip()
    for p in (cert_path, key_path, ca_path):
        if not Path(p).exists():
            raise RuntimeError(f"Service identity artifact missing: {p}")

    pubkey = os.environ.get("VV_TG_SPECTRASTRIKE_ED25519_PUBKEY", "").strip()
    if not pubkey:
        raise RuntimeError("VV_TG_SPECTRASTRIKE_ED25519_PUBKEY must be configured")

    try:
        skew = int(os.environ.get("VV_TG_ALLOWED_CLOCK_SKEW_SECONDS", "30").strip())
        nonce_ttl = int(os.environ.get("VV_TG_NONCE_TTL_SECONDS", "120").strip())
        rate_limit_per_min = int(os.environ.get("VV_TG_RATE_LIMIT_PER_MINUTE", "120").strip())
    except ValueError as exc:
        raise RuntimeError("Clock skew, nonce TTL and rate limit must be integers") from exc

    if skew < 1 or nonce_ttl < 30 or rate_limit_per_min < 1:
        raise RuntimeError("Clock skew must be >=1, nonce TTL >=30, and rate limit >=1")

    feedback_signing_secret = os.environ.get("VV_TG_FEEDBACK_SIGNING_SECRET", "").strip()
    if not feedback_signing_secret:
        raise RuntimeError("VV_TG_FEEDBACK_SIGNING_SECRET must be configured")

    return GatewaySettings(
        require_mtls=_parse_bool("VV_TG_REQUIRE_MTLS", "1"),
        allowed_service_identities=allowed_identities,
        identity_cert_path=cert_path,
        identity_key_path=key_path,
        identity_ca_path=ca_path,
        require_payload_signature=_parse_bool("VV_TG_REQUIRE_PAYLOAD_SIGNATURE", "1"),
        spectrastrike_ed25519_public_key_b64=pubkey,
        allowed_clock_skew_seconds=skew,
        nonce_ttl_seconds=nonce_ttl,
        nonce_backend=os.environ.get("VV_TG_NONCE_BACKEND", "redis").strip().lower(),
        redis_url=os.environ.get("VV_TG_REDIS_URL", "").strip(),
        rate_limit_per_minute=rate_limit_per_min,
        rate_limit_backend=os.environ.get("VV_TG_RATE_LIMIT_BACKEND", "redis").strip().lower(),
        queue_backend=os.environ.get("VV_TG_QUEUE_BACKEND", "nats").strip().lower(),
        operator_tenant_map=_load_operator_tenant_map(),
        enforce_schema_version=_parse_bool("VV_TG_ENFORCE_SCHEMA_VERSION", "0"),
        allowed_schema_version=os.environ.get("VV_TG_ALLOWED_SCHEMA_VERSION", "1.0").strip(),
        feedback_signing_secret=feedback_signing_secret,
    )


def _load_allowed_service_identities() -> dict[str, str]:
    raw = os.environ.get("VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON", "").strip() or "{}"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON must be valid JSON object") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise RuntimeError("VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON must be a non-empty JSON object")

    out: dict[str, str] = {}
    for service_id, fingerprint in parsed.items():
        sid = str(service_id).strip()
        fp = str(fingerprint).strip().lower()
        if not sid:
            raise RuntimeError("service identity id cannot be empty")
        if not HEX_64_RE.fullmatch(fp):
            raise RuntimeError("service identity fingerprint must be 64-char sha256 hex")
        out[sid] = fp
    return out


def _load_operator_tenant_map() -> dict[str, str]:
    raw = os.environ.get("VV_TG_OPERATOR_TENANT_MAP", "").strip() or "{}"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("VV_TG_OPERATOR_TENANT_MAP must be valid JSON object") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("VV_TG_OPERATOR_TENANT_MAP must be a JSON object")
    out: dict[str, str] = {}
    for k, v in parsed.items():
        key = str(k).strip()
        value = str(v).strip()
        if not key or not re.fullmatch(r"^[a-fA-F0-9-]{36}$", value):
            raise RuntimeError("VV_TG_OPERATOR_TENANT_MAP values must be UUID strings")
        out[key] = value
    return out


def _require_header(request: Request, header: str) -> str:
    value = request.headers.get(header, "").strip()
    if not value:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Missing required header: {header}")
    return value


def _enforce_service_identity_auth(request: Request, settings: GatewaySettings) -> str:
    service_id = _require_header(request, "X-Service-Identity")
    cert_fp = _require_header(request, "X-Client-Cert-Sha256").lower()
    if not HEX_64_RE.fullmatch(cert_fp):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client certificate fingerprint format")
    expected = settings.allowed_service_identities.get(service_id)
    if not expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown service identity")
    if settings.require_mtls and cert_fp != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Service identity certificate fingerprint mismatch")
    return cert_fp


def _load_public_key(settings: GatewaySettings) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(settings.spectrastrike_ed25519_public_key_b64)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Invalid gateway public key config") from exc
    if len(raw) != 32:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Invalid Ed25519 public key length")
    return Ed25519PublicKey.from_public_bytes(raw)


def _verify_signature(request: Request, settings: GatewaySettings, raw_body: bytes) -> tuple[int, str]:
    ts_raw = _require_header(request, "X-Telemetry-Timestamp")
    nonce = _require_header(request, "X-Telemetry-Nonce")
    signature_b64 = _require_header(request, "X-Telemetry-Signature")

    if not B64_SIGNATURE_RE.fullmatch(signature_b64):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Signature header is not valid base64")

    try:
        ts = int(ts_raw)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Telemetry timestamp must be unix epoch seconds") from exc

    if abs(int(time.time()) - ts) > settings.allowed_clock_skew_seconds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Telemetry timestamp out of allowed clock skew")

    try:
        signature = base64.b64decode(signature_b64)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed signature encoding") from exc

    key = _load_public_key(settings)
    message = f"{ts}.{nonce}.".encode("utf-8") + raw_body
    try:
        key.verify(signature, message)
    except InvalidSignature as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid telemetry signature") from exc

    nonce_key = hashlib.sha256(f"{ts}:{nonce}".encode("utf-8")).hexdigest()
    if not _register_nonce_once(nonce_key, settings):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Replay detected: nonce already used")

    return ts, nonce


def _register_nonce_once(nonce_key: str, settings: GatewaySettings) -> bool:
    if settings.nonce_backend == "memory":
        return _replay_guard.register(nonce_key, settings.nonce_ttl_seconds)
    if settings.nonce_backend == "redis":
        client = _get_redis_client(settings)
        try:
            return bool(client.set(name=f"vv:tg:nonce:{nonce_key}", value="1", nx=True, ex=settings.nonce_ttl_seconds))
        except RedisError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Nonce store unavailable") from exc
    raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Unsupported nonce backend")


def _enforce_operator_rate_limit(operator_id: str, settings: GatewaySettings) -> None:
    if settings.rate_limit_backend == "memory":
        window_key = f"{operator_id}:{int(time.time() // 60)}"
        accepted = _rate_limiter.hit(window_key, settings.rate_limit_per_minute, 90)
        if not accepted:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Operator burst anomaly detected")
        return

    if settings.rate_limit_backend == "redis":
        client = _get_redis_client(settings)
        try:
            bucket = int(time.time() // 60)
            key = f"vv:tg:ratelimit:{operator_id}:{bucket}"
            count = int(client.incr(key))
            if count == 1:
                client.expire(key, 90)
            if count > settings.rate_limit_per_minute:
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Operator burst anomaly detected")
            return
        except RedisError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Rate limiter unavailable") from exc

    raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Unsupported rate-limit backend")


def _enforce_signed_tenant_metadata(payload: TelemetryIngestRequest, settings: GatewaySettings) -> None:
    metadata = payload.signed_metadata
    if (
        metadata.tenant_id != payload.tenant_id
        or metadata.operator_id != payload.operator_id
        or metadata.campaign_id != payload.campaign_id
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Signed metadata mapping mismatch")

    expected_tenant = settings.operator_tenant_map.get(payload.operator_id)
    if not expected_tenant:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operator is not mapped to any tenant")
    if expected_tenant != payload.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operator tenant mapping violation")


def _enforce_schema_version(
    payload: TelemetryIngestRequest,
    settings: GatewaySettings,
) -> None:
    if not settings.enforce_schema_version:
        return
    schema_version = str(payload.payload.get("attributes", {}).get("schema_version", "")).strip()
    if not schema_version:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Telemetry schema version is required by gateway policy",
        )
    if schema_version != settings.allowed_schema_version:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Telemetry schema version is not allowed",
        )


def _feedback_signature(
    *,
    settings: GatewaySettings,
    tenant_id: str,
    signed_at: int,
    nonce: str,
    payload: list[dict[str, Any]],
) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signing_input = f"{tenant_id}|{signed_at}|{nonce}|{canonical}"
    return hmac.new(
        settings.feedback_signing_secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _build_feedback_adjustments(
    *,
    records: list[ExecutionGraphMetadataRequest],
) -> list[FeedbackAdjustment]:
    out: list[FeedbackAdjustment] = []
    for record in records:
        graph_nodes = record.graph.get("nodes", [])
        target_urn = str(record.graph.get("target_urn", "urn:target:unknown"))
        action = "observe"
        confidence = 0.55
        rationale = "graph telemetry received; monitoring baseline adjustments"
        if isinstance(graph_nodes, list) and len(graph_nodes) >= 8:
            action = "tighten"
            confidence = 0.82
            rationale = "high-complexity execution graph exceeded cognitive threshold"
        out.append(
            FeedbackAdjustment(
                tenant_id=record.tenant_id,
                execution_fingerprint=record.execution_fingerprint.lower(),
                target_urn=target_urn,
                action=action,
                confidence=confidence,
                rationale=rationale,
                control="execution",
                ttl_seconds=1800,
                timestamp=int(time.time()),
                schema_version="feedback.adjustment.v1",
            )
        )
    return out


def _enforce_operator_tenant_pair(
    *,
    operator_id: str,
    tenant_id: str,
    settings: GatewaySettings,
) -> None:
    expected_tenant = settings.operator_tenant_map.get(operator_id)
    if not expected_tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator is not mapped to any tenant",
        )
    if expected_tenant != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator tenant mapping violation",
        )


app = FastAPI(title="VectorVue Telemetry Gateway", version="3.2.0")


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    try:
        settings = _load_settings()
    except RuntimeError as exc:
        return {"status": "degraded", "detail": str(exc)}

    return {
        "status": "healthy",
        "require_mtls": settings.require_mtls,
        "trusted_identities": sorted(settings.allowed_service_identities.keys()),
        "require_payload_signature": settings.require_payload_signature,
        "enforce_schema_version": settings.enforce_schema_version,
        "allowed_schema_version": settings.allowed_schema_version,
        "nonce_ttl_seconds": settings.nonce_ttl_seconds,
        "nonce_backend": settings.nonce_backend,
        "rate_limit_per_minute": settings.rate_limit_per_minute,
        "queue_backend": settings.queue_backend,
    }


@app.post("/internal/v1/federation/verify", response_model=FederationVerifyResponse, status_code=status.HTTP_200_OK)
async def verify_federation_bundle(request: Request, payload: FederationVerifyRequest) -> FederationVerifyResponse:
    audit_log = get_tamper_audit_log()
    request_id = str(uuid4())
    try:
        settings = _load_settings()
    except RuntimeError as exc:
        audit_log.append_event(
            event_type="federation.rejected",
            actor="telemetry_gateway",
            details={"request_id": request_id, "reason": "gateway_settings_invalid", "detail": str(exc)},
        )
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    try:
        _enforce_service_identity_auth(request, settings)
        if not verify_proof_of_origin(payload.bundle):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Federation proof-of-origin verification failed")

        bundle_hash = federation_bundle_hash(payload.bundle)
        audit_log.append_event(
            event_type="federation.accepted",
            actor="telemetry_gateway",
            details={"request_id": request_id, "bundle_hash": bundle_hash, "operator_id": payload.bundle.operator_id},
        )
        return FederationVerifyResponse(accepted=True, bundle_hash=bundle_hash)
    except HTTPException as exc:
        audit_log.append_event(
            event_type="federation.rejected",
            actor="telemetry_gateway",
            details={"request_id": request_id, "status_code": exc.status_code, "detail": str(exc.detail)},
        )
        raise


@app.post("/internal/v1/telemetry", response_model=TelemetryIngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_telemetry(request: Request) -> TelemetryIngestResponse:
    request_id = str(uuid4())
    audit_log = get_tamper_audit_log()
    try:
        settings = _load_settings()
    except RuntimeError as exc:
        audit_log.append_event(
            event_type="telemetry.rejected",
            actor="SYSTEM",
            details={"request_id": request_id, "reason": "gateway_settings_invalid", "detail": str(exc)},
        )
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    queue_settings = load_queue_settings()
    queue = SecureQueuePublisher(queue_settings)
    raw = await request.body()

    try:
        _enforce_service_identity_auth(request, settings)

        if not raw:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Telemetry payload is required")

        if settings.require_payload_signature:
            ts, nonce = _verify_signature(request, settings, raw)
        else:
            # Unsigned telemetry is forbidden by platform policy.
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Unsigned telemetry is disabled by policy")

        try:
            body = json.loads(raw)
        except json.JSONDecodeError as exc:
            await _publish_dead_letter_or_fail(
                queue=queue,
                raw_body=raw,
                error_code="invalid_json",
                error_message="Invalid JSON payload",
                trace={"reason": "json_decode"},
            )
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid JSON payload") from exc

        try:
            parsed = TelemetryIngestRequest.model_validate(body)
        except ValidationError as exc:
            await _publish_dead_letter_or_fail(
                queue=queue,
                raw_body=raw,
                error_code="schema_validation_failed",
                error_message="Telemetry schema validation failed",
                trace={"reason": "schema_validation", "errors": exc.errors()},
            )
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Telemetry schema validation failed") from exc

        if parsed.timestamp != ts:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Body timestamp mismatch with signed header")
        if parsed.nonce != nonce:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Body nonce mismatch with signed header")

        try:
            canonical_payload = validate_canonical_payload(parsed.payload)
        except ValidationError as exc:
            await _publish_dead_letter_or_fail(
                queue=queue,
                raw_body=raw,
                error_code="canonical_schema_failed",
                error_message="Canonical telemetry schema validation failed",
                trace={"reason": "canonical_schema", "errors": exc.errors()},
            )
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Canonical telemetry schema validation failed") from exc

        _enforce_signed_tenant_metadata(parsed, settings)
        _enforce_schema_version(parsed, settings)
        _enforce_operator_rate_limit(parsed.operator_id, settings)

        try:
            await queue.publish_ingest(
                payload={
                    **parsed.model_dump(mode="json"),
                    "payload": canonical_payload.model_dump(mode="json"),
                },
                trace={
                    "operator_id": parsed.operator_id,
                    "campaign_id": parsed.campaign_id,
                    "tenant_id": parsed.tenant_id,
                },
            )
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Telemetry queue publish failed") from exc

        audit_log.append_event(
            event_type="telemetry.accepted",
            actor="telemetry_gateway",
            details={
                "request_id": request_id,
                "tenant_id": parsed.tenant_id,
                "operator_id": parsed.operator_id,
                "campaign_id": parsed.campaign_id,
            },
        )
        return TelemetryIngestResponse(accepted=True, request_id=request_id)

    except HTTPException as exc:
        audit_log.append_event(
            event_type="telemetry.rejected",
            actor="telemetry_gateway",
            details={"request_id": request_id, "status_code": exc.status_code, "detail": str(exc.detail)},
        )
        raise


@app.post("/internal/v1/cognitive/execution-graph", status_code=status.HTTP_202_ACCEPTED)
async def ingest_execution_graph(request: Request) -> dict[str, Any]:
    request_id = str(uuid4())
    audit_log = get_tamper_audit_log()
    settings = _load_settings()
    raw = await request.body()
    _enforce_service_identity_auth(request, settings)
    if settings.require_payload_signature:
        _verify_signature(request, settings, raw)
    else:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unsigned telemetry is disabled by policy",
        )
    payload = ExecutionGraphMetadataRequest.model_validate_json(raw)
    _enforce_operator_tenant_pair(
        operator_id=payload.operator_id,
        tenant_id=payload.tenant_id,
        settings=settings,
    )
    _enforce_operator_rate_limit("graph:" + payload.operator_id, settings)
    with _graph_store_lock:
        tenant_records = _execution_graph_store.setdefault(payload.tenant_id, [])
        tenant_records.append(payload)
        if len(tenant_records) > 1000:
            del tenant_records[:-1000]
    audit_log.append_event(
        event_type="cognitive.graph.accepted",
        actor="telemetry_gateway",
        details={
            "request_id": request_id,
            "tenant_id": payload.tenant_id,
            "operator_id": payload.operator_id,
            "execution_fingerprint": payload.execution_fingerprint.lower(),
            "schema_version": payload.schema_version,
        },
    )
    return {
        "request_id": request_id,
        "status": "accepted",
        "data": {"graph_synced": True},
        "errors": [],
    }


@app.post("/internal/v1/cognitive/feedback/adjustments/query", status_code=status.HTTP_200_OK)
async def query_feedback_adjustments(request: Request) -> dict[str, Any]:
    request_id = str(uuid4())
    audit_log = get_tamper_audit_log()
    settings = _load_settings()
    raw = await request.body()
    _enforce_service_identity_auth(request, settings)
    if settings.require_payload_signature:
        _verify_signature(request, settings, raw)
    else:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unsigned telemetry is disabled by policy",
        )
    query = FeedbackQueryRequest.model_validate_json(raw)
    _enforce_operator_tenant_pair(
        operator_id=query.operator_id,
        tenant_id=query.tenant_id,
        settings=settings,
    )
    with _graph_store_lock:
        records = list(_execution_graph_store.get(query.tenant_id, []))
    selected = records[-query.limit :]
    adjustments = _build_feedback_adjustments(records=selected)
    data = [item.model_dump(mode="json") for item in adjustments]
    signed_at = int(time.time())
    response_nonce = secrets.token_urlsafe(18)
    signature = _feedback_signature(
        settings=settings,
        tenant_id=query.tenant_id,
        signed_at=signed_at,
        nonce=response_nonce,
        payload=data,
    )
    audit_log.append_event(
        event_type="cognitive.feedback.issued",
        actor="telemetry_gateway",
        details={
            "request_id": request_id,
            "tenant_id": query.tenant_id,
            "adjustment_count": len(data),
        },
    )
    return {
        "request_id": request_id,
        "status": "accepted",
        "data": data,
        "errors": [],
        "signature": signature,
        "signed_at": signed_at,
        "nonce": response_nonce,
        "schema_version": "feedback.response.v1",
    }


async def _publish_dead_letter_or_fail(
    *,
    queue: SecureQueuePublisher,
    raw_body: bytes,
    error_code: str,
    error_message: str,
    trace: dict[str, Any],
) -> None:
    try:
        await queue.publish_dlq(raw_body=raw_body, error_code=error_code, error_message=error_message, trace=trace)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Telemetry DLQ publish failed") from exc


# Test-only helper

def _clear_replay_cache_for_tests() -> None:
    _replay_guard.clear()
    _rate_limiter.clear()
    with _graph_store_lock:
        _execution_graph_store.clear()
    clear_memory_messages()
