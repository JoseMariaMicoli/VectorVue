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

"""Internal-only telemetry gateway with mTLS identity + cert pinning."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from threading import Lock
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field, ValidationError
from redis import Redis
from redis.exceptions import RedisError
from services.telemetry_gateway.queue import SecureQueuePublisher, clear_memory_messages, load_queue_settings


HEX_64_RE = re.compile(r"^[a-fA-F0-9]{64}$")
B64_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9+/=]+$")


class TelemetryIngestRequest(BaseModel):
    operator_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=128)
    execution_hash: str = Field(min_length=64, max_length=64)
    timestamp: int
    nonce: str = Field(min_length=12, max_length=128)
    payload: dict[str, Any]


class TelemetryIngestResponse(BaseModel):
    accepted: bool
    request_id: str


@dataclass(frozen=True)
class GatewaySettings:
    require_mtls: bool
    pinned_client_cert_sha256: str
    require_payload_signature: bool
    spectrastrike_ed25519_public_key_b64: str
    allowed_clock_skew_seconds: int
    nonce_ttl_seconds: int
    nonce_backend: str
    redis_url: str
    rate_limit_per_minute: int
    rate_limit_backend: str
    queue_backend: str


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
    pinned = os.environ.get("VV_TG_SPECTRASTRIKE_CERT_SHA256", "").strip().lower()
    if not HEX_64_RE.fullmatch(pinned):
        raise RuntimeError("VV_TG_SPECTRASTRIKE_CERT_SHA256 must be a 64-char sha256 hex fingerprint")

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

    return GatewaySettings(
        require_mtls=_parse_bool("VV_TG_REQUIRE_MTLS", "1"),
        pinned_client_cert_sha256=pinned,
        require_payload_signature=_parse_bool("VV_TG_REQUIRE_PAYLOAD_SIGNATURE", "1"),
        spectrastrike_ed25519_public_key_b64=pubkey,
        allowed_clock_skew_seconds=skew,
        nonce_ttl_seconds=nonce_ttl,
        nonce_backend=os.environ.get("VV_TG_NONCE_BACKEND", "redis").strip().lower(),
        redis_url=os.environ.get("VV_TG_REDIS_URL", "").strip(),
        rate_limit_per_minute=rate_limit_per_min,
        rate_limit_backend=os.environ.get("VV_TG_RATE_LIMIT_BACKEND", "redis").strip().lower(),
        queue_backend=os.environ.get("VV_TG_QUEUE_BACKEND", "nats").strip().lower(),
    )


def _require_header(request: Request, header: str) -> str:
    value = request.headers.get(header, "").strip()
    if not value:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Missing required header: {header}")
    return value


def _enforce_mtls_and_pinning(request: Request, settings: GatewaySettings) -> str:
    cert_fp = _require_header(request, "X-Client-Cert-Sha256").lower()
    if not HEX_64_RE.fullmatch(cert_fp):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client certificate fingerprint format")
    if settings.require_mtls and cert_fp != settings.pinned_client_cert_sha256:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Client certificate fingerprint mismatch")
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


app = FastAPI(title="VectorVue Telemetry Gateway", version="2.1.0")


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    try:
        settings = _load_settings()
    except RuntimeError as exc:
        return {"status": "degraded", "detail": str(exc)}

    return {
        "status": "healthy",
        "require_mtls": settings.require_mtls,
        "require_payload_signature": settings.require_payload_signature,
        "nonce_ttl_seconds": settings.nonce_ttl_seconds,
        "nonce_backend": settings.nonce_backend,
        "rate_limit_per_minute": settings.rate_limit_per_minute,
        "queue_backend": settings.queue_backend,
    }


@app.post("/internal/v1/telemetry", response_model=TelemetryIngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_telemetry(request: Request) -> TelemetryIngestResponse:
    try:
        settings = _load_settings()
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    queue_settings = load_queue_settings()
    queue = SecureQueuePublisher(queue_settings)

    _enforce_mtls_and_pinning(request, settings)

    raw = await request.body()
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
    _enforce_operator_rate_limit(parsed.operator_id, settings)

    try:
        await queue.publish_ingest(
            payload=parsed.model_dump(mode="json"),
            trace={"operator_id": parsed.operator_id, "campaign_id": parsed.campaign_id},
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Telemetry queue publish failed") from exc

    return TelemetryIngestResponse(accepted=True, request_id=str(uuid4()))


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
    clear_memory_messages()
