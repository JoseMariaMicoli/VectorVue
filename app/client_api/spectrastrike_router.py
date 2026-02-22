from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.client_api.dependencies import client_rate_limit, get_db
from app.client_api.spectrastrike_schemas import (
    EnvelopeSignature,
    IntegrationEnvelope,
    IntegrationError,
    SpectraStrikeBatchItemResult,
    SpectraStrikeBatchOut,
    SpectraStrikeFinding,
    SpectraStrikeIngestSummary,
    SpectraStrikeSingleEventOut,
    SpectraStrikeSingleFindingOut,
    SpectraStrikeStatusResponse,
    SpectraStrikeTelemetryEvent,
)
from app.client_api.spectrastrike_service import SpectraStrikeService, deterministic_external_id
from security.tenant_auth import get_current_tenant


logger = logging.getLogger("vectorvue.integrations.spectrastrike")
_metrics: defaultdict[str, int] = defaultdict(int)

router = APIRouter(
    prefix="/api/v1/integrations/spectrastrike",
    tags=["integrations-spectrastrike"],
    dependencies=[Depends(client_rate_limit)],
)


def _metric_inc(metric: str, count: int = 1) -> None:
    _metrics[metric] += count


def _current_ts() -> datetime:
    return datetime.now(timezone.utc)


def _request_id(request: Request) -> str:
    incoming = request.headers.get("X-Request-ID", "").strip()
    return incoming or str(uuid4())


def _endpoint_path(request: Request) -> str:
    return request.url.path


def _max_batch_size() -> int:
    raw = os.environ.get("VV_SPECTRASTRIKE_MAX_BATCH_SIZE", "250").strip()
    try:
        parsed = int(raw)
    except ValueError:
        parsed = 250
    return max(1, min(parsed, 1000))


def _https_required() -> bool:
    return os.environ.get("VV_REQUIRE_HTTPS", "0").strip() == "1"


def _verify_https(request: Request) -> None:
    if not _https_required():
        return
    forwarded = (request.headers.get("X-Forwarded-Proto", "") or "").split(",")[0].strip().lower()
    if request.url.scheme.lower() != "https" and forwarded != "https":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="HTTPS is required")


def _signature_secret() -> str | None:
    value = os.environ.get("VV_SPECTRASTRIKE_SIGNATURE_SECRET", "").strip()
    return value or None


def _verify_optional_signature(request: Request, raw_body: bytes) -> None:
    secret = _signature_secret()
    if not secret:
        return

    header_sig = request.headers.get("X-Signature", "").strip()
    header_ts = request.headers.get("X-Timestamp", "").strip()
    if not header_sig or not header_ts:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing request signature headers")

    max_skew = int(os.environ.get("VV_SPECTRASTRIKE_SIGNATURE_MAX_SKEW_SECONDS", "300"))
    try:
        ts_int = int(header_ts)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-Timestamp") from exc

    if abs(int(time.time()) - ts_int) > max_skew:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Signature timestamp out of range")

    payload = f"{header_ts}.{raw_body.decode('utf-8')}".encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, header_sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid request signature")


def _canonical_hash(data: Any) -> str:
    raw = json.dumps(data, default=str, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _signing_key() -> str | None:
    value = os.environ.get("VV_COMPLIANCE_SIGNING_KEY", "").strip()
    return value or None


def _sign_envelope(path: str, tenant_id: str, data: Any) -> EnvelopeSignature | None:
    key = _signing_key()
    if not key:
        return None
    signed_at = _current_ts().isoformat()
    canon = json.dumps(data, sort_keys=True, default=str, separators=(",", ":"))
    raw = f"{path}|{tenant_id}|{signed_at}|{canon}"
    signature = hmac.new(key.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    return EnvelopeSignature(algorithm="hmac-sha256", signed_at=signed_at, signature=signature)


def get_spectrastrike_service(db: Session = Depends(get_db)) -> SpectraStrikeService:
    return SpectraStrikeService(db)


def _error_response(
    *,
    request_id: str,
    status_value: Literal["accepted", "partial", "failed", "replayed"],
    error_code: str,
    message: str,
    http_status: int,
) -> JSONResponse:
    envelope = IntegrationEnvelope[dict[str, Any]](
        request_id=request_id,
        status=status_value,
        data={},
        errors=[IntegrationError(code=error_code, message=message)],
        signature=None,
    )
    return JSONResponse(status_code=http_status, content=envelope.model_dump(mode="json"))


def _tenant_or_reject(request: Request, service: SpectraStrikeService, request_id: str) -> str:
    try:
        return str(get_current_tenant(request))
    except HTTPException as exc:
        _metric_inc("auth_failed")
        service.write_audit_event(
            actor="SYSTEM",
            action="SPECTRASTRIKE_AUTH_FAILURE",
            target_type="spectrastrike_request",
            target_id=request_id,
            new_value_hash=hashlib.sha256(str(exc.detail).encode("utf-8")).hexdigest(),
        )
        raise


def _log_outcome(
    *,
    endpoint: str,
    tenant_id: str,
    request_id: str,
    outcome: str,
    extra: dict[str, Any] | None = None,
) -> None:
    payload = {
        "endpoint": endpoint,
        "tenant_id": tenant_id,
        "request_id": request_id,
        "outcome": outcome,
    }
    if extra:
        payload.update(extra)
    logger.info("spectrastrike_ingest", extra=payload)


async def _read_json_body(request: Request) -> Any:
    raw = await request.body()
    if not raw:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Request body is required")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid JSON payload") from exc


@router.post(
    "/events",
    response_model=IntegrationEnvelope[SpectraStrikeSingleEventOut],
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_event(
    request: Request,
    service: SpectraStrikeService = Depends(get_spectrastrike_service),
):
    request_id = _request_id(request)
    endpoint = _endpoint_path(request)
    _verify_https(request)
    raw_body = await request.body()
    _verify_optional_signature(request, raw_body)

    tenant_id = _tenant_or_reject(request, service, request_id)

    idempotency_key = request.headers.get("Idempotency-Key", "").strip() or None
    try:
        request_body = await _read_json_body(request)
    except HTTPException as exc:
        _metric_inc("validation_failed")
        service.write_audit_event(
            actor=tenant_id,
            action="SPECTRASTRIKE_SCHEMA_REJECTED",
            target_type="spectrastrike_event",
            target_id=request_id,
            new_value_hash=hashlib.sha256(str(exc.detail).encode("utf-8")).hexdigest(),
        )
        return _error_response(
            request_id=request_id,
            status_value="failed",
            error_code="validation_failed",
            message=str(exc.detail),
            http_status=exc.status_code,
        )
    request_hash = _canonical_hash(request_body)

    if idempotency_key:
        replay = service.fetch_idempotent_response(
            tenant_id=tenant_id,
            endpoint=endpoint,
            idempotency_key=idempotency_key,
        )
        if replay:
            if replay["request_hash"] != request_hash:
                service.write_audit_event(
                    actor=tenant_id,
                    action="SPECTRASTRIKE_IDEMPOTENCY_CONFLICT",
                    target_type="spectrastrike_request",
                    target_id=request_id,
                    new_value_hash=hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest(),
                )
                return _error_response(
                    request_id=request_id,
                    status_value="failed",
                    error_code="idempotency_conflict",
                    message="Idempotency-Key reuse with different payload",
                    http_status=status.HTTP_409_CONFLICT,
                )
            replay_response = JSONResponse(status_code=replay["status_code"], content=replay["response_json"])
            replay_response.headers["X-Idempotent-Replay"] = "true"
            _metric_inc("ingest_total")
            return replay_response

    try:
        payload = SpectraStrikeTelemetryEvent.model_validate(request_body)
    except ValidationError as exc:
        _metric_inc("validation_failed")
        service.write_audit_event(
            actor=tenant_id,
            action="SPECTRASTRIKE_SCHEMA_REJECTED",
            target_type="spectrastrike_event",
            target_id=request_id,
            new_value_hash=hashlib.sha256(str(exc).encode("utf-8")).hexdigest(),
        )
        return _error_response(
            request_id=request_id,
            status_value="failed",
            error_code="validation_failed",
            message="Payload validation failed",
            http_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    item = payload.model_dump(mode="python")
    event_uid = payload.event_id or deterministic_external_id(
        "evt",
        item,
        ["source_system", "event_type", "occurred_at", "asset_ref", "message"],
    )
    service.record_event(tenant_id=tenant_id, request_id=request_id, event_uid=event_uid, payload=item)
    service.record_ingest_status(
        request_id=request_id,
        tenant_id=tenant_id,
        endpoint=endpoint,
        status="accepted",
        total_items=1,
        accepted_items=1,
        failed_items=0,
        failed_references=[],
        idempotency_key=idempotency_key,
    )
    service.write_audit_event(
        actor=tenant_id,
        action="SPECTRASTRIKE_INGEST_ACCEPTED",
        target_type="spectrastrike_event",
        target_id=event_uid,
    )

    payload_out = SpectraStrikeSingleEventOut(event_id=event_uid)
    envelope = IntegrationEnvelope[SpectraStrikeSingleEventOut](
        request_id=request_id,
        status="accepted",
        data=payload_out,
        errors=[],
        signature=_sign_envelope(endpoint, tenant_id, payload_out.model_dump(mode="python")),
    )
    envelope_data = envelope.model_dump(mode="json")

    if idempotency_key:
        service.store_idempotent_response(
            tenant_id=tenant_id,
            endpoint=endpoint,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            response_json=envelope_data,
            status_code=status.HTTP_202_ACCEPTED,
        )

    _metric_inc("ingest_total")
    _log_outcome(endpoint=endpoint, tenant_id=tenant_id, request_id=request_id, outcome="accepted")
    return envelope


@router.post(
    "/events/batch",
    response_model=IntegrationEnvelope[SpectraStrikeBatchOut],
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_events_batch(
    request: Request,
    service: SpectraStrikeService = Depends(get_spectrastrike_service),
):
    request_id = _request_id(request)
    endpoint = _endpoint_path(request)
    _verify_https(request)
    raw_body = await request.body()
    _verify_optional_signature(request, raw_body)
    tenant_id = _tenant_or_reject(request, service, request_id)

    try:
        body = await _read_json_body(request)
    except HTTPException as exc:
        _metric_inc("validation_failed")
        service.write_audit_event(
            actor=tenant_id,
            action="SPECTRASTRIKE_SCHEMA_REJECTED",
            target_type="spectrastrike_events_batch",
            target_id=request_id,
            new_value_hash=hashlib.sha256(str(exc.detail).encode("utf-8")).hexdigest(),
        )
        return _error_response(
            request_id=request_id,
            status_value="failed",
            error_code="validation_failed",
            message=str(exc.detail),
            http_status=exc.status_code,
        )

    if not isinstance(body, list):
        return _error_response(
            request_id=request_id,
            status_value="failed",
            error_code="validation_failed",
            message="Batch payload must be an array",
            http_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    max_batch = _max_batch_size()
    if len(body) > max_batch:
        _metric_inc("validation_failed")
        return _error_response(
            request_id=request_id,
            status_value="failed",
            error_code="batch_too_large",
            message=f"Batch size exceeds configured maximum ({max_batch})",
            http_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    _metric_inc("batch_size", len(body))

    results: list[SpectraStrikeBatchItemResult] = []
    accepted = 0
    for idx, raw in enumerate(body):
        try:
            payload = SpectraStrikeTelemetryEvent.model_validate(raw)
            item = payload.model_dump(mode="python")
            event_uid = payload.event_id or deterministic_external_id(
                "evt",
                item,
                ["source_system", "event_type", "occurred_at", "asset_ref", "message"],
            )
            service.record_event(tenant_id=tenant_id, request_id=request_id, event_uid=event_uid, payload=item)
            accepted += 1
            results.append(SpectraStrikeBatchItemResult(index=idx, item_id=event_uid, status="accepted"))
        except ValidationError as exc:
            _metric_inc("validation_failed")
            results.append(
                SpectraStrikeBatchItemResult(
                    index=idx,
                    item_id=None,
                    status="failed",
                    error_code="validation_failed",
                    error_message=str(exc.errors()[0].get("msg", "validation error")),
                )
            )
        except Exception:
            _metric_inc("ingest_failed")
            results.append(
                SpectraStrikeBatchItemResult(
                    index=idx,
                    item_id=None,
                    status="failed",
                    error_code="ingest_failed",
                    error_message="Failed to persist event",
                )
            )

    failed = len(body) - accepted
    status_value: Literal["accepted", "partial", "failed", "replayed"]
    if failed == 0:
        status_value = "accepted"
    elif accepted == 0:
        status_value = "failed"
    else:
        status_value = "partial"

    failed_refs = [item for item in results if item.status == "failed"]
    service.record_ingest_status(
        request_id=request_id,
        tenant_id=tenant_id,
        endpoint=endpoint,
        status=status_value,
        total_items=len(body),
        accepted_items=accepted,
        failed_items=failed,
        failed_references=failed_refs,
        idempotency_key=request.headers.get("Idempotency-Key", "").strip() or None,
    )

    action = "SPECTRASTRIKE_BATCH_PARTIAL_FAILURE" if status_value == "partial" else "SPECTRASTRIKE_INGEST_ACCEPTED"
    service.write_audit_event(
        actor=tenant_id,
        action=action,
        target_type="spectrastrike_events_batch",
        target_id=request_id,
    )

    summary = SpectraStrikeIngestSummary(total=len(body), accepted=accepted, failed=failed)
    data = SpectraStrikeBatchOut(summary=summary, results=results)
    envelope = IntegrationEnvelope[SpectraStrikeBatchOut](
        request_id=request_id,
        status=status_value,
        data=data,
        errors=[],
        signature=_sign_envelope(endpoint, tenant_id, data.model_dump(mode="python")),
    )
    _metric_inc("ingest_total")
    if failed:
        _metric_inc("ingest_failed", failed)
    _log_outcome(
        endpoint=endpoint,
        tenant_id=tenant_id,
        request_id=request_id,
        outcome=status_value,
        extra={"accepted": accepted, "failed": failed},
    )
    return envelope


@router.post(
    "/findings",
    response_model=IntegrationEnvelope[SpectraStrikeSingleFindingOut],
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_finding(
    request: Request,
    service: SpectraStrikeService = Depends(get_spectrastrike_service),
):
    request_id = _request_id(request)
    endpoint = _endpoint_path(request)
    _verify_https(request)
    raw_body = await request.body()
    _verify_optional_signature(request, raw_body)

    tenant_id = _tenant_or_reject(request, service, request_id)
    try:
        body = await _read_json_body(request)
        payload = SpectraStrikeFinding.model_validate(body)
    except HTTPException as exc:
        _metric_inc("validation_failed")
        service.write_audit_event(
            actor=tenant_id,
            action="SPECTRASTRIKE_SCHEMA_REJECTED",
            target_type="spectrastrike_finding",
            target_id=request_id,
            new_value_hash=hashlib.sha256(str(exc.detail).encode("utf-8")).hexdigest(),
        )
        return _error_response(
            request_id=request_id,
            status_value="failed",
            error_code="validation_failed",
            message=str(exc.detail),
            http_status=exc.status_code,
        )
    except ValidationError as exc:
        _metric_inc("validation_failed")
        service.write_audit_event(
            actor=tenant_id,
            action="SPECTRASTRIKE_SCHEMA_REJECTED",
            target_type="spectrastrike_finding",
            target_id=request_id,
            new_value_hash=hashlib.sha256(str(exc).encode("utf-8")).hexdigest(),
        )
        return _error_response(
            request_id=request_id,
            status_value="failed",
            error_code="validation_failed",
            message="Payload validation failed",
            http_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    item = payload.model_dump(mode="python")
    finding_uid = payload.finding_id or deterministic_external_id(
        "fnd",
        item,
        ["title", "severity", "first_seen", "asset_ref"],
    )
    service.record_finding(tenant_id=tenant_id, request_id=request_id, finding_uid=finding_uid, payload=item)
    service.record_ingest_status(
        request_id=request_id,
        tenant_id=tenant_id,
        endpoint=endpoint,
        status="accepted",
        total_items=1,
        accepted_items=1,
        failed_items=0,
        failed_references=[],
        idempotency_key=request.headers.get("Idempotency-Key", "").strip() or None,
    )
    service.write_audit_event(
        actor=tenant_id,
        action="SPECTRASTRIKE_INGEST_ACCEPTED",
        target_type="spectrastrike_finding",
        target_id=finding_uid,
    )

    data = SpectraStrikeSingleFindingOut(finding_id=finding_uid)
    envelope = IntegrationEnvelope[SpectraStrikeSingleFindingOut](
        request_id=request_id,
        status="accepted",
        data=data,
        errors=[],
        signature=_sign_envelope(endpoint, tenant_id, data.model_dump(mode="python")),
    )
    _metric_inc("ingest_total")
    _log_outcome(endpoint=endpoint, tenant_id=tenant_id, request_id=request_id, outcome="accepted")
    return envelope


@router.post(
    "/findings/batch",
    response_model=IntegrationEnvelope[SpectraStrikeBatchOut],
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_findings_batch(
    request: Request,
    service: SpectraStrikeService = Depends(get_spectrastrike_service),
):
    request_id = _request_id(request)
    endpoint = _endpoint_path(request)
    _verify_https(request)
    raw_body = await request.body()
    _verify_optional_signature(request, raw_body)
    tenant_id = _tenant_or_reject(request, service, request_id)

    try:
        body = await _read_json_body(request)
    except HTTPException as exc:
        _metric_inc("validation_failed")
        service.write_audit_event(
            actor=tenant_id,
            action="SPECTRASTRIKE_SCHEMA_REJECTED",
            target_type="spectrastrike_findings_batch",
            target_id=request_id,
            new_value_hash=hashlib.sha256(str(exc.detail).encode("utf-8")).hexdigest(),
        )
        return _error_response(
            request_id=request_id,
            status_value="failed",
            error_code="validation_failed",
            message=str(exc.detail),
            http_status=exc.status_code,
        )
    if not isinstance(body, list):
        return _error_response(
            request_id=request_id,
            status_value="failed",
            error_code="validation_failed",
            message="Batch payload must be an array",
            http_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    max_batch = _max_batch_size()
    if len(body) > max_batch:
        _metric_inc("validation_failed")
        return _error_response(
            request_id=request_id,
            status_value="failed",
            error_code="batch_too_large",
            message=f"Batch size exceeds configured maximum ({max_batch})",
            http_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    _metric_inc("batch_size", len(body))

    results: list[SpectraStrikeBatchItemResult] = []
    accepted = 0

    for idx, raw in enumerate(body):
        try:
            payload = SpectraStrikeFinding.model_validate(raw)
            item = payload.model_dump(mode="python")
            finding_uid = payload.finding_id or deterministic_external_id(
                "fnd",
                item,
                ["title", "severity", "first_seen", "asset_ref"],
            )
            service.record_finding(tenant_id=tenant_id, request_id=request_id, finding_uid=finding_uid, payload=item)
            accepted += 1
            results.append(SpectraStrikeBatchItemResult(index=idx, item_id=finding_uid, status="accepted"))
        except ValidationError as exc:
            _metric_inc("validation_failed")
            results.append(
                SpectraStrikeBatchItemResult(
                    index=idx,
                    item_id=None,
                    status="failed",
                    error_code="validation_failed",
                    error_message=str(exc.errors()[0].get("msg", "validation error")),
                )
            )
        except Exception:
            _metric_inc("ingest_failed")
            results.append(
                SpectraStrikeBatchItemResult(
                    index=idx,
                    item_id=None,
                    status="failed",
                    error_code="ingest_failed",
                    error_message="Failed to persist finding",
                )
            )

    failed = len(body) - accepted
    if failed == 0:
        status_value: Literal["accepted", "partial", "failed", "replayed"] = "accepted"
    elif accepted == 0:
        status_value = "failed"
    else:
        status_value = "partial"

    failed_refs = [item for item in results if item.status == "failed"]
    service.record_ingest_status(
        request_id=request_id,
        tenant_id=tenant_id,
        endpoint=endpoint,
        status=status_value,
        total_items=len(body),
        accepted_items=accepted,
        failed_items=failed,
        failed_references=failed_refs,
        idempotency_key=request.headers.get("Idempotency-Key", "").strip() or None,
    )
    action = "SPECTRASTRIKE_BATCH_PARTIAL_FAILURE" if status_value == "partial" else "SPECTRASTRIKE_INGEST_ACCEPTED"
    service.write_audit_event(
        actor=tenant_id,
        action=action,
        target_type="spectrastrike_findings_batch",
        target_id=request_id,
    )

    summary = SpectraStrikeIngestSummary(total=len(body), accepted=accepted, failed=failed)
    data = SpectraStrikeBatchOut(summary=summary, results=results)
    envelope = IntegrationEnvelope[SpectraStrikeBatchOut](
        request_id=request_id,
        status=status_value,
        data=data,
        errors=[],
        signature=_sign_envelope(endpoint, tenant_id, data.model_dump(mode="python")),
    )
    _metric_inc("ingest_total")
    if failed:
        _metric_inc("ingest_failed", failed)
    _log_outcome(
        endpoint=endpoint,
        tenant_id=tenant_id,
        request_id=request_id,
        outcome=status_value,
        extra={"accepted": accepted, "failed": failed},
    )
    return envelope


@router.get(
    "/ingest/status/{request_id}",
    response_model=IntegrationEnvelope[SpectraStrikeStatusResponse],
)
def ingest_status(
    request_id: str,
    request: Request,
    service: SpectraStrikeService = Depends(get_spectrastrike_service),
):
    resolved_request_id = _request_id(request)
    tenant_id = _tenant_or_reject(request, service, resolved_request_id)

    row = service.get_ingest_status(request_id=request_id, tenant_id=tenant_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")

    failed_items = [SpectraStrikeBatchItemResult.model_validate(item) for item in row["failed_references"]]
    status_payload = SpectraStrikeStatusResponse(
        request_id=row["request_id"],
        status=row["status"],
        endpoint=row["endpoint"],
        counts=SpectraStrikeIngestSummary(
            total=row["total_items"],
            accepted=row["accepted_items"],
            failed=row["failed_items"],
        ),
        failed_items=failed_items,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )

    return IntegrationEnvelope[SpectraStrikeStatusResponse](
        request_id=resolved_request_id,
        status="accepted",
        data=status_payload,
        errors=[],
        signature=_sign_envelope(
            "/api/v1/integrations/spectrastrike/ingest/status/{request_id}",
            tenant_id,
            status_payload.model_dump(mode="python"),
        ),
    )
