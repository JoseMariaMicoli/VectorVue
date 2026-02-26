# SpectraStrike Integration API

> Status: Retired in Phase 0 Sprint 0.1. Public client API ingestion endpoints were removed.

## Base Path
No active runtime routes. Historical base path was:

- `/api/v1/integrations/spectrastrike/*` (removed)

## Authentication and Tenant Requirements
- Bearer JWT is required in `Authorization: Bearer <token>`.
- JWT must include `tenant_id` claim.
- All writes and status reads are isolated by the authenticated tenant.
- Cross-tenant access to ingest status returns `404 Request not found`.

## HTTPS and Signature Requirements
- If `VV_REQUIRE_HTTPS=1`, non-HTTPS requests are rejected.
- Optional request signature verification is enabled when `VV_SPECTRASTRIKE_SIGNATURE_SECRET` is configured.
- Signature headers:
  - `X-Signature`
  - `X-Timestamp`

## Idempotency
- `POST /events` supports `Idempotency-Key`.
- Replaying the same key with the same payload returns the original envelope and `X-Idempotent-Replay: true`.
- Reusing the same key with a different payload returns `409 idempotency_conflict`.

## Endpoints

### `POST /api/v1/integrations/spectrastrike/events`
Ingest one telemetry event.

### `POST /api/v1/integrations/spectrastrike/events/batch`
Ingest telemetry events in batch.
- Enforces `VV_SPECTRASTRIKE_MAX_BATCH_SIZE`.
- Returns per-item partial failure details.

### `POST /api/v1/integrations/spectrastrike/findings`
Ingest one finding.
- Severity values are normalized (`informational` -> `info`, `med` -> `medium`, etc).
- Emits tenant-scoped audit event on acceptance.

### `POST /api/v1/integrations/spectrastrike/findings/batch`
Ingest findings in batch with partial failure semantics.

### `GET /api/v1/integrations/spectrastrike/ingest/status/{request_id}`
Fetch processing status and failure references for one ingest request.

## Response Envelope
All SpectraStrike endpoints return:
- `request_id`
- `status` (`accepted|partial|failed|replayed`)
- `data`
- `errors[]`
- optional `signature`

## Error Model
Common error codes:
- `validation_failed`
- `batch_too_large`
- `idempotency_conflict`
- HTTP auth errors from tenant JWT guard (`401`).

Validation errors return a structured envelope with `status=failed` and `errors[]` populated.

## Rate Limits
- Router reuses existing client API rate limiter (`client_rate_limit`).
- Event/finding batches also emit batch-size metric hooks.

## Audit and Observability
Audit entries are emitted for:
- auth failures
- schema rejection
- accepted ingestion
- batch partial failures

Structured logs include:
- `request_id`
- `tenant_id`
- `endpoint`
- `outcome`

Metric hooks emitted:
- `ingest_total`
- `ingest_failed`
- `auth_failed`
- `validation_failed`
- `batch_size`
