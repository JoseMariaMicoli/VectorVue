<sub>Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue v4.1 Client REST API Manual

## Scope

This manual is a practical runbook for teams integrating with the client API.
It focuses on exact operational steps, request patterns, and safe usage.

## Runtime Components

- `vectorvue_app`: FastAPI service (`vv_client_api.py`)
- `vectorvue_runtime`: RuntimeExecutor worker (`vv_core_postgres.py --mode service`)
- `postgres`: primary datastore
- `redis`: runtime coordination/cache
- `nginx`: TLS termination and reverse proxy

## Security Model (What Matters in Practice)

1. Tenant ID is mandatory from JWT claim: `tenant_id`.
2. Data access is read-only for client data endpoints.
3. Client-safe schemas sanitize internal fields (no exploit payloads, no operator notes).
4. Telemetry endpoint only stores security workflow behavior, not marketing tracking.

## Base URL and Authentication

- Base URL (default local): `https://127.0.0.1`
- Auth endpoint: `POST /api/v1/client/auth/login`
- Auth mechanism for subsequent calls: `Authorization: Bearer <access_token>`

### Step 1: Login and Obtain Token

```bash
curl -k -X POST https://127.0.0.1/api/v1/client/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "acme_viewer",
    "password": "AcmeView3r!",
    "tenant_id": "10000000-0000-0000-0000-000000000001"
  }'
```

Save `access_token` from the response.

### Step 2: Use Token on API Calls

```bash
TOKEN="<paste_access_token>"
curl -k https://127.0.0.1/api/v1/client/findings?page=1&page_size=25 \
  -H "Authorization: Bearer $TOKEN"
```

## Endpoint Catalog

- `GET /healthz`
- `POST /api/v1/client/auth/login`
- `GET /api/v1/client/findings`
- `GET /api/v1/client/findings/{finding_id}`
- `GET /api/v1/client/evidence`
- `GET /api/v1/client/evidence/{finding_id}`
- `GET /api/v1/client/reports`
- `GET /api/v1/client/reports/{report_id}/download`
- `GET /api/v1/client/risk`
- `GET /api/v1/client/risk-summary`
- `GET /api/v1/client/risk-trend`
- `GET /api/v1/client/remediation`
- `GET /api/v1/client/remediation-status`
- `GET /api/v1/client/theme`
- `GET /api/v1/client/theme/logo`
- `POST /api/v1/client/events`
- `GET /ml/client/security-score`
- `GET /ml/client/risk`
- `GET /ml/client/detection-gaps`
- `GET /ml/client/anomalies`
- `POST /ml/client/simulate`
- `GET /ml/operator/suggestions/{campaign_id}`

## Common Workflows (Step-by-Step)

### A) Fetch Findings + Detail + Evidence
1. Call `GET /api/v1/client/findings`.
2. Select a finding ID.
3. Call `GET /api/v1/client/findings/{finding_id}`.
4. Call `GET /api/v1/client/evidence/{finding_id}`.

### B) Fetch Risk Dashboard Inputs
1. Call `GET /api/v1/client/risk`.
2. Call `GET /api/v1/client/risk-trend`.
3. Call `GET /api/v1/client/remediation-status`.

### C) Fetch Reports and Download
1. Call `GET /api/v1/client/reports`.
2. Select a report ID.
3. Call `GET /api/v1/client/reports/{report_id}/download`.

### D) Submit Usage Telemetry Event
Use for defensive intelligence metrics only.

```bash
curl -k -X POST https://127.0.0.1/api/v1/client/events \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "event_type": "FINDING_VIEWED",
    "object_type": "finding",
    "object_id": "123",
    "severity": "critical",
    "metadata_json": {"source":"portal"}
  }'
```

Expected response: `202 Accepted`.

### E) Fetch Commercial Analytics (Phase 8)
1. Call `GET /ml/client/security-score`.
2. Call `GET /ml/client/risk`.
3. Call `GET /ml/client/detection-gaps`.
4. Call `GET /ml/client/anomalies`.
5. Optionally call `POST /ml/client/simulate` for what-if defense projection.

Response contract for all client analytics endpoints:
- `score`
- `confidence`
- `explanation`
- `model_version`
- `generated_at`

## Deployment Commands

```bash
make deploy
make phase65-migrate
make phase7e-migrate
make phase8-migrate
make api-smoke
```

## Local Validation Flow

1. Start stack: `make api-up`
2. Apply migration: `make phase65-migrate`
3. Apply telemetry migration: `make phase7e-migrate`
4. Apply analytics migration: `make phase8-migrate`
5. Verify API: `make api-smoke`
6. Tail runtime logs: `make api-logs`
7. Seed demo multi-tenant data: `make seed-clients`

## Telemetry Event Reference

Supported `event_type` values:
- `FINDING_VIEWED`
- `FINDING_ACKNOWLEDGED`
- `REMEDIATION_OPENED`
- `REMEDIATION_COMPLETED`
- `REPORT_DOWNLOADED`
- `DASHBOARD_VIEWED`

Supported `object_type` values:
- `finding`
- `report`
- `dashboard`
- `remediation`

Privacy constraints:
- no IP storage
- no user-agent storage
- no keystroke storage

Analytics reference:
- `docs/manuals/PHASE7E_TELEMETRY_QUERIES.sql`

## Compatibility Notes

- Existing operator logic in `vv.py` and `vv_core.py` is unchanged.
- Client API is intentionally read-only except telemetry event ingestion.
