<sub>Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue v4.1 Client REST API Manual

## Scope

Phase 6.5 introduces a tenant-isolated, read-only REST API for customer-safe access. This API is additive and does not change operator TUI workflows.

## Runtime Components

- `vectorvue_app`: FastAPI service (`vv_client_api.py`)
- `vectorvue_runtime`: RuntimeExecutor worker (`vv_core_postgres.py --mode service`)
- `postgres`: primary datastore
- `redis`: runtime coordination/cache
- `nginx`: TLS termination and reverse proxy

## Security Model

1. Tenant ID is mandatory from JWT claim: `tenant_id`.
2. Data access is read-only for public API endpoints.
3. Client-safe schemas sanitize internal fields (no exploit payloads, no operator notes).
4. Migration enforces `tenant_id` boundaries on key tenant-scoped tables.

## Endpoints

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

## Deployment Commands

```bash
make deploy
make phase65-migrate
make api-smoke
```

## Local Test Flow

1. Start stack: `make api-up`
2. Apply migration: `make phase65-migrate`
3. Verify API: `make api-smoke`
4. Tail runtime logs: `make api-logs`
5. Seed demo multi-tenant data: `make seed-clients`

## Compatibility Notes

- Existing operator logic in `vv.py` and `vv_core.py` is unchanged.
- REST API is intentionally read-only for customer safety and Phase 7 readiness.
