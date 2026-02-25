<sub>Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue v4.0 Client REST API Manual

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
- `GET /api/v1/client/findings`
- `GET /api/v1/client/evidence`
- `GET /api/v1/client/reports`
- `GET /api/v1/client/risk-summary`
- `GET /api/v1/client/remediation-status`

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

## Compatibility Notes

- Existing operator logic in `vv.py` and `vv_core.py` is unchanged.
- REST API is intentionally read-only for customer safety and Phase 7 readiness.
