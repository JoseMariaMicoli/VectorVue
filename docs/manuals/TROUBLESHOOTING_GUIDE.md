<sub>Copyright (c) 2026 Jose Maria Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue Troubleshooting Guide

This guide covers high-frequency operational issues in production and demo environments.

## 1. Deployment Fails (`make deploy`)

Checks:

1. Verify Docker daemon is running.
2. Verify Compose can start postgres/redis.
3. Check container logs:

```bash
docker compose logs --tail=120 vectorvue_app
docker compose logs --tail=120 vectorvue_postgres
```

## 2. Migration Errors

If schema errors appear during migration:

1. Verify migration order:

```bash
make pg-schema-bootstrap
make phase65-migrate
make phase7e-migrate
make phase8-migrate
make phase9-migrate
```

2. Recheck PostgreSQL health and rerun failing step.

## 3. Portal Login Fails

1. Confirm tenant URL is correct.
2. Confirm seeded credentials are current.
3. Rerun demo seed in non-production:

```bash
make seed-clients
```

## 4. Worker Restart Loops

1. Inspect worker logs:

```bash
docker compose logs --tail=120 vectorvue_ml_worker
docker compose logs --tail=120 vectorvue_compliance_observation_worker
docker compose logs --tail=120 vectorvue_compliance_daily_worker
```

2. Rebuild and recreate relevant services:

```bash
docker compose build vectorvue_app
docker compose up -d --force-recreate vectorvue_app vectorvue_ml_worker vectorvue_compliance_observation_worker vectorvue_compliance_daily_worker
```

## 5. Compliance Endpoint Errors

1. Verify compliance migration applied: `make phase9-migrate`.
2. Verify tenant-authenticated token and role.
3. Verify compliance workers are running.

## 6. Data Scope or Tenant Mismatch

1. Stop integration workflow immediately.
2. Capture request/tenant identifiers.
3. Escalate to platform admin for scope verification.

## 7. Slow Responses

1. Check postgres and redis health.
2. Check worker backlog and queue processing.
3. Review app logs for timeouts and heavy queries.

## 8. Support Handoff Template

Include:

- command run
- timestamp
- service logs snippet
- tenant/environment impacted
- expected vs actual behavior

