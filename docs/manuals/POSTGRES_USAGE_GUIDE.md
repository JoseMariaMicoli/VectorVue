<sub>Copyright (c) 2026 Jose Maria Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# PostgreSQL Usage Guide

This runbook covers day-to-day PostgreSQL operations for VectorVue deployments.

## 1. Start Services

```bash
docker compose up -d postgres redis vectorvue_app
```

## 2. Initialize Schema and Migrations

```bash
make pg-schema-bootstrap
make phase65-migrate
make phase7e-migrate
make phase8-migrate
make phase9-migrate
```

## 3. Seed Environment

```bash
make seed-clients
```

## 4. Health Validation

```bash
make api-smoke
docker compose ps
```

## 5. Backup

Example logical backup:

```bash
docker compose exec -T postgres pg_dump -U vectorvue -d vectorvue_db > backup.sql
```

## 6. Restore

```bash
docker compose exec -T postgres psql -U vectorvue -d vectorvue_db < backup.sql
```

## 7. Reset (Non-Production)

```bash
make pg-reset
```

## 8. Safety Notes

- Validate tenant scoping after any restore.
- Re-run smoke checks after migration or restore.
- Restrict direct database access to platform operators.

