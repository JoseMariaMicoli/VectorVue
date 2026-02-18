<sub>Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue PostgreSQL Usage Guide (v4.0)

## Table of Contents

1. [Scope](#scope)
2. [Prerequisites](#prerequisites)
3. [Start Services](#start-services)
4. [Initialize Database](#initialize-database)
5. [Run VectorVue on PostgreSQL](#run-vectorvue-on-postgresql)
6. [Seed and Reset Operations](#seed-and-reset-operations)
7. [Validation and Testing](#validation-and-testing)
8. [Backup and Restore](#backup-and-restore)
9. [Troubleshooting](#troubleshooting)
10. [Operational Safety Notes](#operational-safety-notes)

## Scope

This runbook provides production-style operational steps for using VectorVue v4.0 with PostgreSQL in Docker, including migration, reset, seeding, verification, and recovery workflows.

## Prerequisites

1. Docker and Docker Compose installed.
2. Project root as current directory.
3. `vectorvue.db` available if migrating existing SQLite data.

## Start Services

1. Start PostgreSQL container:

```bash
docker compose up -d postgres
```

2. Verify health:

```bash
docker compose ps
```

Expected: `vectorvue-postgres-1` shows `healthy`.

Note: host mapping is `5433:5432` in `docker-compose.yml`.

### One-command operations via Make

```bash
make pg-reset
make pg-migrate
make pg-seed
make pg-smoke
```

## Initialize Database

### Option A: Migrate existing SQLite data (recommended for continuity)

```bash
docker compose run --rm vectorvue_app python scripts/migrate_sqlite_to_postgres.py \
  --sqlite vectorvue.db \
  --pg-url postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db \
  --schema sql/postgres_schema.sql \
  --truncate
```

### Option B: Fresh clean state (no SQLite import)

```bash
docker compose run --rm vectorvue_app python scripts/reset_db.py \
  --backend postgres \
  --pg-url postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db \
  --drop-schema --yes
```

Then seed:

```bash
docker compose run --rm vectorvue_app python scripts/seed_db.py \
  --backend postgres \
  --pg-url postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db
```

## Run VectorVue on PostgreSQL

### Docker mode

```bash
docker compose up -d vectorvue_app
```

### Local python mode

```bash
export VV_DB_BACKEND=postgres
export VV_DB_URL=postgresql://vectorvue:strongpassword@127.0.0.1:5433/vectorvue_db
python vv.py
```

## Seed and Reset Operations

### Reset PostgreSQL by truncating data

```bash
docker compose run --rm vectorvue_app python scripts/reset_db.py \
  --backend postgres \
  --pg-url postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db \
  --yes
```

### Reset PostgreSQL by dropping schema

```bash
docker compose run --rm vectorvue_app python scripts/reset_db.py \
  --backend postgres \
  --pg-url postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db \
  --drop-schema --yes
```

### Seed PostgreSQL test dataset

```bash
docker compose run --rm vectorvue_app python scripts/seed_db.py \
  --backend postgres \
  --pg-url postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db \
  --admin-user admin \
  --admin-pass AdminPassw0rd!
```

## Validation and Testing

1. Syntax check:

```bash
python -m py_compile vv.py vv_core.py scripts/*.py tests/test_postgres_smoke.py
```

2. PostgreSQL smoke tests:

```bash
docker compose run --rm \
  -e VV_DB_BACKEND=postgres \
  -e VV_DB_URL=postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db \
  vectorvue_app python -m unittest -q tests/test_postgres_smoke.py
```

3. Optional method audit refresh:

```bash
python scripts/audit_vv_core_methods.py
```

## Backup and Restore

### Backup

```bash
docker compose exec postgres pg_dump -U vectorvue -d vectorvue_db > vectorvue_pg_backup.sql
```

### Restore

```bash
cat vectorvue_pg_backup.sql | docker compose exec -T postgres psql -U vectorvue -d vectorvue_db
```

## Troubleshooting

### `address already in use` on port 5432

Use host port `5433` (already configured in compose).

### `current transaction is aborted`

This indicates a prior SQL error in the same transaction. Check preceding SQL exception and rerun operation.

### `relation ... does not exist`

Initialize schema first:

```bash
python scripts/export_pg_schema.py
docker compose run --rm vectorvue_app python scripts/migrate_sqlite_to_postgres.py --truncate --pg-url postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db
```

## Operational Safety Notes

1. Keep immutable/audit table protections enabled.
2. Always backup before `--drop-schema`.
3. Use `--truncate` only in controlled migration windows.
4. Keep RBAC validation in smoke/integration tests after schema changes.
