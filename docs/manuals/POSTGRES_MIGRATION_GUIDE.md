<sub>Copyright (c) 2026 Jose Maria Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# PostgreSQL Migration Guide

This guide describes migration and validation for PostgreSQL-backed VectorVue environments.

## 1. Included Assets

- `sql/postgres_schema.sql`
- `scripts/export_pg_schema.py`
- `scripts/migrate_sqlite_to_postgres.py`
- `tests/test_postgres_smoke.py`

## 2. Start Database Service

```bash
docker compose up -d postgres
docker compose ps
```

## 3. Apply Schema

```bash
make pg-schema-bootstrap
```

## 4. Optional SQLite-to-PostgreSQL Data Migration

```bash
docker compose run --rm vectorvue_app python scripts/migrate_sqlite_to_postgres.py \
  --sqlite vectorvue.db \
  --pg-url postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db \
  --schema sql/postgres_schema.sql \
  --truncate
```

## 5. Apply Platform Migrations

```bash
make phase65-migrate
make phase7e-migrate
make phase8-migrate
make phase9-migrate
```

## 6. Validate Runtime

```bash
make deploy
make api-smoke
```

## 7. Regression Checks

Use checklist:

- `docs/manuals/POSTGRES_REGRESSION_CHECKLIST.md`

