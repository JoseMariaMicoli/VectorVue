<sub>Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# PostgreSQL Migration and Docker Deployment Guide (v4.1)

## Scope

This guide describes the VectorVue SQLite-to-PostgreSQL migration path, Docker deployment, and validation workflow while preserving all current operational features.

## Deliverables in Repository

- PostgreSQL schema: `sql/postgres_schema.sql`
- Schema export tool: `scripts/export_pg_schema.py`
- Data migration tool: `scripts/migrate_sqlite_to_postgres.py`
- Method audit report: `docs/manuals/POSTGRES_AUDIT_REPORT.md`
- Docker runtime: `Dockerfile`, `docker-compose.yml`
- PostgreSQL smoke tests: `tests/test_postgres_smoke.py`

## 1. Prepare PostgreSQL Schema

Regenerate schema from current SQLite if needed:

```bash
python scripts/export_pg_schema.py
```

Output:

- `sql/postgres_schema.sql`

## 2. Start PostgreSQL with Docker

```bash
docker compose up -d postgres
```

Validate health:

```bash
docker compose ps
```

Note: host port mapping is `5433:5432` in `docker-compose.yml`.

## 3. Migrate Data from SQLite to PostgreSQL

```bash
docker compose run --rm vectorvue python scripts/migrate_sqlite_to_postgres.py \
  --sqlite vectorvue.db \
  --pg-url postgresql://vectorvue:vectorvue@postgres:5432/vectorvue \
  --schema sql/postgres_schema.sql \
  --truncate
```

## 4. Run VectorVue with PostgreSQL Backend

Set runtime backend variables:

```bash
export VV_DB_BACKEND=postgres
export VV_DB_URL=postgresql://vectorvue:vectorvue@127.0.0.1:5433/vectorvue
python vv.py
```

Or run through compose:

```bash
docker compose up --build vectorvue
```

## 5. Regression Validation

### Core syntax sanity

```bash
python -m py_compile vv.py vv_core.py vv_tab_navigation.py vv_theme.py
```

### PostgreSQL smoke tests

```bash
docker compose run --rm \
  -e VV_DB_BACKEND=postgres \
  -e VV_DB_URL=postgresql://vectorvue:vectorvue@postgres:5432/vectorvue \
  vectorvue python -m unittest -q tests/test_postgres_smoke.py
```

## 6. Audit and Risk Review

Review migration audit:

- `docs/manuals/POSTGRES_AUDIT_REPORT.md`

Focus areas:

1. Methods marked as multi-table mutation candidates
2. Conflict-handling SQL (`INSERT OR IGNORE`, upserts)
3. Immutable table protections (trigger-based)
4. Evidence/audit hash preservation

## 7. Operational Safety Notes

- Keep a backup of `vectorvue.db` before first migration.
- Validate canary/auth and sample campaigns post-migration.
- Confirm critical views: Campaign, Sessions, Detections, Timeline, Reporting, Cognition tabs.
- Validate export artifacts in `Reports/`.
