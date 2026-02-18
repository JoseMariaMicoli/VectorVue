# Copyright (c) 2026 José María Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}
#
# You may:
# ✔ Study
# ✔ Modify
# ✔ Use for internal security testing
#
# You may NOT:
# ✘ Offer as a commercial service
# ✘ Sell derived competing products

PG_URL ?= postgresql://vectorvue:vectorvue@postgres:5432/vectorvue
SQLITE_DB ?= vectorvue.db
SCHEMA_SQL ?= sql/postgres_schema.sql
PY ?= python

.PHONY: help pg-reset pg-migrate pg-seed pg-smoke

help:
	@echo "VectorVue PostgreSQL operational targets"
	@echo "  make pg-reset   - Drop/recreate PostgreSQL public schema"
	@echo "  make pg-migrate - Migrate SQLite to PostgreSQL (truncate target first)"
	@echo "  make pg-seed    - Seed PostgreSQL with demo operational data"
	@echo "  make pg-smoke   - Run PostgreSQL smoke tests"
	@echo ""
	@echo "Overrides:"
	@echo "  PG_URL='postgresql://user:pass@postgres:5432/vectorvue'"
	@echo "  SQLITE_DB=vectorvue.db SCHEMA_SQL=sql/postgres_schema.sql"

pg-reset:
	docker compose run --rm vectorvue $(PY) scripts/reset_db.py \
		--backend postgres \
		--pg-url $(PG_URL) \
		--drop-schema --yes

pg-migrate:
	docker compose run --rm vectorvue $(PY) scripts/migrate_sqlite_to_postgres.py \
		--sqlite $(SQLITE_DB) \
		--pg-url $(PG_URL) \
		--schema $(SCHEMA_SQL) \
		--truncate

pg-seed:
	docker compose run --rm vectorvue $(PY) scripts/seed_db.py \
		--backend postgres \
		--pg-url $(PG_URL)

pg-smoke:
	docker compose run --rm \
		-e VV_DB_BACKEND=postgres \
		-e VV_DB_URL=$(PG_URL) \
		vectorvue $(PY) -m unittest -q tests/test_postgres_smoke.py
