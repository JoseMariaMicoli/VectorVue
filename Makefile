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

PG_URL ?= postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db
SQLITE_DB ?= vectorvue.db
SCHEMA_SQL ?= sql/postgres_schema.sql
PY ?= python

.PHONY: help venv-rebuild run-tui run-local-postgres deploy phase6-up phase6-test phase6-down phase6-reset phase6-airgap phase6-hardening phase6-all pg-reset pg-migrate pg-seed pg-smoke

help:
	@echo "VectorVue PostgreSQL operational targets"
	@echo "  make pg-reset   - Drop/recreate PostgreSQL public schema"
	@echo "  make pg-migrate - Migrate SQLite to PostgreSQL (truncate target first)"
	@echo "  make pg-seed    - Seed PostgreSQL with demo operational data"
	@echo "  make pg-smoke   - Run PostgreSQL smoke tests"
	@echo "  make venv-rebuild - Delete venv, recreate it, and install requirements"
	@echo "  make run-tui    - Run interactive TUI in Docker (PostgreSQL backend)"
	@echo "  make run-local-postgres - Run local Python TUI against Docker PostgreSQL"
	@echo "  make deploy     - Build and start full Phase 6 stack"
	@echo "  make phase6-up  - Generate TLS certs, build, and start Phase 6 stack"
	@echo "  make phase6-test - Run functional, security, and performance validation"
	@echo "  make phase6-down - Stop Phase 6 stack"
	@echo "  make phase6-reset - Stop stack and remove volumes"
	@echo "  make phase6-airgap - Export air-gap deployment bundle"
	@echo "  make phase6-hardening - Run hardening checks"
	@echo "  make phase6-all - End-to-end: up + pg-smoke + all Phase 6 tests"
	@echo ""
	@echo "Overrides:"
	@echo "  PG_URL='postgresql://user:pass@postgres:5432/vectorvue_db'"
	@echo "  SQLITE_DB=vectorvue.db SCHEMA_SQL=sql/postgres_schema.sql"

deploy: phase6-up

venv-rebuild:
	rm -rf venv
	python3 -m venv venv
	venv/bin/python -m pip install --upgrade pip
	venv/bin/pip install -r requirements.txt

run-tui:
	docker compose run --rm -it -e VV_RUN_MODE=tui vectorvue_app python vv.py

run-local-postgres:
	VV_DB_BACKEND=postgres \
	VV_DB_URL=postgresql://vectorvue:strongpassword@127.0.0.1:5433/vectorvue_db \
	python3 vv.py

phase6-up:
	./deploy/scripts/generate_tls_certs.sh
	docker compose build vectorvue_app
	docker compose up -d postgres redis vectorvue_app nginx

phase6-test:
	./scripts/test_phase6_functional.sh
	./scripts/test_phase6_security.sh
	./scripts/test_phase6_performance.sh 200

phase6-down:
	docker compose down

phase6-reset:
	docker compose down -v

phase6-airgap:
	./deploy/scripts/export_airgap_bundle.sh

phase6-hardening:
	./deploy/scripts/security_hardening.sh check

phase6-all: phase6-up pg-smoke phase6-test

pg-reset:
	docker compose run --rm vectorvue_app $(PY) scripts/reset_db.py \
		--backend postgres \
		--pg-url $(PG_URL) \
		--drop-schema --yes

pg-migrate:
	docker compose run --rm vectorvue_app $(PY) scripts/migrate_sqlite_to_postgres.py \
		--sqlite $(SQLITE_DB) \
		--pg-url $(PG_URL) \
		--schema $(SCHEMA_SQL) \
		--truncate

pg-seed:
	docker compose run --rm vectorvue_app $(PY) scripts/seed_db.py \
		--backend postgres \
		--pg-url $(PG_URL)

pg-smoke:
	docker compose run --rm \
		-e VV_DB_BACKEND=postgres \
		-e VV_DB_URL=$(PG_URL) \
		vectorvue_app $(PY) -m unittest -q tests/test_postgres_smoke.py
