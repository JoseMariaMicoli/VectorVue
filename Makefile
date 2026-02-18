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
SKIP_BUILD ?= 0
FORCE_CLASSIC_BUILD ?= 0
DC ?= docker compose --ansi always
CUSTOMER ?= default
TENANT_NAME ?= Default Customer
TENANT_ID ?= auto

.PHONY: help venv-rebuild run-tui run-local-postgres deploy customer-deploy phase65-bootstrap api-up api-down api-logs api-smoke phase6-up phase6-test phase6-down phase6-reset phase6-airgap phase6-hardening phase6-all phase65-migrate pg-reset pg-migrate pg-seed pg-smoke

help:
	@echo "VectorVue PostgreSQL operational targets"
	@echo "  make pg-reset   - Drop/recreate PostgreSQL public schema"
	@echo "  make pg-migrate - Migrate SQLite to PostgreSQL (truncate target first)"
	@echo "  make pg-seed    - Seed PostgreSQL with demo operational data"
	@echo "  make pg-smoke   - Run PostgreSQL smoke tests"
	@echo "  make venv-rebuild - Delete venv, recreate it, and install requirements"
	@echo "  make run-tui    - Run interactive TUI in Docker (PostgreSQL backend)"
	@echo "  make run-local-postgres - Run local Python TUI against Docker PostgreSQL"
	@echo "  make deploy     - Build/start full stack + Phase 6.5 migration + API smoke test"
	@echo "  make customer-deploy - Deploy stack scoped by COMPOSE project name per customer"
	@echo "  make phase65-bootstrap - Create customer dirs/env and bootstrap tenant metadata"
	@echo "  make api-up     - Start REST API stack (postgres, redis, api, runtime worker, nginx)"
	@echo "  make api-down   - Stop REST API stack"
	@echo "  make api-logs   - Tail API and runtime logs"
	@echo "  make api-smoke  - Validate API health and OpenAPI endpoint"
	@echo "  make phase6-up  - Generate TLS certs, build, and start Phase 6 stack"
	@echo "  make phase6-test - Run functional, security, and performance validation"
	@echo "  make phase65-migrate - Apply tenant isolation migration (Phase 6.5)"
	@echo "  make phase6-down - Stop Phase 6 stack"
	@echo "  make phase6-reset - Stop stack and remove volumes"
	@echo "  make phase6-airgap - Export air-gap deployment bundle"
	@echo "  make phase6-hardening - Run hardening checks"
	@echo "  make phase6-all - End-to-end: up + pg-smoke + all Phase 6 tests"
	@echo ""
	@echo "Overrides:"
	@echo "  PG_URL='postgresql://user:pass@postgres:5432/vectorvue_db'"
	@echo "  SQLITE_DB=vectorvue.db SCHEMA_SQL=sql/postgres_schema.sql"
	@echo "  CUSTOMER=acme TENANT_NAME='ACME Corp' TENANT_ID=auto"

deploy: api-up phase65-migrate api-smoke

customer-deploy:
	COMPOSE_PROJECT_NAME=$(CUSTOMER) $(MAKE) deploy

venv-rebuild:
	rm -rf venv
	python3 -m venv venv
	venv/bin/python -m pip install --upgrade pip
	venv/bin/pip install -r requirements.txt

run-tui:
	$(DC) run --rm -it -e VV_RUN_MODE=tui vectorvue_app python vv.py

run-local-postgres:
	VV_DB_BACKEND=postgres \
	VV_DB_URL=postgresql://vectorvue:strongpassword@127.0.0.1:5433/vectorvue_db \
	python3 vv.py

phase6-up:
	./deploy/scripts/generate_tls_certs.sh
	@if [ "$(SKIP_BUILD)" != "1" ]; then \
		if [ "$(FORCE_CLASSIC_BUILD)" = "1" ]; then \
			DOCKER_BUILDKIT=0 $(DC) build vectorvue_app; \
		else \
			$(DC) build vectorvue_app || (echo "BuildKit failed, retrying with classic builder..." && DOCKER_BUILDKIT=0 $(DC) build vectorvue_app); \
		fi; \
	else \
		echo "SKIP_BUILD=1 -> skipping image build"; \
	fi
	$(DC) up -d --force-recreate postgres redis vectorvue_app vectorvue_runtime nginx

api-up: phase6-up

api-down: phase6-down

api-logs:
	$(DC) logs --tail=120 -f vectorvue_app vectorvue_runtime nginx

api-smoke:
	$(DC) exec -T vectorvue_app python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=5).read().decode())"
	$(DC) exec -T vectorvue_app python -c "import urllib.request;print('openapi_ok' if urllib.request.urlopen('http://127.0.0.1:8080/openapi.json', timeout=5).status==200 else 'openapi_fail')"

phase65-migrate:
	$(DC) run --rm -v "$(CURDIR):/opt/vectorvue" vectorvue_app $(PY) scripts/apply_pg_sql.py \
		--pg-url $(PG_URL) \
		--sql sql/phase65_tenant_migration.sql

phase65-bootstrap: phase65-migrate
	./deploy/scripts/bootstrap_customer.sh "$(CUSTOMER)" "$(TENANT_NAME)" "$(TENANT_ID)" "$(PG_URL)"

phase6-test:
	./scripts/test_phase6_functional.sh
	./scripts/test_phase6_security.sh
	./scripts/test_phase6_performance.sh 200

phase6-down:
	$(DC) down

phase6-reset:
	$(DC) down -v

phase6-airgap:
	./deploy/scripts/export_airgap_bundle.sh

phase6-hardening:
	./deploy/scripts/security_hardening.sh check

phase6-all: deploy pg-smoke phase6-test

pg-reset:
	$(DC) run --rm vectorvue_app $(PY) scripts/reset_db.py \
		--backend postgres \
		--pg-url $(PG_URL) \
		--drop-schema --yes

pg-migrate:
	$(DC) run --rm vectorvue_app $(PY) scripts/migrate_sqlite_to_postgres.py \
		--sqlite $(SQLITE_DB) \
		--pg-url $(PG_URL) \
		--schema $(SCHEMA_SQL) \
		--truncate

pg-seed:
	$(DC) run --rm vectorvue_app $(PY) scripts/seed_db.py \
		--backend postgres \
		--pg-url $(PG_URL)

pg-smoke:
	$(DC) run --rm \
		-e VV_DB_BACKEND=postgres \
		-e VV_DB_URL=$(PG_URL) \
		vectorvue_app $(PY) -m unittest -q tests/test_postgres_smoke.py
