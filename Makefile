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
NPM ?= npm
SKIP_BUILD ?= 0
FORCE_CLASSIC_BUILD ?= 0
DC ?= docker compose
CUSTOMER ?= default
TENANT_NAME ?= Default Customer
TENANT_ID ?= auto
HTTP_HOST_PORT ?= 80
HTTPS_HOST_PORT ?= 443
POSTGRES_HOST_PORT ?= 5433
PORTAL_DIR ?= portal
export HTTP_HOST_PORT HTTPS_HOST_PORT POSTGRES_HOST_PORT
GLOBAL_ADMIN_USER ?= redteam_admin
GLOBAL_ADMIN_PASS ?= RedTeamAdm1n!
OPERATOR_LEAD_USER ?= rt_lead
OPERATOR_LEAD_PASS ?= LeadOperat0r!
OPERATOR_USER ?= rt_operator
OPERATOR_PASS ?= CoreOperat0r!
PANEL1_TENANT_ID ?= 10000000-0000-0000-0000-000000000001
PANEL1_TENANT_NAME ?= ACME Industries
PANEL1_CLIENT_USER_1 ?= acme_viewer
PANEL1_CLIENT_PASS_1 ?= AcmeView3r!
PANEL1_CLIENT_ROLE_1 ?= viewer
PANEL1_CLIENT_USER_2 ?= acme_operator
PANEL1_CLIENT_PASS_2 ?= AcmeOperat0r!
PANEL1_CLIENT_ROLE_2 ?= operator
PANEL2_TENANT_ID ?= 20000000-0000-0000-0000-000000000002
PANEL2_TENANT_NAME ?= Globex Corporation
PANEL2_CLIENT_USER_1 ?= globex_viewer
PANEL2_CLIENT_PASS_1 ?= GlobexView3r!
PANEL2_CLIENT_ROLE_1 ?= viewer
PANEL2_CLIENT_USER_2 ?= globex_operator
PANEL2_CLIENT_PASS_2 ?= GlobexOperat0r!
PANEL2_CLIENT_ROLE_2 ?= operator
PANEL1_PORTAL_HOST ?= acme.vectorvue.local
PANEL2_PORTAL_HOST ?= globex.vectorvue.local
PORTAL_PROTO ?= https

.PHONY: help venv-rebuild run-tui run-local-postgres deploy customer-deploy customer-deploy-isolated phase65-bootstrap api-up api-down api-logs api-smoke phase7a-check portal-install portal-dev portal-build portal-start phase7b-check phase6-up phase6-test phase6-down phase6-reset phase6-airgap phase6-hardening phase6-all pg-schema-bootstrap phase65-migrate phase7d-migrate pg-reset pg-migrate pg-seed seed-clients pg-smoke print-access-matrix

help:
	@echo "VectorVue PostgreSQL operational targets"
	@echo "  make pg-reset   - Drop/recreate PostgreSQL public schema"
	@echo "  make pg-schema-bootstrap - Apply base PostgreSQL schema SQL (idempotent)"
	@echo "  make pg-migrate - Migrate SQLite to PostgreSQL (truncate target first)"
	@echo "  make pg-seed    - Backward-compatible alias for make seed-clients"
	@echo "  make seed-clients - Seed multi-tenant client/demo users + campaigns"
	@echo "  make print-access-matrix - Print seeded global + client panel credential matrix"
	@echo "  make pg-smoke   - Run PostgreSQL smoke tests"
	@echo "  make venv-rebuild - Delete venv, recreate it, and install requirements"
	@echo "  make run-tui    - Run interactive TUI in Docker (PostgreSQL backend)"
	@echo "  make run-local-postgres - Run local Python TUI against Docker PostgreSQL"
	@echo "  make deploy     - Build/start full stack + tenant/theme migrations + API smoke test"
	@echo "  make customer-deploy - Deploy stack scoped by COMPOSE project name per customer"
	@echo "  make customer-deploy-isolated - Deploy one tenant-per-stack and bootstrap tenant metadata"
	@echo "  make phase65-bootstrap - Create customer dirs/env and bootstrap tenant metadata"
	@echo "  make api-up     - Start full stack (postgres, redis, api, runtime worker, portal, nginx)"
	@echo "  make api-down   - Stop REST API stack"
	@echo "  make api-logs   - Tail API and runtime logs"
	@echo "  make api-smoke  - Validate API health and OpenAPI endpoint"
	@echo "  make phase7a-check - Validate Phase 7A router/schemas/url builder modules"
	@echo "  make portal-install - Install Next.js portal dependencies"
	@echo "  make portal-dev - Run Next.js portal in development mode"
	@echo "  make portal-build - Build Next.js portal for production"
	@echo "  make portal-start - Start built Next.js portal"
	@echo "  make phase7b-check - Validate Phase 7B (portal build)"
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
	@echo "  PANEL1_TENANT_NAME='ACME Industries' PANEL2_TENANT_NAME='Globex Corporation'"
	@echo "  PANEL1_PORTAL_HOST=acme.vectorvue.local PANEL2_PORTAL_HOST=globex.vectorvue.local"
	@echo "  HTTP_HOST_PORT=8080 HTTPS_HOST_PORT=8443 POSTGRES_HOST_PORT=5543"

deploy: api-up phase65-migrate phase7d-migrate api-smoke

customer-deploy:
	COMPOSE_PROJECT_NAME=$(CUSTOMER) \
	HTTP_HOST_PORT=$(HTTP_HOST_PORT) \
	HTTPS_HOST_PORT=$(HTTPS_HOST_PORT) \
	POSTGRES_HOST_PORT=$(POSTGRES_HOST_PORT) \
	$(MAKE) deploy

customer-deploy-isolated:
	COMPOSE_PROJECT_NAME=$(CUSTOMER) \
	HTTP_HOST_PORT=$(HTTP_HOST_PORT) \
	HTTPS_HOST_PORT=$(HTTPS_HOST_PORT) \
	POSTGRES_HOST_PORT=$(POSTGRES_HOST_PORT) \
	$(MAKE) deploy
	COMPOSE_PROJECT_NAME=$(CUSTOMER) \
	HTTP_HOST_PORT=$(HTTP_HOST_PORT) \
	HTTPS_HOST_PORT=$(HTTPS_HOST_PORT) \
	POSTGRES_HOST_PORT=$(POSTGRES_HOST_PORT) \
	$(MAKE) phase65-bootstrap CUSTOMER="$(CUSTOMER)" TENANT_NAME="$(TENANT_NAME)" TENANT_ID="$(TENANT_ID)"

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
			DOCKER_BUILDKIT=0 $(DC) build vectorvue_app vectorvue_portal; \
		else \
			$(DC) build vectorvue_app vectorvue_portal || (echo "BuildKit failed, retrying with classic builder..." && DOCKER_BUILDKIT=0 $(DC) build vectorvue_app vectorvue_portal); \
		fi; \
	else \
		echo "SKIP_BUILD=1 -> skipping image build"; \
	fi
	$(DC) up -d --force-recreate postgres redis vectorvue_app vectorvue_runtime vectorvue_portal nginx

api-up: phase6-up

api-down: phase6-down

api-logs:
	$(DC) logs --tail=120 -f vectorvue_app vectorvue_runtime vectorvue_portal nginx

api-smoke:
	$(DC) exec -T vectorvue_app python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=5).read().decode())"
	$(DC) exec -T vectorvue_app python -c "import urllib.request;print('openapi_ok' if urllib.request.urlopen('http://127.0.0.1:8080/openapi.json', timeout=5).status==200 else 'openapi_fail')"

phase7a-check:
	$(PY) -m py_compile app/client_api/__init__.py app/client_api/dependencies.py app/client_api/schemas.py app/client_api/router.py utils/url_builder.py

portal-install:
	$(NPM) --prefix $(PORTAL_DIR) install

portal-dev:
	$(NPM) --prefix $(PORTAL_DIR) run dev

portal-build:
	$(NPM) --prefix $(PORTAL_DIR) run build

portal-start:
	$(NPM) --prefix $(PORTAL_DIR) run start

phase7b-check: portal-install portal-build

pg-schema-bootstrap:
	$(DC) run --rm -v "$(CURDIR):/opt/vectorvue" vectorvue_app $(PY) scripts/apply_pg_sql.py \
		--pg-url $(PG_URL) \
		--sql $(SCHEMA_SQL)

phase65-migrate: pg-schema-bootstrap
	$(DC) run --rm -v "$(CURDIR):/opt/vectorvue" vectorvue_app $(PY) scripts/apply_pg_sql.py \
		--pg-url $(PG_URL) \
		--sql sql/phase65_tenant_migration.sql

phase7d-migrate:
	$(DC) run --rm -v "$(CURDIR):/opt/vectorvue" vectorvue_app $(PY) scripts/apply_pg_sql.py \
		--pg-url $(PG_URL) \
		--sql sql/phase7d_tenant_theme.sql

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

seed-clients: phase65-migrate phase7d-migrate
	$(DC) run --rm -v "$(CURDIR):/opt/vectorvue" vectorvue_app $(PY) scripts/seed_db.py \
		--backend postgres \
		--pg-url $(PG_URL) \
		--global-admin-user "$(GLOBAL_ADMIN_USER)" \
		--global-admin-pass "$(GLOBAL_ADMIN_PASS)" \
		--operator-lead-user "$(OPERATOR_LEAD_USER)" \
		--operator-lead-pass "$(OPERATOR_LEAD_PASS)" \
		--operator-user "$(OPERATOR_USER)" \
		--operator-pass "$(OPERATOR_PASS)" \
		--panel1-tenant-id "$(PANEL1_TENANT_ID)" \
		--panel1-tenant-name "$(PANEL1_TENANT_NAME)" \
		--panel1-client-user-1 "$(PANEL1_CLIENT_USER_1)" \
		--panel1-client-pass-1 "$(PANEL1_CLIENT_PASS_1)" \
		--panel1-client-role-1 "$(PANEL1_CLIENT_ROLE_1)" \
		--panel1-client-user-2 "$(PANEL1_CLIENT_USER_2)" \
		--panel1-client-pass-2 "$(PANEL1_CLIENT_PASS_2)" \
		--panel1-client-role-2 "$(PANEL1_CLIENT_ROLE_2)" \
		--panel2-tenant-id "$(PANEL2_TENANT_ID)" \
		--panel2-tenant-name "$(PANEL2_TENANT_NAME)" \
		--panel2-client-user-1 "$(PANEL2_CLIENT_USER_1)" \
		--panel2-client-pass-1 "$(PANEL2_CLIENT_PASS_1)" \
		--panel2-client-role-1 "$(PANEL2_CLIENT_ROLE_1)" \
		--panel2-client-user-2 "$(PANEL2_CLIENT_USER_2)" \
		--panel2-client-pass-2 "$(PANEL2_CLIENT_PASS_2)" \
		--panel2-client-role-2 "$(PANEL2_CLIENT_ROLE_2)"
	@$(MAKE) print-access-matrix --no-print-directory

pg-seed: seed-clients

print-access-matrix:
	@echo ""
	@echo "=== VectorVue Access Matrix ==="
	@echo "Global Red Team:"
	@echo " - admin:    $(GLOBAL_ADMIN_USER) / $(GLOBAL_ADMIN_PASS) (ADMIN)"
	@echo " - lead:     $(OPERATOR_LEAD_USER) / $(OPERATOR_LEAD_PASS) (LEAD)"
	@echo " - operator: $(OPERATOR_USER) / $(OPERATOR_PASS) (OPERATOR)"
	@echo "Client Panel 1 ($(PANEL1_TENANT_NAME)):"
	@echo " - tenant_id: $(PANEL1_TENANT_ID)"
	@echo " - portal_url: $(PORTAL_PROTO)://$(PANEL1_PORTAL_HOST)/login"
	@echo " - user1: $(PANEL1_CLIENT_USER_1) / $(PANEL1_CLIENT_PASS_1) ($(PANEL1_CLIENT_ROLE_1))"
	@echo " - user2: $(PANEL1_CLIENT_USER_2) / $(PANEL1_CLIENT_PASS_2) ($(PANEL1_CLIENT_ROLE_2))"
	@echo "Client Panel 2 ($(PANEL2_TENANT_NAME)):"
	@echo " - tenant_id: $(PANEL2_TENANT_ID)"
	@echo " - portal_url: $(PORTAL_PROTO)://$(PANEL2_PORTAL_HOST)/login"
	@echo " - user1: $(PANEL2_CLIENT_USER_1) / $(PANEL2_CLIENT_PASS_1) ($(PANEL2_CLIENT_ROLE_1))"
	@echo " - user2: $(PANEL2_CLIENT_USER_2) / $(PANEL2_CLIENT_PASS_2) ($(PANEL2_CLIENT_ROLE_2))"
	@echo "Fallback host:"
	@echo " - portal_url: $(PORTAL_PROTO)://127.0.0.1/login"
	@echo "==============================="

pg-smoke:
	$(DC) run --rm \
		-e VV_DB_BACKEND=postgres \
		-e VV_DB_URL=$(PG_URL) \
		vectorvue_app $(PY) -m unittest -q tests/test_postgres_smoke.py
