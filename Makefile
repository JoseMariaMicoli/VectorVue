# Copyright (c) 2026 NyxeraLabs
# Author: José María Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-17 → Apache-2.0
#
# You may:
# ✔ Study
# ✔ Modify
# ✔ Use for internal security testing
#
# You may NOT:
# ✘ Offer as a commercial service
# ✘ Sell derived competing products
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
TENANT_PORTAL_HOST ?= $(CUSTOMER).vectorvue.local
TENANT_ADMIN_USER ?= tenant_admin
TENANT_ADMIN_PASS ?= TenantAdm1n!
TENANT_CLIENT_USER ?= tenant_viewer
TENANT_CLIENT_PASS ?= TenantView3r!
TENANT_CLIENT_ROLE ?= viewer
TENANT_OPERATOR_USER ?=
TENANT_OPERATOR_PASS ?=
TENANT_OPERATOR_ROLE ?= operator
DB_PASSPHRASE ?= $(GLOBAL_ADMIN_PASS)

# Security integration defaults (local/demo safe defaults so core targets run without manual env setup)
VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON ?= {"spectrastrike-producer":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
VV_TG_SPECTRASTRIKE_ED25519_PUBKEY ?= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
VV_FEDERATION_SPECTRASTRIKE_ED25519_PUBKEY ?= $(VV_TG_SPECTRASTRIKE_ED25519_PUBKEY)
VV_TG_OPERATOR_TENANT_MAP ?= {"op-001":"10000000-0000-0000-0000-000000000001"}
VV_HSM_EVIDENCE_ROOT_KEY_ID ?= vv-evidence-root-v1
VV_HSM_ROOT_KEYS_JSON ?= {"vv-evidence-root-v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}

# Optional local demo/preflight environment file (gitignored)
-include .env.demo-preflight.local
export VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON VV_TG_SPECTRASTRIKE_ED25519_PUBKEY VV_FEDERATION_SPECTRASTRIKE_ED25519_PUBKEY VV_TG_OPERATOR_TENANT_MAP VV_HSM_ROOT_KEYS_JSON VV_HSM_EVIDENCE_ROOT_KEY_ID DB_PASSPHRASE

.PHONY: help wizard venv-rebuild run-tui run-local-postgres install legal-install-check deploy commercial-deploy customer-deploy customer-deploy-isolated customer-deploy-portal-isolated tenant-bootstrap-real phase79-real-smoke phase65-bootstrap api-up api-down api-logs api-smoke phase7a-check portal-install portal-dev portal-build portal-start phase7b-check phase6-up phase6-test phase6-down phase6-reset phase6-airgap phase6-hardening phase6-all pg-schema-bootstrap phase65-migrate phase7d-migrate phase7e-migrate phase8-migrate phase9-migrate pg-reset pg-migrate pg-seed seed-clients pg-smoke print-access-matrix spectrastrike-preflight security-policy-gate security-regression redteam-validate spectrastrike-connect-check evidence-crypto-preflight demo-preflight-help bootstrap-local-integration

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
	@echo "  make wizard     - Interactive guided deploy/bootstrap wizard"
	@echo "  make install    - Production install path (mandatory legal acceptance + deploy)"
	@echo "  make deploy     - Build/start full stack + tenant/theme migrations + API smoke test"
	@echo "  make commercial-deploy - Deploy + print access matrix for commercial demos"
	@echo "  make customer-deploy - Deploy stack scoped by COMPOSE project name per customer"
	@echo "  make customer-deploy-isolated - Deploy one tenant-per-stack and bootstrap tenant metadata"
	@echo "  make customer-deploy-portal-isolated - One-command isolated stack + tenant users + portal host mapping"
	@echo "  make tenant-bootstrap-real - Bootstrap tenant users without dummy campaign data"
	@echo "  make phase79-real-smoke - Validate Phase 7-9 endpoints in real/no-dummy scenario"
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
	@echo "  make phase7e-migrate - Apply portal usage telemetry schema (Phase 7E)"
	@echo "  make phase8-migrate - Apply advanced ML/analytics schema (Phase 8)"
	@echo "  make phase9-migrate - Apply compliance/regulatory assurance schema (Phase 9)"
	@echo "  make phase6-down - Stop Phase 6 stack"
	@echo "  make phase6-reset - Stop stack and remove volumes"
	@echo "  make phase6-airgap - Export air-gap deployment bundle"
	@echo "  make phase6-hardening - Run hardening checks"
	@echo "  make phase6-all - End-to-end: up + pg-smoke + all Phase 6 tests"
	@echo "  make spectrastrike-preflight - Validate required SpectraStrike federation env + cert artifacts"
	@echo "  make security-policy-gate - Run Phase 8 policy gate checks (mTLS/signature/tenant guard)"
	@echo "  make security-regression - Run security regression test suite (Phase 1/6/7/8/9 + tenant isolation)"
	@echo "  make redteam-validate - Run full Phase 9 red-team simulation suite"
	@echo "  make spectrastrike-connect-check - Run SpectraStrike integration checks (preflight + policy gate + red-team)"
	@echo "  make evidence-crypto-preflight - Validate required evidence encryption HSM env config"
	@echo "  make demo-preflight-help - Print how to populate .env.demo-preflight.local"
	@echo "  make bootstrap-local-integration - Create local integration deliverables + demo preflight env file"
	@echo ""
	@echo "Overrides:"
	@echo "  PG_URL='postgresql://user:pass@postgres:5432/vectorvue_db'"
	@echo "  SQLITE_DB=vectorvue.db SCHEMA_SQL=sql/postgres_schema.sql"
	@echo "  CUSTOMER=acme TENANT_NAME='ACME Corp' TENANT_ID=auto"
	@echo "  PANEL1_TENANT_NAME='ACME Industries' PANEL2_TENANT_NAME='Globex Corporation'"
	@echo "  PANEL1_PORTAL_HOST=acme.vectorvue.local PANEL2_PORTAL_HOST=globex.vectorvue.local"
	@echo "  HTTP_HOST_PORT=8080 HTTPS_HOST_PORT=8443 POSTGRES_HOST_PORT=5543"

wizard:
	@set -eu; \
	printf "\n=== VectorVue Guided Wizard ===\n"; \
	printf "1) Commercial deploy (stack + migrations + smoke + access matrix)\n"; \
	printf "2) Isolated customer portal deploy (tenant + users + host mapping)\n"; \
	printf "3) Bootstrap real tenant users only (no dummy campaigns)\n"; \
	printf "4) Seed multi-tenant demo dataset\n"; \
	printf "5) Run real scenario validation (Phase 7-9 smoke)\n"; \
	printf "Select [1-5]: "; \
	read -r choice; \
	case "$$choice" in \
		1) \
			$(MAKE) commercial-deploy; \
			;; \
		2) \
			printf "Customer slug [acme]: "; read -r customer; customer="$${customer:-acme}"; \
			printf "Tenant name [ACME Corp]: "; read -r tenant_name; tenant_name="$${tenant_name:-ACME Corp}"; \
			printf "Tenant ID (UUID) [30000000-0000-0000-0000-000000000003]: "; read -r tenant_id; tenant_id="$${tenant_id:-30000000-0000-0000-0000-000000000003}"; \
			printf "Portal host [acme.vectorvue.local]: "; read -r portal_host; portal_host="$${portal_host:-acme.vectorvue.local}"; \
			printf "Tenant admin user [tenant_admin]: "; read -r admin_user; admin_user="$${admin_user:-tenant_admin}"; \
			printf "Tenant admin pass [TenantAdm1n!]: "; read -r admin_pass; admin_pass="$${admin_pass:-TenantAdm1n!}"; \
			printf "Client user [tenant_viewer]: "; read -r client_user; client_user="$${client_user:-tenant_viewer}"; \
			printf "Client pass [TenantView3r!]: "; read -r client_pass; client_pass="$${client_pass:-TenantView3r!}"; \
			printf "Client role [viewer]: "; read -r client_role; client_role="$${client_role:-viewer}"; \
			printf "DB passphrase (optional, for existing encrypted DB) []: "; read -r db_passphrase; \
			$(MAKE) customer-deploy-portal-isolated \
				CUSTOMER="$$customer" \
				TENANT_NAME="$$tenant_name" \
				TENANT_ID="$$tenant_id" \
				TENANT_PORTAL_HOST="$$portal_host" \
				TENANT_ADMIN_USER="$$admin_user" \
				TENANT_ADMIN_PASS="$$admin_pass" \
				TENANT_CLIENT_USER="$$client_user" \
				TENANT_CLIENT_PASS="$$client_pass" \
				TENANT_CLIENT_ROLE="$$client_role" \
				DB_PASSPHRASE="$$db_passphrase"; \
			;; \
		3) \
			printf "Tenant name [New Customer]: "; read -r tenant_name; tenant_name="$${tenant_name:-New Customer}"; \
			printf "Tenant ID [auto]: "; read -r tenant_id; tenant_id="$${tenant_id:-auto}"; \
			printf "Tenant admin user [tenant_admin]: "; read -r admin_user; admin_user="$${admin_user:-tenant_admin}"; \
			printf "Tenant admin pass [TenantAdm1n!]: "; read -r admin_pass; admin_pass="$${admin_pass:-TenantAdm1n!}"; \
			printf "Client user [tenant_viewer]: "; read -r client_user; client_user="$${client_user:-tenant_viewer}"; \
			printf "Client pass [TenantView3r!]: "; read -r client_pass; client_pass="$${client_pass:-TenantView3r!}"; \
			printf "Client role [viewer]: "; read -r client_role; client_role="$${client_role:-viewer}"; \
			printf "DB passphrase (optional, for existing encrypted DB) []: "; read -r db_passphrase; \
			$(MAKE) tenant-bootstrap-real \
				TENANT_NAME="$$tenant_name" \
				TENANT_ID="$$tenant_id" \
				TENANT_ADMIN_USER="$$admin_user" \
				TENANT_ADMIN_PASS="$$admin_pass" \
				TENANT_CLIENT_USER="$$client_user" \
				TENANT_CLIENT_PASS="$$client_pass" \
				TENANT_CLIENT_ROLE="$$client_role" \
				DB_PASSPHRASE="$$db_passphrase"; \
			;; \
		4) \
			$(MAKE) seed-clients; \
			;; \
		5) \
			printf "Tenant ID [$(PANEL1_TENANT_ID)]: "; read -r tenant_id; tenant_id="$${tenant_id:-$(PANEL1_TENANT_ID)}"; \
			if [ "$$tenant_id" = "auto" ]; then echo "Tenant ID must be explicit UUID for phase79-real-smoke"; exit 1; fi; \
			printf "Admin user [$(TENANT_ADMIN_USER)]: "; read -r admin_user; admin_user="$${admin_user:-$(TENANT_ADMIN_USER)}"; \
			printf "Admin pass [$(TENANT_ADMIN_PASS)]: "; read -r admin_pass; admin_pass="$${admin_pass:-$(TENANT_ADMIN_PASS)}"; \
			$(MAKE) phase79-real-smoke \
				TENANT_ID="$$tenant_id" \
				TENANT_ADMIN_USER="$$admin_user" \
				TENANT_ADMIN_PASS="$$admin_pass"; \
			;; \
		*) \
			echo "Invalid selection: $$choice"; \
			exit 1; \
			;; \
	esac

deploy: bootstrap-local-integration api-up phase65-migrate phase7d-migrate phase7e-migrate phase8-migrate phase9-migrate api-smoke

legal-install-check:
	$(PY) scripts/legal_install_guard.py --mode self-hosted --acceptance-file .vectorvue/legal_acceptance.json

install: legal-install-check deploy

commercial-deploy: deploy
	@$(MAKE) print-access-matrix --no-print-directory

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

customer-deploy-portal-isolated:
	@if [ "$(TENANT_ID)" = "auto" ]; then \
		echo "TENANT_ID must be explicit for portal host mapping (example: TENANT_ID=30000000-0000-0000-0000-000000000003)"; \
		exit 1; \
	fi
	COMPOSE_PROJECT_NAME=$(CUSTOMER) \
	HTTP_HOST_PORT=$(HTTP_HOST_PORT) \
	HTTPS_HOST_PORT=$(HTTPS_HOST_PORT) \
	POSTGRES_HOST_PORT=$(POSTGRES_HOST_PORT) \
	VV_TENANT_HOST_MAP="$(TENANT_PORTAL_HOST)=$(TENANT_ID)|$(TENANT_NAME),vectorvue.local=$(TENANT_ID)|$(TENANT_NAME)" \
	$(MAKE) deploy
	COMPOSE_PROJECT_NAME=$(CUSTOMER) \
	HTTP_HOST_PORT=$(HTTP_HOST_PORT) \
	HTTPS_HOST_PORT=$(HTTPS_HOST_PORT) \
	POSTGRES_HOST_PORT=$(POSTGRES_HOST_PORT) \
	$(MAKE) phase65-bootstrap CUSTOMER="$(CUSTOMER)" TENANT_NAME="$(TENANT_NAME)" TENANT_ID="$(TENANT_ID)"
	COMPOSE_PROJECT_NAME=$(CUSTOMER) \
	HTTP_HOST_PORT=$(HTTP_HOST_PORT) \
	HTTPS_HOST_PORT=$(HTTPS_HOST_PORT) \
	POSTGRES_HOST_PORT=$(POSTGRES_HOST_PORT) \
	$(MAKE) tenant-bootstrap-real TENANT_ID="$(TENANT_ID)" TENANT_NAME="$(TENANT_NAME)"
	@echo ""
	@echo "Isolated client portal deployed:"
	@echo " - customer: $(CUSTOMER)"
	@echo " - tenant_id: $(TENANT_ID)"
	@echo " - portal_url: $(PORTAL_PROTO)://$(TENANT_PORTAL_HOST)/login"
	@echo " - admin_user: $(TENANT_ADMIN_USER) / $(TENANT_ADMIN_PASS)"
	@echo " - client_user: $(TENANT_CLIENT_USER) / $(TENANT_CLIENT_PASS) ($(TENANT_CLIENT_ROLE))"

venv-rebuild:
	rm -rf venv
	python3 -m venv venv
	venv/bin/python -m pip install --upgrade pip
	venv/bin/pip install -r requirements.txt

run-tui: bootstrap-local-integration phase6-up
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
	$(DC) up -d --force-recreate postgres redis vectorvue_app vectorvue_runtime vectorvue_ml_worker vectorvue_compliance_observation_worker vectorvue_compliance_daily_worker vectorvue_portal nginx

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

phase7e-migrate:
	$(DC) run --rm -v "$(CURDIR):/opt/vectorvue" vectorvue_app $(PY) scripts/apply_pg_sql.py \
		--pg-url $(PG_URL) \
		--sql sql/phase7e_portal_telemetry.sql

phase8-migrate:
	$(DC) run --rm -v "$(CURDIR):/opt/vectorvue" vectorvue_app $(PY) scripts/apply_pg_sql.py \
		--pg-url $(PG_URL) \
		--sql sql/phase8_analytics.sql

phase9-migrate:
	$(DC) run --rm -v "$(CURDIR):/opt/vectorvue" vectorvue_app $(PY) scripts/apply_pg_sql.py \
		--pg-url $(PG_URL) \
		--sql sql/phase9_compliance.sql

phase65-bootstrap: phase65-migrate
	./deploy/scripts/bootstrap_customer.sh "$(CUSTOMER)" "$(TENANT_NAME)" "$(TENANT_ID)" "$(PG_URL)"

tenant-bootstrap-real:
	$(DC) run --rm -v "$(CURDIR):/opt/vectorvue" vectorvue_app $(PY) scripts/bootstrap_real_tenant.py \
		--backend postgres \
		--pg-url $(PG_URL) \
		--tenant-id "$(TENANT_ID)" \
		--tenant-name "$(TENANT_NAME)" \
		--admin-user "$(TENANT_ADMIN_USER)" \
		--admin-pass "$(TENANT_ADMIN_PASS)" \
		--client-user "$(TENANT_CLIENT_USER)" \
		--client-pass "$(TENANT_CLIENT_PASS)" \
		--client-role "$(TENANT_CLIENT_ROLE)" \
		--operator-user "$(TENANT_OPERATOR_USER)" \
		--operator-pass "$(TENANT_OPERATOR_PASS)" \
		--operator-role "$(TENANT_OPERATOR_ROLE)" \
		--passphrase "$(DB_PASSPHRASE)"

phase79-real-smoke:
	$(DC) run --rm -v "$(CURDIR):/opt/vectorvue" vectorvue_app $(PY) scripts/phase79_real_smoke.py \
		--base-url http://vectorvue_app:8080 \
		--tenant-id "$(TENANT_ID)" \
		--username "$(TENANT_ADMIN_USER)" \
		--password "$(TENANT_ADMIN_PASS)"

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

pg-reset: bootstrap-local-integration
	$(DC) run --rm vectorvue_app $(PY) scripts/reset_db.py \
		--backend postgres \
		--pg-url $(PG_URL) \
		--drop-schema --yes

pg-migrate: bootstrap-local-integration
	$(DC) run --rm vectorvue_app $(PY) scripts/migrate_sqlite_to_postgres.py \
		--sqlite $(SQLITE_DB) \
		--pg-url $(PG_URL) \
		--schema $(SCHEMA_SQL) \
		--truncate

seed-clients: evidence-crypto-preflight phase65-migrate phase7d-migrate phase7e-migrate phase8-migrate phase9-migrate
	$(DC) run --rm \
		-e VV_HSM_ROOT_KEYS_JSON='$(VV_HSM_ROOT_KEYS_JSON)' \
		-e VV_HSM_EVIDENCE_ROOT_KEY_ID='$(VV_HSM_EVIDENCE_ROOT_KEY_ID)' \
		--user "$$(id -u):$$(id -g)" -v "$(CURDIR):/opt/vectorvue" vectorvue_app $(PY) scripts/seed_db.py \
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

pg-smoke: bootstrap-local-integration
	$(DC) run --rm \
		-e VV_DB_BACKEND=postgres \
		-e VV_DB_URL=$(PG_URL) \
		vectorvue_app $(PY) -m unittest -q tests/test_postgres_smoke.py

spectrastrike-preflight:
	@test -n "$${VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON:-}" || (echo "ERROR: Missing VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON"; echo "Hint: set service identity to pinned cert fingerprint JSON"; exit 1)
	@test -n "$${VV_TG_SPECTRASTRIKE_ED25519_PUBKEY:-}" || (echo "ERROR: Missing VV_TG_SPECTRASTRIKE_ED25519_PUBKEY"; echo "Hint: set base64 raw 32-byte Ed25519 public key"; exit 1)
	@test -n "$${VV_TG_OPERATOR_TENANT_MAP:-}" || (echo "ERROR: Missing VV_TG_OPERATOR_TENANT_MAP"; echo "Hint: JSON map operator_id -> tenant UUID"; exit 1)
	@test -f deploy/certs/server.crt || (echo "ERROR: Missing deploy/certs/server.crt"; exit 1)
	@test -f deploy/certs/server.key || (echo "ERROR: Missing deploy/certs/server.key"; exit 1)
	@test -f deploy/certs/ca.crt || (echo "ERROR: Missing deploy/certs/ca.crt"; exit 1)
	$(PY) -c "import base64, json, os; json.loads(os.environ['VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON']); json.loads(os.environ['VV_TG_OPERATOR_TENANT_MAP']); key=base64.b64decode(os.environ['VV_TG_SPECTRASTRIKE_ED25519_PUBKEY']); assert len(key)==32, 'VV_TG_SPECTRASTRIKE_ED25519_PUBKEY must decode to 32 bytes'; print('spectrastrike preflight ok')"

security-policy-gate:
	$(PY) scripts/security_ci_policy_gate.py

security-regression:
	$(PY) -m unittest tests/unit/test_tenant_isolation.py -v
	$(PY) -m unittest tests/unit/test_phase1_sprint11_telemetry_gateway.py -v
	$(PY) -m unittest tests/unit/test_phase6_sprint61_tamper_log.py -v
	$(PY) -m unittest tests/unit/test_phase7_sprint71_federation.py -v
	$(PY) -m unittest tests/unit/test_phase8_sprint81_security_ci_gate.py -v
	$(PY) -m unittest tests/unit/test_phase9_sprint91_redteam_attacks.py -v

redteam-validate:
	$(PY) -m unittest tests/unit/test_phase9_sprint91_redteam_attacks.py -v

spectrastrike-connect-check: spectrastrike-preflight security-policy-gate redteam-validate

evidence-crypto-preflight:
	@test -n "$${VV_HSM_ROOT_KEYS_JSON:-}" || (echo "ERROR: Missing VV_HSM_ROOT_KEYS_JSON"; echo "Hint: export VV_HSM_ROOT_KEYS_JSON='{\"vv-evidence-root-v1\":\"<base64-32-byte-key>\"}'"; exit 1)
	$(PY) -c "import base64, json, os; kid=os.environ.get('VV_HSM_EVIDENCE_ROOT_KEY_ID','vv-evidence-root-v1').strip(); keys=json.loads(os.environ['VV_HSM_ROOT_KEYS_JSON']); assert isinstance(keys, dict) and keys, 'VV_HSM_ROOT_KEYS_JSON must be a non-empty JSON object'; assert kid in keys, f'missing key id: {kid}'; raw=base64.b64decode(keys[kid]); assert len(raw) in (16,24,32), 'root key must decode to 16/24/32 bytes'; print(f'evidence crypto preflight ok (key_id={kid})')"

demo-preflight-help:
	@echo "Use .env.demo-preflight.local for local demo runs."
	@echo "Required values:"
	@echo "  VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON"
	@echo "  VV_TG_SPECTRASTRIKE_ED25519_PUBKEY"
	@echo "  VV_TG_OPERATOR_TENANT_MAP"
	@echo "  VV_HSM_EVIDENCE_ROOT_KEY_ID"
	@echo "  VV_HSM_ROOT_KEYS_JSON"
	@echo ""
	@echo "Then run:"
	@echo "  make spectrastrike-connect-check"
	@echo "  make seed-clients"

bootstrap-local-integration:
	@mkdir -p integration-deliverables/spectrastrike-vectorvue
	@printf '%s\n' \
		"# SpectraStrike-VectorVue Deliverables Index" \
		"" \
		"- \`spectrastrike-deliverables-list.md\`: artifacts and implementation inputs SpectraStrike must provide to send telemetry securely." \
		"- \`vectorvue-acceptance-deliverables-list.md\`: mandatory VectorVue-side controls and evidence required to accept integration traffic." \
		> integration-deliverables/spectrastrike-vectorvue/DELIVERABLES_INDEX.md
	@printf '%s\n' \
		"# SpectraStrike Deliverables (to send telemetry to VectorVue)" \
		"" \
		"1. Service identity name: \`spectrastrike-producer\`" \
		"2. mTLS client credentials: \`client.crt\`, \`client.key\`, trusted \`ca.crt\`" \
		"3. Ed25519 signing keypair (\`private\` retained by SpectraStrike, \`public\` delivered to VectorVue)" \
		"4. Canonical telemetry signing implementation (\`\"{timestamp}.{nonce}.\" + raw_json\`)" \
		"5. Replay-safe sender behavior (unique nonce + synchronized time + bounded retries)" \
		"6. Operator identifiers that match approved VectorVue tenant mapping" \
		"7. Validation package: valid signed sample, invalid signature sample, pinned cert fingerprint" \
		> integration-deliverables/spectrastrike-vectorvue/spectrastrike-deliverables-list.md
	@printf '%s\n' \
		"# VectorVue Acceptance Deliverables (required to accept SpectraStrike integration)" \
		"" \
		"1. Gateway trust config: mTLS/signature required, identity pin map, Ed25519 public key, operator->tenant map" \
		"2. Service cert artifacts: \`deploy/certs/server.crt\`, \`deploy/certs/server.key\`, \`deploy/certs/ca.crt\`" \
		"3. Replay/rate-limit controls configured with production backend" \
		"4. Internal queue + DLQ configured (no public queue exposure)" \
		"5. Evidence encryption controls: \`VV_HSM_EVIDENCE_ROOT_KEY_ID\`, \`VV_HSM_ROOT_KEYS_JSON\`" \
		"6. Tamper-evident audit logging controls" \
		"7. Validation pass evidence: preflight, policy gate, red-team, and tenant smoke checks" \
		"8. Dual-control governance approvals for federation enablement" \
		> integration-deliverables/spectrastrike-vectorvue/vectorvue-acceptance-deliverables-list.md
	@printf '%s\n' \
		"# SpectraStrike ↔ VectorVue Integration Deliverables (Local Pack)" \
		"" \
		"This local folder is generated by \`make bootstrap-local-integration\` and is gitignored." \
		> integration-deliverables/spectrastrike-vectorvue/00_README.md
	@if [ ! -f .env.demo-preflight.local ]; then \
		printf '%s\n' \
		"# Local-only demo/preflight variables for SpectraStrike <-> VectorVue hardened integration" \
		"# Auto-generated by make bootstrap-local-integration (gitignored)" \
		"" \
		"VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON=$(VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON)" \
		"VV_TG_SPECTRASTRIKE_ED25519_PUBKEY=$(VV_TG_SPECTRASTRIKE_ED25519_PUBKEY)" \
		"VV_FEDERATION_SPECTRASTRIKE_ED25519_PUBKEY=$(VV_FEDERATION_SPECTRASTRIKE_ED25519_PUBKEY)" \
		"VV_TG_OPERATOR_TENANT_MAP=$(VV_TG_OPERATOR_TENANT_MAP)" \
		"VV_HSM_EVIDENCE_ROOT_KEY_ID=$(VV_HSM_EVIDENCE_ROOT_KEY_ID)" \
		"VV_HSM_ROOT_KEYS_JSON=$(VV_HSM_ROOT_KEYS_JSON)" \
		"VV_DB_PASSPHRASE=$(DB_PASSPHRASE)" \
		> .env.demo-preflight.local; \
	fi
