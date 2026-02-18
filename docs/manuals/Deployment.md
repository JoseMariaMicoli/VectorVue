<sub>Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue Deployment & Hardening Guide (Phase 6 / 6.5)

## Scope

This runbook makes VectorVue production-ready with:
- Multi-stage Docker build
- Docker Compose stack (`vectorvue_app`, `vectorvue_runtime`, `postgres`, `redis`, `nginx`)
- systemd service integration
- TLS 1.3 and mTLS preparation
- Tenant-isolated REST API runtime
- Air-gap deployment packaging
- Security hardening checks
- Functional, security, and performance validation scripts

All existing TUI views, keybindings, database features, RBAC checks, audit logging, encryption, and RuntimeExecutor behavior remain unchanged.

## 1. Prerequisites

1. Docker Engine + Compose plugin
2. OpenSSL
3. Linux host with systemd (for bare-metal service mode)
4. Ports open only as needed: `443/tcp` (and optional `5433/tcp` for local DB admin)

## 2. Environment Variables

Use these PostgreSQL values (required by Phase 6+):

```bash
export POSTGRES_USER=vectorvue
export POSTGRES_PASSWORD=strongpassword
export POSTGRES_DB=vectorvue_db
```

VectorVue uses:

```bash
export VV_DB_BACKEND=postgres
export VV_DB_URL=postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db
```

## 3. TLS Certificate Generation

Generate CA/server/client certificates:

```bash
./deploy/scripts/generate_tls_certs.sh
```

Output location: `deploy/certs/`.

- `server.crt` + `server.key`: nginx TLS termination (and optional PostgreSQL TLS)
- `ca.crt`: trust anchor
- `client.crt` + `client.key`: Phase 7 mTLS test client

Certificates are mounted into containers read-only.

## 4. Start Production Stack (Docker + REST API)

```bash
make deploy
```

Services:
- `vectorvue_app`: FastAPI client-safe REST API (`vv_client_api.py`) on `:8080`
- `vectorvue_runtime`: RuntimeExecutor background worker (`vv_core_postgres.py --mode service`)
- `postgres`: primary database, SSL enabled, WAL archive enabled
- `redis`: cache/task coordination backend
- `nginx`: TLS 1.3 reverse proxy and secure headers

Per-tenant isolated stack (separate compose project + container namespace):

```bash
make customer-deploy-isolated \
  CUSTOMER=acme \
  TENANT_NAME="ACME Industries" \
  HTTP_HOST_PORT=8081 \
  HTTPS_HOST_PORT=8444 \
  POSTGRES_HOST_PORT=5544
```

For a second tenant, use a different `CUSTOMER` and different host ports.

## 5. PostgreSQL Initialization / Migration / Tenant Isolation

Fresh reset:

```bash
make pg-reset
```

SQLite migration:

```bash
make pg-migrate
```

Seed:

```bash
make seed-clients
```

Smoke tests:

```bash
make pg-smoke
```

Phase 6.5 tenant migration:

```bash
make phase65-migrate
```

REST API validation:

```bash
make api-smoke
```

## 6. systemd Integration (Host Mode)

Install unit:

```bash
sudo install -D -m 0640 deploy/systemd/vectorvue.service /etc/systemd/system/vectorvue.service
sudo mkdir -p /etc/vectorvue
```

Optional env file `/etc/vectorvue/vectorvue.env`:

```ini
VV_DB_BACKEND=postgres
VV_DB_HOST=127.0.0.1
VV_DB_PORT=5432
VV_DB_NAME=vectorvue_db
VV_DB_USER=vectorvue
VV_DB_PASSWORD=strongpassword
VV_RUN_MODE=service
VV_HEALTH_PORT=8080
```

Enable/start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable vectorvue.service
sudo systemctl start vectorvue.service
sudo systemctl status vectorvue.service
journalctl -u vectorvue.service -f
```

## 7. TLS / mTLS Notes

Nginx config enforces `TLSv1.3` and sets:
- HSTS
- X-Frame-Options
- X-Content-Type-Options
- CSP

mTLS is prepared with:
- `ssl_client_certificate /etc/nginx/certs/ca.crt`
- `ssl_verify_client optional`

For strict mTLS in Phase 7, switch to:

```nginx
ssl_verify_client on;
```

## 8. Optional HSM / PKCS#11 Key Loading

`vv_core_postgres.py` supports HSM-backed passphrase retrieval.

Enable file-backed secret mount mode:

```bash
export VV_HSM_ENABLED=1
export VV_HSM_KEY_FILE=/opt/vectorvue/config/service_passphrase.secret
```

Enable PKCS#11 mode:

```bash
export VV_HSM_ENABLED=1
export VV_PKCS11_MODULE=/usr/lib/your-pkcs11.so
export VV_HSM_KEY_LABEL=vectorvue-service-key
export VV_PKCS11_PIN=********
```

Every key retrieval writes an audit record to:
- `/var/lib/vectorvue/logs/key_access_audit.log`

## 9. Air-Gap Deployment

Create an offline bundle:

```bash
./deploy/scripts/export_airgap_bundle.sh
```

This packages:
- PostgreSQL dump (`pg_dump -F c`)
- App code + compose + Dockerfile
- Deployment assets and runbooks
- Air-gap update instructions

## 10. Security Hardening Checklist

Run automated checks:

```bash
./deploy/scripts/security_hardening.sh check
```

Checklist coverage:
- Container security: non-root, read-only FS, dropped capabilities
- Database security: TLS, SCRAM auth, WAL archive baseline, role constraints
- Application security: RBAC/audit/encryption references validated in source
- Network security: TLS 1.3 + secure headers + reverse proxy
- Monitoring/logging: systemd journals and service logs

## 11. Validation Scripts

Functional:

```bash
./scripts/test_phase6_functional.sh
```

Security:

```bash
./scripts/test_phase6_security.sh
```

Performance:

```bash
./scripts/test_phase6_performance.sh 200
```

## 12. Local Operator TUI Access

Production service mode runs RuntimeExecutor headless. For interactive TUI inside the container:

```bash
docker compose run --rm -it \
  -e VV_RUN_MODE=tui \
  vectorvue_app python vv.py
```

This preserves all existing views/keybindings and full operator workflow.

### Font and Theme Parity (Local vs Docker)

For terminal-native TUI rendering, fonts are provided by your host terminal emulator, not by the container runtime.  
Set your terminal font to **JetBrainsMono Nerd Font** for icon/glyph parity.  

Container defaults also enforce color parity:
- `TERM=xterm-256color`
- `COLORTERM=truecolor`
- `FORCE_COLOR=1`

## 13. Phase 7 and Phase 8 Integration Readiness

Phase 6/6.5 outputs required for next phases:
- PostgreSQL stable backend in production stack
- Redis operational for queue/caching expansion
- Nginx TLS reverse proxy with mTLS-ready certificate chain
- Containerized deployment with hardened defaults
- Centralized logs and audit trail preservation
- Tenant-isolated read-only REST API contract for customer portal
