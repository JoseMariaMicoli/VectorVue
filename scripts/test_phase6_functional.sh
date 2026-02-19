#!/usr/bin/env bash

# Copyright (c) 2026 Jose Maria Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "[1/6] Validate compose config"
docker compose config >/dev/null

if [[ ! -f deploy/certs/server.crt || ! -f deploy/certs/server.key || ! -f deploy/certs/ca.crt ]]; then
  echo "[prep] Generating TLS certificates"
  ./deploy/scripts/generate_tls_certs.sh
fi

echo "[prep] Build vectorvue_app image"
docker compose build vectorvue_app

echo "[2/6] Start required services"
docker compose up -d postgres redis vectorvue_app nginx

echo "[3/6] Wait for health"
docker compose ps

echo "[4/6] Verify VectorVue app health endpoint"
curl -fsS --retry 20 --retry-delay 2 --retry-connrefused https://127.0.0.1/healthz --insecure >/tmp/vectorvue_health.json

echo "[5/6] Validate PostgreSQL smoke tests"
docker compose run --rm \
  -e VV_DB_BACKEND=postgres \
  -e VV_DB_URL=postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db \
  vectorvue_app python -m unittest -q tests/test_postgres_smoke.py

echo "[6/6] RuntimeExecutor service mode check"
docker compose logs --tail=200 vectorvue_app | grep -q "RuntimeExecutor loop started"

echo "Functional validation complete"
