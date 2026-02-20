#!/usr/bin/env bash

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

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

ROUNDS="${1:-200}"

echo "[PERF] Warm-up health endpoint"
for _ in 1 2 3; do
  curl -fsS --insecure https://127.0.0.1/healthz >/dev/null
  sleep 1
done

echo "[PERF] Measure health endpoint latency over ${ROUNDS} rounds"
START="$(date +%s)"
for _ in $(seq 1 "${ROUNDS}"); do
  curl -fsS --insecure https://127.0.0.1/healthz >/dev/null
done
END="$(date +%s)"

DURATION=$((END - START))
RPS=0
if [[ "${DURATION}" -gt 0 ]]; then
  RPS=$((ROUNDS / DURATION))
fi

echo "Total seconds: ${DURATION}"
echo "Requests/second: ${RPS}"

echo "[PERF] PostgreSQL connection count"
docker compose exec -T -e PGPASSWORD=strongpassword postgres psql -U vectorvue -d vectorvue_db -c "select count(*) as active_connections from pg_stat_activity;"

echo "[PERF] Resource snapshot"
docker stats --no-stream vectorvue_app vectorvue_postgres vectorvue_redis vectorvue_nginx

echo "Performance validation complete"
