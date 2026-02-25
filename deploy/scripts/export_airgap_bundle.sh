#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BUNDLE_DIR="${OUT_DIR}/vectorvue_airgap_${STAMP}"
ARCHIVE_PATH="${OUT_DIR}/vectorvue_airgap_${STAMP}.tar.gz"

mkdir -p "${BUNDLE_DIR}" "${OUT_DIR}"

PG_CONTAINER="${PG_CONTAINER:-vectorvue_postgres}"
PG_USER="${PG_USER:-vectorvue}"
PG_DB="${PG_DB:-vectorvue_db}"
DUMP_FILE="${BUNDLE_DIR}/vectorvue_db_backup.dump"

if docker ps --format '{{.Names}}' | grep -q "^${PG_CONTAINER}$"; then
  docker exec "${PG_CONTAINER}" pg_dump -U "${PG_USER}" -F c "${PG_DB}" > "${DUMP_FILE}"
  echo "Database dump exported: ${DUMP_FILE}"
else
  echo "[WARN] PostgreSQL container ${PG_CONTAINER} is not running; skipping DB dump"
fi

mkdir -p "${BUNDLE_DIR}/app" "${BUNDLE_DIR}/deploy" "${BUNDLE_DIR}/docs/manuals"

cp -a "${ROOT_DIR}"/*.py "${BUNDLE_DIR}/app/" 2>/dev/null || true
cp -a "${ROOT_DIR}/engines" "${BUNDLE_DIR}/app/"
cp -a "${ROOT_DIR}/scripts" "${BUNDLE_DIR}/app/"
cp -a "${ROOT_DIR}/sql" "${BUNDLE_DIR}/app/"
cp -a "${ROOT_DIR}/requirements.txt" "${BUNDLE_DIR}/app/"
cp -a "${ROOT_DIR}/Dockerfile" "${BUNDLE_DIR}/app/"
cp -a "${ROOT_DIR}/docker-compose.yml" "${BUNDLE_DIR}/app/"
cp -a "${ROOT_DIR}/Makefile" "${BUNDLE_DIR}/app/"
cp -a "${ROOT_DIR}/deploy"/* "${BUNDLE_DIR}/deploy/"
cp -a "${ROOT_DIR}/docs/manuals/Deployment.md" "${BUNDLE_DIR}/docs/manuals/"
cp -a "${ROOT_DIR}/docs/manuals/POSTGRES_USAGE_GUIDE.md" "${BUNDLE_DIR}/docs/manuals/"

cat > "${BUNDLE_DIR}/AIRGAP_UPDATE_INSTRUCTIONS.txt" <<'INSTR'
VectorVue Air-Gap Update Procedure
1. Transfer this archive to the offline environment via approved media.
2. Extract archive: tar -xzf vectorvue_airgap_*.tar.gz
3. Generate or copy TLS certificates into deploy/certs.
4. Build image offline: docker compose build --no-cache vectorvue_app
5. Start stack: docker compose up -d postgres redis vectorvue_app nginx
6. Restore DB if present:
   pg_restore -U vectorvue -d vectorvue_db vectorvue_db_backup.dump
7. Validate:
   ./scripts/test_phase6_functional.sh
   ./scripts/test_phase6_security.sh
INSTR

( cd "${OUT_DIR}" && tar -czf "${ARCHIVE_PATH}" "$(basename "${BUNDLE_DIR}")" )
echo "Air-gap bundle created: ${ARCHIVE_PATH}"
