#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-check}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
REPORT_FILE="${ROOT_DIR}/deploy/security_hardening_report.txt"

check_cmd() {
  local cmd="$1"
  if command -v "${cmd}" >/dev/null 2>&1; then
    echo "[OK] ${cmd} present"
  else
    echo "[WARN] ${cmd} missing"
  fi
}

write_report() {
  {
    echo "VectorVue Phase 6 Security Hardening Report"
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "Container Security"
    grep -n "read_only:\|no-new-privileges\|cap_drop" "${COMPOSE_FILE}" || true
    echo
    echo "Database Security"
    grep -n "ssl_min_protocol_version\|archive_mode\|password_encryption" "${ROOT_DIR}/deploy/postgres/postgresql.conf" || true
    echo
    echo "Network Security"
    grep -n "ssl_protocols\|Strict-Transport-Security\|ssl_verify_client" "${ROOT_DIR}/deploy/nginx/conf.d/vectorvue.conf" || true
    echo
    echo "Application Security"
    grep -n "AES-256-GCM\|PBKDF2\|HMAC\|RBAC\|audit" "${ROOT_DIR}/vv_core.py" | head -n 20 || true
  } > "${REPORT_FILE}"
}

if [[ "${MODE}" == "check" ]]; then
  check_cmd docker
  check_cmd openssl
  check_cmd psql
  check_cmd redis-cli
  write_report
  echo "Hardening check report written: ${REPORT_FILE}"
  exit 0
fi

if [[ "${MODE}" == "apply" ]]; then
  echo "Applying recommended file permissions for deployment assets"
  chmod 700 "${ROOT_DIR}/deploy/certs" 2>/dev/null || true
  chmod 600 "${ROOT_DIR}/deploy/certs"/*.key 2>/dev/null || true
  chmod 644 "${ROOT_DIR}/deploy/certs"/*.crt 2>/dev/null || true
  chmod 640 "${ROOT_DIR}/deploy/systemd/vectorvue.service" || true
  write_report
  echo "Apply mode completed. Report: ${REPORT_FILE}"
  exit 0
fi

echo "Usage: $0 [check|apply]"
exit 1
