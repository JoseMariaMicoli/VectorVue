#!/usr/bin/env bash
set -euo pipefail

PGDATA_DIR="${PGDATA:-/var/lib/postgresql/data}"
CERT_SRC_DIR="/var/lib/postgresql/certs"

if [[ -f "${CERT_SRC_DIR}/server.crt" && -f "${CERT_SRC_DIR}/server.key" ]]; then
  mkdir -p "${PGDATA_DIR}"
  cp "${CERT_SRC_DIR}/server.crt" "${PGDATA_DIR}/server.crt"
  cp "${CERT_SRC_DIR}/server.key" "${PGDATA_DIR}/server.key"
  chown postgres:postgres "${PGDATA_DIR}/server.crt" "${PGDATA_DIR}/server.key"
  chmod 644 "${PGDATA_DIR}/server.crt"
  chmod 600 "${PGDATA_DIR}/server.key"
fi

exec docker-entrypoint.sh postgres -c config_file=/etc/postgresql/postgresql.conf -c hba_file=/etc/postgresql/pg_hba.conf
