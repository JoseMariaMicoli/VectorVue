#!/usr/bin/env bash
set -euo pipefail

if [[ -f /var/lib/postgresql/certs/server.crt && -f /var/lib/postgresql/certs/server.key ]]; then
  cp /var/lib/postgresql/certs/server.crt "${PGDATA}/server.crt"
  cp /var/lib/postgresql/certs/server.key "${PGDATA}/server.key"
  chmod 600 "${PGDATA}/server.key"
  chmod 644 "${PGDATA}/server.crt"
fi

mkdir -p "${PGDATA}/wal_archive"
