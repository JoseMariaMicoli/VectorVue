#!/usr/bin/env bash

# Copyright (c) 2026 Jose Maria Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

set -euo pipefail

if [[ -f /var/lib/postgresql/certs/server.crt && -f /var/lib/postgresql/certs/server.key ]]; then
  cp /var/lib/postgresql/certs/server.crt "${PGDATA}/server.crt"
  cp /var/lib/postgresql/certs/server.key "${PGDATA}/server.key"
  chmod 600 "${PGDATA}/server.key"
  chmod 644 "${PGDATA}/server.crt"
fi

mkdir -p "${PGDATA}/wal_archive"
