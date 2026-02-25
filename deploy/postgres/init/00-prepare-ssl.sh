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

if [[ -f /var/lib/postgresql/certs/server.crt && -f /var/lib/postgresql/certs/server.key ]]; then
  cp /var/lib/postgresql/certs/server.crt "${PGDATA}/server.crt"
  cp /var/lib/postgresql/certs/server.key "${PGDATA}/server.key"
  chmod 600 "${PGDATA}/server.key"
  chmod 644 "${PGDATA}/server.crt"
fi

mkdir -p "${PGDATA}/wal_archive"
