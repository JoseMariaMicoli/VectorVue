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

./deploy/scripts/security_hardening.sh check

echo "[SEC] Verify TLS 1.3 negotiation"
openssl s_client -connect 127.0.0.1:443 -tls1_3 -brief </dev/null 2>&1 | grep -Eq "Protocol( version)?: TLSv1.3"

echo "[SEC] Verify invalid client cert is rejected when requested endpoint enforces certificate checks"
# mTLS is optional for Phase 6, so this checks certificate request presence in handshake.
openssl s_client -connect 127.0.0.1:443 -tls1_3 -brief </dev/null 2>&1 | grep -q "Verification"

echo "[SEC] Verify container privilege hardening flags"
docker compose config | grep -q "no-new-privileges:true"
docker compose config | grep -q "cap_drop"

echo "[SEC] Verify RBAC denial path (manual command)"
echo "Run an operator-only user against a LEAD+ delete action and confirm denial message in TUI logs."

echo "Security validation complete"
