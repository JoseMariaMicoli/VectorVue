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

CUSTOMER="${1:-}"
TENANT_NAME="${2:-}"
TENANT_ID="${3:-auto}"
PG_URL="${4:-postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db}"

if [[ -z "${CUSTOMER}" || -z "${TENANT_NAME}" ]]; then
  echo "Usage: $0 <customer_slug> <tenant_name> [tenant_id|auto] [pg_url]"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CUSTOMER_DIR="${ROOT_DIR}/deploy/customers/${CUSTOMER}"
TEMPLATE="${ROOT_DIR}/deploy/templates/customer.env.template"
ENV_FILE="${CUSTOMER_DIR}/customer.env"

mkdir -p "${CUSTOMER_DIR}"/{reports,logs,run,tmp,config}

if [[ ! -f "${TEMPLATE}" ]]; then
  echo "Template not found: ${TEMPLATE}"
  exit 1
fi

cp "${TEMPLATE}" "${ENV_FILE}"
sed -i "s/{{CUSTOMER_NAME}}/${CUSTOMER}/g" "${ENV_FILE}"
sed -i "s/{{TENANT_NAME}}/${TENANT_NAME}/g" "${ENV_FILE}"
sed -i "s/{{TENANT_ID}}/${TENANT_ID}/g" "${ENV_FILE}"

echo "Customer deployment scaffold ready: ${CUSTOMER_DIR}"

cd "${ROOT_DIR}"
docker compose run --rm -v "${ROOT_DIR}:/opt/vectorvue" vectorvue_app python scripts/bootstrap_tenant.py \
  --pg-url "${PG_URL}" \
  --tenant-name "${TENANT_NAME}" \
  --tenant-id "${TENANT_ID}"

echo "Customer bootstrap completed for '${CUSTOMER}'"
