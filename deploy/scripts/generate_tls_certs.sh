#!/usr/bin/env bash

# Copyright (c) 2026 Jose Maria Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

set -euo pipefail

CERT_DIR="${1:-deploy/certs}"
DAYS="${DAYS:-365}"
SERVER_CN="${SERVER_CN:-vectorvue.local}"
CLIENT_CN="${CLIENT_CN:-vectorvue-client}"

mkdir -p "${CERT_DIR}"
chmod 755 "${CERT_DIR}"

# Create a local CA for server and client certificates.
openssl req -x509 -newkey rsa:4096 -sha256 -days "${DAYS}" -nodes \
  -subj "/CN=VectorVue-CA" \
  -keyout "${CERT_DIR}/ca.key" \
  -out "${CERT_DIR}/ca.crt"

# Server certificate for nginx and optional PostgreSQL TLS.
openssl req -newkey rsa:4096 -nodes \
  -subj "/CN=${SERVER_CN}" \
  -keyout "${CERT_DIR}/server.key" \
  -out "${CERT_DIR}/server.csr"
openssl x509 -req -sha256 -days "${DAYS}" \
  -in "${CERT_DIR}/server.csr" \
  -CA "${CERT_DIR}/ca.crt" \
  -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/server.crt"

# Client certificate for Phase 7 mTLS validation tests.
openssl req -newkey rsa:4096 -nodes \
  -subj "/CN=${CLIENT_CN}" \
  -keyout "${CERT_DIR}/client.key" \
  -out "${CERT_DIR}/client.csr"
openssl x509 -req -sha256 -days "${DAYS}" \
  -in "${CERT_DIR}/client.csr" \
  -CA "${CERT_DIR}/ca.crt" \
  -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/client.crt"

chmod 644 "${CERT_DIR}"/*.key
chmod 644 "${CERT_DIR}"/*.crt
rm -f "${CERT_DIR}"/*.csr "${CERT_DIR}"/*.srl

echo "TLS assets generated in ${CERT_DIR}"
