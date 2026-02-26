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

CERT_DIR="${1:-deploy/certs}"
DAYS="${DAYS:-365}"
SERVER_CN="${SERVER_CN:-vectorvue.local}"
CLIENT_CN="${CLIENT_CN:-vectorvue-client}"
SERVER_SAN_DNS_1="${SERVER_SAN_DNS_1:-localhost}"
SERVER_SAN_DNS_2="${SERVER_SAN_DNS_2:-vectorvue.local}"
SERVER_SAN_IP_1="${SERVER_SAN_IP_1:-127.0.0.1}"

mkdir -p "${CERT_DIR}"
chmod 755 "${CERT_DIR}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

cat >"${tmpdir}/ca_ext.cnf" <<EOF
[v3_ca]
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF

cat >"${tmpdir}/server_ext.cnf" <<EOF
[v3_server]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${SERVER_SAN_DNS_1},DNS:${SERVER_SAN_DNS_2},IP:${SERVER_SAN_IP_1}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

cat >"${tmpdir}/client_ext.cnf" <<EOF
[v3_client]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

# Create a local CA for server and client certificates.
openssl req -x509 -newkey rsa:4096 -sha256 -days "${DAYS}" -nodes \
  -subj "/CN=VectorVue-CA" \
  -keyout "${CERT_DIR}/ca.key" \
  -out "${CERT_DIR}/ca.crt" \
  -extensions v3_ca \
  -config "${tmpdir}/ca_ext.cnf"

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
  -out "${CERT_DIR}/server.crt" \
  -extensions v3_server \
  -extfile "${tmpdir}/server_ext.cnf"

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
  -out "${CERT_DIR}/client.crt" \
  -extensions v3_client \
  -extfile "${tmpdir}/client_ext.cnf"

chmod 644 "${CERT_DIR}"/*.key
chmod 644 "${CERT_DIR}"/*.crt
rm -f "${CERT_DIR}"/*.csr "${CERT_DIR}"/*.srl

echo "TLS assets generated in ${CERT_DIR}"
