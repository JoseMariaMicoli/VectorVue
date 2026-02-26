# VectorVue Federation Gateway Configuration

This folder contains local/operator-managed configuration references for the
SpectraStrike federation intake channel.

Do not commit secrets. Certificates and private keys are ignored via
`.gitignore` in this directory.

Required gateway environment values:

- `VV_TG_REQUIRE_MTLS=1`
- `VV_TG_REQUIRE_PAYLOAD_SIGNATURE=1`
- `VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON`
- `VV_TG_SPECTRASTRIKE_ED25519_PUBKEY`
- `VV_FEDERATION_SPECTRASTRIKE_ED25519_PUBKEY`
- `VV_TG_OPERATOR_TENANT_MAP`
- `VV_TG_NONCE_BACKEND`
- `VV_TG_REDIS_URL`
- `VV_TG_RATE_LIMIT_BACKEND`
- `VV_TG_ALLOWED_SCHEMA_VERSION`
- `VV_TG_ENFORCE_SCHEMA_VERSION`

Certificate trust chain:

1. `deploy/certs/ca.crt` trusted CA root/intermediate.
2. `deploy/certs/server.crt` and `deploy/certs/server.key` gateway identity.
3. SpectraStrike client cert fingerprint pinned in
   `VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON`.
