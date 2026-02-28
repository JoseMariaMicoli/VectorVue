<!--
Copyright (c) 2026 NyxeraLabs
Author: Jose Maria Micoli
Licensed under BSL 1.1
Change Date: 2033-02-22 -> Apache-2.0
-->

# Full Federation Integration

## Trust Model

- Explicit trust anchors: certificate pin map + Ed25519 public keys.
- No shared symmetric feedback secrets.
- Tenant mapping is mandatory before persistence.

## Threat Model

- Signature forgery
- Payload tampering
- Replay attacks
- Cross-tenant spoofing
- Redirect abuse and downgrade attempts

## Cryptographic Flows

1. SpectraStrike signs payloads with Ed25519.
2. Gateway verifies signatures and anti-replay constraints.
3. Gateway signs feedback response with active Ed25519 feedback key.
4. SpectraStrike verifies response by `kid` keyring.

## mTLS Handshake Flow

- Client cert required.
- Service identity asserted by header.
- Cert fingerprint must match identity allowlist.
- Violations fail with `401`.

## Signing Flow

- Ingress signing input: `timestamp.nonce.raw_body`.
- Feedback signing input: `tenant|signed_at|nonce|schema|kid|canonical_data`.
- Signature algorithm: `Ed25519`.

## Attestation Propagation

`attestation_measurement_hash` is validated and preserved through ingest, cognitive graph records, feedback adjustments, and policy decision input.

## Policy Engine Binding

Feedback adjustments bind to execution fingerprints and attestation hashes. Unverified adjustments are not applied.

## Replay Protection Model

- Timestamp skew checks
- Nonce one-time registration with TTL
- Repeat nonce is hard-failed

## Failure Modes

- Invalid signature: reject
- Unknown key id (`kid`): reject
- Schema mismatch: reject
- Mapping violation: reject
- Replay nonce: reject

## Audit Logging Model

- Accept/reject events include request id and reason.
- Cognitive graph and feedback issuance events are recorded.
- Host smoke logs are persisted under SpectraStrike audit path.

## Production Deployment Considerations

- Use HSM/Vault-backed key management.
- Rotate mTLS and Ed25519 keys on schedule.
- Separate signing domains per tenant for high-scale deployments.
- Mirror audit logs into immutable external storage.

## Local Persistent Federation Setup

For local persistent runs, keep runtime federation values in gitignored:

- `local_federation/.env.vectorvue.local`

Bootstrap/start:

```bash
cd VectorVue
make local-federation-up
```

Tracked dummy template for documentation and onboarding:

- `docs/examples/vectorvue_local_federation.env.dummy`
