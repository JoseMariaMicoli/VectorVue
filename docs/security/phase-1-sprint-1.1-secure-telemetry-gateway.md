# Phase 1 Sprint 1.1 - Secure Telemetry Gateway

## Threat Model
- Asset: inbound telemetry stream integrity and service-to-service trust boundary.
- Trust boundary: private telemetry gateway network and authenticated ingest endpoint.
- Adversary: forged service client, replay actor, unauthorized internal caller.

## Attack Vectors Considered
- Unauthenticated telemetry POST calls.
- Caller identity spoofing without mTLS client certificate.
- Certificate substitution attack against expected producer identity.
- Unsigned payload submission and signature forgery.
- Nonce replay with reused signed requests.

## Mitigations Implemented
- New internal-only gateway service: `services.telemetry_gateway.main`.
- Mandatory mTLS identity header gate (`X-Client-Cert-Sha256`).
- Certificate pinning against trusted service identity certificate fingerprints.
- Mandatory Ed25519 payload signature validation via pinned public key (`VV_TG_SPECTRASTRIKE_ED25519_PUBKEY`).
- Strict timestamp skew validation (default 30s).
- Nonce replay guard with TTL enforcement.
- Runtime returns fail-closed responses for missing/invalid security controls.

## Residual Risk
- Current replay cache is in-memory and not shared across instances.
- mTLS signal is represented by trusted header contract from upstream TLS terminator.

## Future Improvements
- Move replay cache to Redis for multi-instance consistency.
- Bind gateway ingress to dedicated mTLS reverse proxy with direct certificate extraction.
- Add hardware-backed key lifecycle management for producer signing keys.
