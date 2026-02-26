# Phase 5 Sprint 5.1 - Service Identity

## Threat Model
- Asset: service-to-service trust decisions for telemetry ingress.
- Adversary: rogue internal caller, spoofed service identity, reused static trust values.
- Trust boundary: gateway ingress identity authentication.

## Attack Vectors Considered
- Unknown service identity attempting ingest.
- Certificate fingerprint mismatch for claimed identity.
- Implicit trust based on a single static environment value.

## Mitigations Implemented
- Replaced single shared cert fingerprint env with explicit identity map:
  - `VV_TG_ALLOWED_SERVICE_IDENTITIES_JSON`
- Enforced identity-aware cert auth headers:
  - `X-Service-Identity`
  - `X-Client-Cert-Sha256`
- Gateway now rejects unknown identities and identity/fingerprint mismatches.
- Added service identity certificate/key/CA path validation at startup.
- Added per-service identity cert mounts/env paths in compose service definitions.

## Residual Risk
- Trust still depends on trusted TLS terminator header integrity.
- Identity map remains static configuration and requires controlled deployment updates.

## Future Improvements
- Move identity map to signed control-plane policy distribution.
- Bind direct mTLS peer cert extraction in gateway runtime (no proxy header dependency).
