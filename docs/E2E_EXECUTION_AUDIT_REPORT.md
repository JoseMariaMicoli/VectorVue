<!--
Copyright (c) 2026 NyxeraLabs
Author: Jose Maria Micoli
Licensed under BSL 1.1
Change Date: 2033-02-22 -> Apache-2.0
-->

# E2E Execution Audit Report

## Scope

Validation of VectorVue telemetry gateway under asymmetric federation with SpectraStrike producer.

## Commands Used

```bash
cd VectorVue
make local-federation-up

cd ../SpectraStrike
PYTHONPATH=src .venv/bin/python -m pkg.integration.host_integration_smoke --tenant-id 10000000-0000-0000-0000-000000000001 --check-vectorvue
```

Additional runtime checks:

- `sliver-client version`
- `PYTHONPATH=src .venv/bin/pytest -q tests/unit/test_firecracker_microvm_runner.py`

## Runtime Evidence

- VectorVue accepted telemetry and findings from host smoke.
- Status observed: `vectorvue_event_status=accepted`.
- Cognitive feedback flow observed as accepted and signature-verified by SpectraStrike client.

Primary detailed log:

- `../SpectraStrike/local_docs/audit/final-e2e-asymmetric-20260227-134036.log`

## Signature Verification Proof

- Gateway rejects unsigned/forged telemetry.
- Gateway signs feedback responses using Ed25519 active `kid`.
- SpectraStrike verifier confirms feedback signature validity (`feedback_signature_verified=True`).

## Attestation Proof

- `attestation_measurement_hash` is validated and propagated in cognitive graph + feedback records.
- End-to-end attestation check observed as `attestation_hash_verified=True`.

## Failure Cases Tested

- Sliver wrapper dry-run path failed due CLI incompatibility (`unknown flag --target`).
- Security failure paths (replay, signature forgery, schema mismatch) covered by gateway/security unit tests.

## Final Conclusion

VectorVue federation ingress/feedback loop is operating with mandatory asymmetric verification, replay protection, and strict tenant/service identity controls. Functional E2E flow is accepted; only wrapper-level Sliver command compatibility remains for execution-path completeness.

## Local Persistent Configuration Note (2026-02-28)

- Runtime local federation values are persisted in gitignored `local_federation/.env.vectorvue.local`.
- `make local-federation-up` reuses this local file if present.
- Tracked dummy template for docs/onboarding:
  - `docs/examples/vectorvue_local_federation.env.dummy`
