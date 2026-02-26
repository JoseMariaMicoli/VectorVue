# Phase 5 Sprint 5.1 - Service Identity

## Objective
Enforce explicit cert-based service identity authentication and remove shared service trust values.

## Deliverables
- Service identity auth enforcement in telemetry gateway.
- Shared trust env replacement with identity mapping policy.
- Service identity certificate path validation.
- Compose-level identity cert wiring for platform services.
- Security tests for unknown identity and cert mismatch rejection.

## Exit Criteria
- Unknown service identities are rejected.
- Identity/certificate mismatches are rejected.
- Shared single-value service trust is removed from gateway config.
