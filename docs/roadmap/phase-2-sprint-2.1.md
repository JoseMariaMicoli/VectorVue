# Phase 2 Sprint 2.1 - Queue Layer

## Objective
Deploy a secure internal queue path for telemetry with dead-letter handling and integrity hashing.

## Deliverables
- Internal-only NATS service in compose.
- Gateway queue publisher for accepted telemetry.
- DLQ publisher for malformed payloads.
- SHA-256 payload integrity hash in queued envelopes.
- Security tests for queue publish and DLQ behavior.

## Exit Criteria
- Queue service has no public host exposure.
- Malformed telemetry is routed to DLQ.
- All queued messages include integrity hash metadata.
