# Phase 2 Sprint 2.1 - Message Queue Isolation

## Threat Model
- Asset: accepted telemetry events in transit between gateway and downstream processing.
- Adversary: malformed event sender, queue poisoner, replay/burst actor.
- Trust boundary: telemetry gateway to internal queue transport.

## Attack Vectors Considered
- Public exposure of queue endpoint.
- Malformed payloads bypassing controls and entering processing stream.
- Message tampering during handoff to downstream consumers.

## Mitigations Implemented
- Introduced internal NATS queue service on private network only.
- Gateway publishes accepted telemetry to dedicated ingest subject.
- Malformed payloads are routed to DLQ subject with error metadata.
- Every queued message includes SHA-256 integrity hash over canonical payload.
- Gateway fails closed when queue publish cannot be completed.

## Residual Risk
- Consumer-side integrity verification is not yet enforced in this sprint.
- NATS ACL hardening is pending in later infrastructure hardening phases.

## Future Improvements
- Enforce consumer-side hash verification and reject hash mismatches.
- Add per-subject retention and poison message quarantine workflows.
- Add NATS account-level authz and mTLS between gateway and queue.
