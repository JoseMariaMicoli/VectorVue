## Sprint 2.1 — Queue Layer
Status: Done
Owner: José María Micoli
Risk Level: High
Security Impact: Introduces internal queue isolation with DLQ controls and integrity hashing for telemetry handoff.

### Tasks
- [x] Deploy internal-only NATS queue service
- [x] Route valid telemetry to secure queue subject
- [x] Route malformed telemetry to DLQ subject
- [x] Add SHA-256 integrity hash to queue envelopes
- [x] Add security tests for queue and DLQ handling
- [x] Update sprint docs and architecture artifacts

### Validation Checklist
- [x] Security test added
- [ ] Manual verification done
- [x] No tenant boundary regression
