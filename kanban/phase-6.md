## Sprint 6.1 — Immutable Logging
Status: Done
Owner: José María Micoli
Risk Level: High
Security Impact: Adds append-only hash-chained audit logging with periodic seals and tamper detection for telemetry gateway events.

### Tasks
- [x] Implement append-only audit log module
- [x] Add hash-chain linkage and verification
- [x] Add periodic snapshot sealing records
- [x] Integrate gateway accepted/rejected event logging
- [x] Add security tests for tamper detection
- [x] Update sprint docs and architecture artifacts

### Validation Checklist
- [x] Security test added
- [ ] Manual verification done
- [x] No tenant boundary regression
