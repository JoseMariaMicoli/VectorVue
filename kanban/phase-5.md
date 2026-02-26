## Sprint 5.1 — Service Identity
Status: Done
Owner: José María Micoli
Risk Level: High
Security Impact: Enforces cert-based service identity verification and removes shared trust variable from telemetry gateway authentication.

### Tasks
- [x] Enforce service identity authentication in gateway
- [x] Require identity-to-cert fingerprint mapping policy
- [x] Remove shared single-value trust var from gateway config
- [x] Add service identity cert/key/CA path checks
- [x] Add security tests for identity mismatch scenarios
- [x] Update sprint docs and architecture artifacts

### Validation Checklist
- [x] Security test added
- [ ] Manual verification done
- [x] No tenant boundary regression
