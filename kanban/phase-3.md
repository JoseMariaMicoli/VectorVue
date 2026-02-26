## Sprint 3.1 — Schema Enforcement
Status: Done
Owner: José María Micoli
Risk Level: High
Security Impact: Blocks malformed telemetry and invalid MITRE mappings before processing pipeline entry.

### Tasks
- [x] Define canonical telemetry schema
- [x] Reject additional payload properties
- [x] Validate MITRE ATT&CK technique/tactic formats
- [x] Route schema violations to DLQ
- [x] Add schema and MITRE security tests
- [x] Update sprint docs and architecture artifacts

### Validation Checklist
- [x] Security test added
- [ ] Manual verification done
- [x] No tenant boundary regression
