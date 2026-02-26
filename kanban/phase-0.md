## Sprint 0.1 - Telemetry Capability Removal
Status: In Progress
Owner: José María Micoli
Risk Level: High
Security Impact: Removes public telemetry ingestion paths from client API to reduce external write attack surface.

### Tasks
- [x] Remove SpectraStrike ingestion router from runtime API.
- [x] Remove `/api/v1/client/events` telemetry ingestion endpoint.
- [x] Add SQL cleanup script for telemetry staging tables.
- [x] Add security regression tests for endpoint removal.
- [x] Update sprint security and architecture documentation.

### Validation Checklist
- [x] Security test added
- [ ] Manual verification done
- [x] No tenant boundary regression
