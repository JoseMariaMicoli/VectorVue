# Phase 0 - Sprint 0.1 - Telemetry Capability Removal

## Sprint Objective
Remove telemetry ingestion capability from the client API so tenant portal usage is constrained to read-only client data and signed compliance retrieval.

## Deliverables
- Removed active telemetry ingestion routes from runtime API.
- Removed SpectraStrike ingestion modules from codebase.
- Added DB cleanup script: `sql/phase0_sprint01_telemetry_removal.sql`.
- Added security regression tests for endpoint removal and method hardening.
- Updated security and architecture documentation for reduced attack surface.

## Exit Criteria
- No public client API endpoint accepts telemetry POST payloads.
- No `/api/v1/integrations/spectrastrike/*` endpoint is exposed.
- Regression tests confirm the removed attack surface.

## Roll-forward Notes
Next sprint should implement a dedicated private telemetry gateway with mTLS and signed payload validation. No telemetry ingestion should be reintroduced to client API.
