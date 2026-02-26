# Phase 3 Sprint 3.1 - Schema Enforcement

## Threat Model
- Asset: telemetry semantic integrity and downstream analytics reliability.
- Adversary: malformed-event sender, schema-bypass sender, MITRE mapping forger.
- Trust boundary: telemetry gateway to processing engine validation boundary.

## Attack Vectors Considered
- Payloads with undeclared fields to smuggle unsafe data.
- Missing required canonical fields that break processing invariants.
- Invalid MITRE ATT&CK TTP identifiers to poison attribution analytics.

## Mitigations Implemented
- Added canonical telemetry schema model with `extra=forbid`.
- Enforced strict top-level ingest schema and canonical nested payload schema.
- Added MITRE technique code validation (`T####` / `T####.###`).
- Added MITRE tactic code validation (`TA####`).
- Routed canonical/schema violations to DLQ with explicit error metadata.

## Residual Risk
- Validation currently runs in gateway process; dedicated downstream schema registry is not yet deployed.

## Future Improvements
- Introduce versioned schema registry and compatibility policies.
- Add consumer-side schema verification gates before processing.
