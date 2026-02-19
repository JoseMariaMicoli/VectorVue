<sub>Copyright (c) 2026 Jose Maria Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue Compliance API Specification

This specification defines tenant-scoped compliance and auditor API behavior.

## 1. Response Envelope

Compliance responses return signed payload envelopes:

```json
{
  "data": {},
  "signature": {
    "algorithm": "HMAC-SHA256",
    "key_id": "vv-compliance-v1",
    "signed_at": "2026-02-19T15:30:00Z",
    "signature": "hex_hmac"
  }
}
```

## 2. Authentication and Authorization

- Bearer JWT required for tenant-scoped compliance reads
- Tenant resolved from JWT `tenant_id`
- `POST /audit/session` requires role `auditor`, `admin`, or `lead`

## 3. Endpoints

### `POST /audit/session`

Creates a time-limited audit session token record.

### `GET /compliance/frameworks`

Returns active frameworks and latest framework scores for tenant.

### `GET /compliance/{framework}/controls`

Returns mapped controls and latest evaluated control state.

### `GET /compliance/{framework}/score`

Returns latest compliance score and coverage.

### `GET /compliance/{framework}/report`

Returns control summary, dataset hash, evidence metadata, and report context.

### `GET /compliance/audit-window`

Returns observation/evidence/evaluation counts for selected framework and period.

## 4. Integrity and Reproducibility Model

- append-only compliance evidence records
- hash chain integrity between compliance events
- dataset hash for deterministic export validation
- signed API response envelope for transmission integrity checks

## 5. Operational Requirements

1. Apply migrations and deploy workers.
2. Keep daily compliance evaluation jobs active.
3. Validate endpoint behavior in smoke checks before audit windows.

## 6. Related References

- [Auditor Guide](./AUDITOR_GUIDE.md)
- [Client API Manual](./manuals/CLIENT_API_MANUAL.md)

