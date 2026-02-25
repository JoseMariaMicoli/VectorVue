<sub>Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue Portal Telemetry Manual

## Purpose

This manual explains portal usage telemetry for defensive intelligence.
It is not marketing analytics.

Primary outcomes:
- measure time to acknowledge risk
- measure time to remediate
- measure dashboard and report consultation behavior
- prepare clean datasets for defensive effectiveness models

## Privacy Guarantees

Telemetry excludes:
- IP addresses
- user-agent strings
- keystrokes or typed content

Telemetry includes only workflow actions:
- page-level and object-level security operations behavior

## Event Types

- `FINDING_VIEWED`
- `FINDING_ACKNOWLEDGED`
- `REMEDIATION_OPENED`
- `REMEDIATION_COMPLETED`
- `REPORT_DOWNLOADED`
- `DASHBOARD_VIEWED`

## Data Model

Table: `client_activity_events`

Fields:
- `id` (uuid)
- `tenant_id`
- `user_id` (nullable)
- `event_type`
- `object_type` (`finding|report|dashboard|remediation`)
- `object_id`
- `severity` (nullable snapshot)
- `timestamp`
- `metadata_json`

Index:
- `(tenant_id, timestamp desc)`

## Runtime Flow

1. Portal UI calls `/api/proxy/events`.
2. Proxy forwards request to `/api/v1/client/events`.
3. API validates JWT tenant context.
4. API validates event type/object type.
5. API applies basic rate limiting.
6. API sanitizes metadata (drops restricted keys).
7. API inserts asynchronously in background task.
8. API returns quickly (`202 Accepted`) without blocking UI.

## Operational Steps

### Enable telemetry schema

```bash
make phase7e-migrate
```

### Seed demo and generate events

```bash
make seed-clients
```

Then use portal pages as a normal client:
- open dashboards
- open findings
- open remediation page
- download reports

### Validate event ingestion

```sql
SELECT tenant_id, event_type, object_type, COUNT(*) AS total
FROM client_activity_events
GROUP BY tenant_id, event_type, object_type
ORDER BY tenant_id, event_type, object_type;
```

## Analytics Queries

Use:
- `docs/manuals/PHASE7E_TELEMETRY_QUERIES.sql`

Included metrics:
- MTTA (mean time to acknowledge)
- MTTR (mean time to remediate)

