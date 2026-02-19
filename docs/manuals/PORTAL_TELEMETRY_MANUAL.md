<sub>Copyright (c) 2026 Jose Maria Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue Portal Telemetry Manual

This manual defines how client portal telemetry is captured for security intelligence and assurance analytics.

## 1. Purpose

Telemetry supports:

- time-to-acknowledge measurement
- remediation latency measurement
- dashboard/report consultation analysis
- defensive effectiveness model datasets

This is not marketing telemetry.

## 2. Privacy Constraints

Telemetry does not store:

- IP addresses
- user-agent strings
- keystrokes or typed content

Telemetry stores only security workflow actions.

## 3. Event Types

- `FINDING_VIEWED`
- `FINDING_ACKNOWLEDGED`
- `REMEDIATION_OPENED`
- `REMEDIATION_COMPLETED`
- `REPORT_DOWNLOADED`
- `DASHBOARD_VIEWED`

## 4. Storage Model

Table: `client_activity_events`

Core fields:

- `id`
- `tenant_id`
- `user_id` (nullable)
- `event_type`
- `object_type`
- `object_id`
- `severity` (nullable)
- `timestamp`
- `metadata_json`

Primary index:

- `(tenant_id, timestamp DESC)`

## 5. Runtime Flow

1. Portal calls telemetry endpoint.
2. API validates tenant auth and event schema.
3. API applies basic rate limiting.
4. API sanitizes metadata.
5. Event is inserted asynchronously.
6. API returns `202 Accepted` quickly.

## 6. Operational Commands

```bash
make phase7e-migrate
make phase8-migrate
make seed-clients
```

## 7. Analytics Usage

Telemetry data can be used to compute:

- MTTA (Mean Time to Acknowledge)
- MTTR (Mean Time to Remediate)
- risk awareness behavior
- defensive responsiveness indicators

Reference SQL: `docs/manuals/PHASE7E_TELEMETRY_QUERIES.sql`

