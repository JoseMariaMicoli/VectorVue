-- Copyright (c) 2026 Jose Maria Micoli
-- Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

-- Phase 7E: Client portal usage telemetry for defensive intelligence datasets.

CREATE TABLE IF NOT EXISTS client_activity_events (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    user_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NULL,
    severity TEXT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_client_activity_events_tenant_timestamp
ON client_activity_events (tenant_id, timestamp DESC);

