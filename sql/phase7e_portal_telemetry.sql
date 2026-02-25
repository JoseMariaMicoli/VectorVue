-- Copyright (c) 2026 NyxeraLabs
-- Author: José María Micoli
-- Licensed under BSL 1.1
-- Change Date: 2033-02-17 → Apache-2.0
--
-- You may:
-- ✔ Study
-- ✔ Modify
-- ✔ Use for internal security testing
--
-- You may NOT:
-- ✘ Offer as a commercial service
-- ✘ Sell derived competing products

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

