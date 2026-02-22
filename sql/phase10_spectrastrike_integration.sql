-- Copyright (c) 2026 NyxeraLabs
-- Author: José María Micoli
-- Licensed under BSL 1.1
-- Change Date: 2033-02-17 → Apache-2.0

-- Phase 10: SpectraStrike integration ingestion persistence.

CREATE TABLE IF NOT EXISTS spectrastrike_ingest_requests (
    request_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    endpoint TEXT NOT NULL,
    status TEXT NOT NULL,
    total_items INTEGER NOT NULL DEFAULT 0,
    accepted_items INTEGER NOT NULL DEFAULT 0,
    failed_items INTEGER NOT NULL DEFAULT 0,
    failed_references JSONB NOT NULL DEFAULT '[]'::jsonb,
    idempotency_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS spectrastrike_idempotency (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    endpoint TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    response_json JSONB NOT NULL,
    status_code INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, endpoint, idempotency_key)
);

CREATE TABLE IF NOT EXISTS spectrastrike_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    request_id UUID NOT NULL,
    event_uid TEXT NOT NULL,
    source_system TEXT NOT NULL,
    event_type TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    severity TEXT NOT NULL,
    asset_ref TEXT NOT NULL,
    message TEXT NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, event_uid)
);

CREATE TABLE IF NOT EXISTS spectrastrike_findings (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    request_id UUID NOT NULL,
    finding_uid TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ,
    asset_ref TEXT,
    recommendation TEXT,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, finding_uid)
);

CREATE INDEX IF NOT EXISTS idx_spectrastrike_ingest_requests_tenant_created
ON spectrastrike_ingest_requests (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_spectrastrike_events_tenant_occurred
ON spectrastrike_events (tenant_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_spectrastrike_findings_tenant_seen
ON spectrastrike_findings (tenant_id, first_seen DESC);
