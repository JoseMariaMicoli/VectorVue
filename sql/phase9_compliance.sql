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

-- Phase 9: Continuous Compliance & Regulatory Assurance

CREATE TABLE IF NOT EXISTS frameworks (
    id BIGSERIAL PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT 'current',
    description TEXT NOT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS controls (
    id BIGSERIAL PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT 'general',
    severity TEXT NOT NULL DEFAULT 'medium',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS control_mappings (
    id BIGSERIAL PRIMARY KEY,
    framework_id BIGINT NOT NULL REFERENCES frameworks(id) ON DELETE CASCADE,
    control_id BIGINT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    requirement_ref TEXT NOT NULL,
    source_event_type TEXT NOT NULL DEFAULT '',
    inherited_from_control_id BIGINT NULL REFERENCES controls(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (framework_id, control_id, requirement_ref)
);

CREATE INDEX IF NOT EXISTS idx_control_mappings_framework
ON control_mappings (framework_id, control_id);

CREATE INDEX IF NOT EXISTS idx_control_mappings_source_event
ON control_mappings (source_event_type);

CREATE TABLE IF NOT EXISTS control_applicability_rules (
    id BIGSERIAL PRIMARY KEY,
    framework_id BIGINT NOT NULL REFERENCES frameworks(id) ON DELETE CASCADE,
    control_id BIGINT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    tenant_id UUID NULL REFERENCES tenants(id) ON DELETE CASCADE,
    environment TEXT NULL,
    asset_type TEXT NULL,
    business_process TEXT NULL,
    in_scope_required BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_control_applicability_framework_control
ON control_applicability_rules (framework_id, control_id);

CREATE INDEX IF NOT EXISTS idx_control_applicability_tenant
ON control_applicability_rules (tenant_id, environment, asset_type);

CREATE TABLE IF NOT EXISTS assets (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('system', 'service', 'identity', 'network')),
    criticality TEXT NOT NULL DEFAULT 'medium',
    environment TEXT NOT NULL CHECK (environment IN ('prod', 'staging', 'dev')),
    business_process TEXT NOT NULL DEFAULT '',
    in_scope BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name, environment)
);

ALTER TABLE assets ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS type TEXT;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS criticality TEXT;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS environment TEXT;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS business_process TEXT;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS in_scope BOOLEAN;
ALTER TABLE assets ALTER COLUMN criticality SET DEFAULT 'medium';
ALTER TABLE assets ALTER COLUMN environment SET DEFAULT 'prod';
ALTER TABLE assets ALTER COLUMN business_process SET DEFAULT '';
ALTER TABLE assets ALTER COLUMN in_scope SET DEFAULT TRUE;

UPDATE assets a
SET tenant_id = c.tenant_id
FROM campaigns c
WHERE a.tenant_id IS NULL
  AND a.campaign_id = c.id
  AND c.tenant_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_assets_tenant_scope
ON assets (tenant_id, in_scope, environment, type);

CREATE TABLE IF NOT EXISTS system_boundaries (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_system_boundaries_tenant
ON system_boundaries (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS control_owners (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    control_id BIGINT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    responsibility TEXT NOT NULL,
    acknowledged_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, control_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_control_owners_tenant_control
ON control_owners (tenant_id, control_id);

CREATE TABLE IF NOT EXISTS control_attestations (
    id BIGSERIAL PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES control_owners(id) ON DELETE CASCADE,
    attested_at TIMESTAMPTZ NOT NULL,
    comment TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_control_attestations_owner_time
ON control_attestations (owner_id, attested_at DESC);

CREATE TABLE IF NOT EXISTS control_policies (
    id BIGSERIAL PRIMARY KEY,
    control_id BIGINT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    expected_frequency INTEGER NOT NULL DEFAULT 1 CHECK (expected_frequency >= 1),
    failure_threshold DOUBLE PRECISION NOT NULL DEFAULT 0.15 CHECK (failure_threshold >= 0 AND failure_threshold <= 1),
    observation_window_days INTEGER NOT NULL DEFAULT 30 CHECK (observation_window_days >= 1),
    required_coverage_percent DOUBLE PRECISION NOT NULL DEFAULT 80 CHECK (required_coverage_percent >= 0 AND required_coverage_percent <= 100),
    sampling_method TEXT NOT NULL DEFAULT 'full',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (control_id)
);

CREATE TABLE IF NOT EXISTS control_observations (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    control_id BIGINT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    derived_from_event TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('success', 'failure')),
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    observed_at TIMESTAMPTZ NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, control_id, derived_from_event)
);

CREATE INDEX IF NOT EXISTS idx_control_observations_tenant_time
ON control_observations (tenant_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_control_observations_control_time
ON control_observations (control_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS control_state_history (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    control_id BIGINT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('operating', 'degraded', 'failed', 'insufficient_evidence')),
    evaluated_at TIMESTAMPTZ NOT NULL,
    details_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_control_state_history_tenant_control_time
ON control_state_history (tenant_id, control_id, evaluated_at DESC);

CREATE TABLE IF NOT EXISTS compliance_events (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    framework TEXT NOT NULL,
    control_id BIGINT NOT NULL REFERENCES controls(id) ON DELETE RESTRICT,
    status TEXT NOT NULL,
    evidence_hash TEXT NOT NULL,
    dataset_hash TEXT NOT NULL,
    timestamp_signature TEXT NOT NULL,
    previous_event_hash TEXT NULL,
    chain_hash TEXT NOT NULL,
    payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    retention_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_compliance_events_tenant_framework_time
ON compliance_events (tenant_id, framework, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_compliance_events_chain
ON compliance_events (tenant_id, framework, chain_hash);

CREATE OR REPLACE FUNCTION prevent_update_delete_compliance_events()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'compliance_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS trg_compliance_events_no_update ON compliance_events;
CREATE TRIGGER trg_compliance_events_no_update
BEFORE UPDATE ON compliance_events
FOR EACH ROW
EXECUTE FUNCTION prevent_update_delete_compliance_events();

DROP TRIGGER IF EXISTS trg_compliance_events_no_delete ON compliance_events;
CREATE TRIGGER trg_compliance_events_no_delete
BEFORE DELETE ON compliance_events
FOR EACH ROW
EXECUTE FUNCTION prevent_update_delete_compliance_events();

CREATE TABLE IF NOT EXISTS compliance_scores (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    framework TEXT NOT NULL,
    score DOUBLE PRECISION NOT NULL CHECK (score >= 0 AND score <= 100),
    coverage_percent DOUBLE PRECISION NOT NULL CHECK (coverage_percent >= 0 AND coverage_percent <= 100),
    calculated_at TIMESTAMPTZ NOT NULL,
    details_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_compliance_scores_tenant_framework_time
ON compliance_scores (tenant_id, framework, calculated_at DESC);

CREATE TABLE IF NOT EXISTS compliance_snapshots (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    framework TEXT NOT NULL,
    score DOUBLE PRECISION NOT NULL CHECK (score >= 0 AND score <= 100),
    snapshot_at TIMESTAMPTZ NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_compliance_snapshots_tenant_framework_time
ON compliance_snapshots (tenant_id, framework, snapshot_at DESC);

CREATE TABLE IF NOT EXISTS audit_sessions (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, token_hash)
);

CREATE INDEX IF NOT EXISTS idx_audit_sessions_tenant_expires
ON audit_sessions (tenant_id, expires_at DESC);
