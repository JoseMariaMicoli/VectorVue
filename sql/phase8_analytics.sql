-- Copyright (c) 2026 Jose Maria Micoli
-- Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

-- Phase 8: Advanced ML / Analytics schema (tenant-isolated, reproducible, explainable).

CREATE SCHEMA IF NOT EXISTS analytics;

CREATE TABLE IF NOT EXISTS analytics.events (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analytics_events_tenant_ts
ON analytics.events (tenant_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_analytics_events_event_type
ON analytics.events (event_type);

-- Append-only enforcement for analytics.events.
CREATE OR REPLACE FUNCTION analytics.prevent_update_delete_events()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'analytics.events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS trg_analytics_events_no_update ON analytics.events;
CREATE TRIGGER trg_analytics_events_no_update
BEFORE UPDATE ON analytics.events
FOR EACH ROW
EXECUTE FUNCTION analytics.prevent_update_delete_events();

DROP TRIGGER IF EXISTS trg_analytics_events_no_delete ON analytics.events;
CREATE TRIGGER trg_analytics_events_no_delete
BEFORE DELETE ON analytics.events
FOR EACH ROW
EXECUTE FUNCTION analytics.prevent_update_delete_events();

CREATE TABLE IF NOT EXISTS analytics.feature_sets (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dataset_hash TEXT NOT NULL,
    "window" TEXT NOT NULL CHECK ("window" IN ('1h', '24h', '7d', '30d')),
    UNIQUE (tenant_id, name, version)
);

CREATE INDEX IF NOT EXISTS idx_analytics_feature_sets_tenant_created
ON analytics.feature_sets (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS analytics.features (
    feature_set_id BIGINT NOT NULL REFERENCES analytics.feature_sets(id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    feature_name TEXT NOT NULL,
    value DOUBLE PRECISION NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (feature_set_id, entity_id, feature_name, ts)
);

CREATE INDEX IF NOT EXISTS idx_analytics_features_entity
ON analytics.features (entity_id, ts DESC);

CREATE TABLE IF NOT EXISTS analytics.models (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    task TEXT NOT NULL,
    version TEXT NOT NULL,
    dataset_hash TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    hyperparameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    stage TEXT NOT NULL CHECK (stage IN ('experimental', 'staging', 'production')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, task, version)
);

CREATE INDEX IF NOT EXISTS idx_analytics_models_tenant_task_stage
ON analytics.models (tenant_id, task, stage, created_at DESC);

CREATE TABLE IF NOT EXISTS analytics.predictions (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    model_id BIGINT NOT NULL REFERENCES analytics.models(id) ON DELETE RESTRICT,
    entity_id TEXT NOT NULL,
    prediction JSONB NOT NULL,
    explanation JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analytics_predictions_tenant_entity
ON analytics.predictions (tenant_id, entity_id, created_at DESC);

CREATE TABLE IF NOT EXISTS analytics.model_health (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    model_id BIGINT NOT NULL REFERENCES analytics.models(id) ON DELETE CASCADE,
    feature_drift_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    prediction_drift_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    alert_triggered BOOLEAN NOT NULL DEFAULT FALSE,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_analytics_model_health_tenant_recorded
ON analytics.model_health (tenant_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS analytics.tenant_security_summary (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    security_posture JSONB NOT NULL DEFAULT '{}'::jsonb,
    trend JSONB NOT NULL DEFAULT '{}'::jsonb,
    maturity_level TEXT NOT NULL DEFAULT 'baseline',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    generated_by_model_version TEXT NOT NULL DEFAULT 'n/a'
);
