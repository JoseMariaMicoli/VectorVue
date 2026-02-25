-- Copyright (c) 2026 Jose Maria Micoli
-- Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

-- Phase 6.5 tenant isolation migration for PostgreSQL schema.
-- Safe for existing deployments: creates/extends objects if missing.

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS user_tenant_access (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    username TEXT NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    access_role TEXT NOT NULL DEFAULT 'viewer',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, tenant_id),
    UNIQUE (username, tenant_id)
);

INSERT INTO tenants (id, name, created_at, active)
VALUES ('00000000-0000-0000-0000-000000000001', 'legacy-default', NOW(), TRUE)
ON CONFLICT (id) DO NOTHING;

-- Ensure Phase 6.5 requested tables exist even if prior phases did not include them.
CREATE TABLE IF NOT EXISTS evidence (
    id BIGSERIAL PRIMARY KEY,
    campaign_id BIGINT,
    finding_id BIGINT,
    label TEXT NOT NULL DEFAULT 'evidence',
    created_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS reports (
    id BIGSERIAL PRIMARY KEY,
    campaign_id BIGINT,
    title TEXT NOT NULL DEFAULT 'report',
    created_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS remediation_tasks (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT,
    title TEXT NOT NULL DEFAULT 'task',
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT DEFAULT ''
);

ALTER TABLE findings ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE evidence_items ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE campaign_reports ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE client_reports ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE findings SET tenant_id='00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE campaigns SET tenant_id='00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE evidence_items SET tenant_id='00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE campaign_reports SET tenant_id='00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE client_reports SET tenant_id='00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE evidence SET tenant_id='00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE reports SET tenant_id='00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE remediation_tasks SET tenant_id='00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;

ALTER TABLE findings ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE campaigns ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE evidence_items ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE campaign_reports ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE client_reports ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE evidence ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE reports ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE remediation_tasks ALTER COLUMN tenant_id SET NOT NULL;

DO $$ BEGIN
    ALTER TABLE findings ADD CONSTRAINT findings_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE campaigns ADD CONSTRAINT campaigns_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE evidence_items ADD CONSTRAINT evidence_items_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE campaign_reports ADD CONSTRAINT campaign_reports_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE client_reports ADD CONSTRAINT client_reports_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE evidence ADD CONSTRAINT evidence_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE reports ADD CONSTRAINT reports_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE remediation_tasks ADD CONSTRAINT remediation_tasks_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_findings_tenant_id ON findings (tenant_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_tenant_id ON campaigns (tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_items_tenant_id ON evidence_items (tenant_id);
CREATE INDEX IF NOT EXISTS idx_campaign_reports_tenant_id ON campaign_reports (tenant_id);
CREATE INDEX IF NOT EXISTS idx_client_reports_tenant_id ON client_reports (tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_tenant_id ON evidence (tenant_id);
CREATE INDEX IF NOT EXISTS idx_reports_tenant_id ON reports (tenant_id);
CREATE INDEX IF NOT EXISTS idx_remediation_tasks_tenant_id ON remediation_tasks (tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_tenant_access_tenant_id ON user_tenant_access (tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_tenant_access_username ON user_tenant_access (username);
