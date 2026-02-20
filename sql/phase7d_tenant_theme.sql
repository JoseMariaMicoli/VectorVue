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

-- Phase 7D dynamic tenant branding schema (white-label portal).

CREATE TABLE IF NOT EXISTS tenant_theme (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    company_name TEXT NOT NULL DEFAULT 'VectorVue Customer',
    logo_path TEXT NOT NULL DEFAULT '',
    primary_color TEXT NOT NULL DEFAULT '#0f172a',
    accent_color TEXT NOT NULL DEFAULT '#22d3ee',
    background_color TEXT NOT NULL DEFAULT '#0b0e14',
    foreground_color TEXT NOT NULL DEFAULT '#e5e7eb',
    danger_color TEXT NOT NULL DEFAULT '#ef4444',
    success_color TEXT NOT NULL DEFAULT '#22c55e',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO tenant_theme (
    tenant_id, company_name, logo_path,
    primary_color, accent_color, background_color, foreground_color, danger_color, success_color, updated_at
)
SELECT
    t.id,
    CASE WHEN t.name = 'legacy-default' THEN 'Default Customer' ELSE t.name END,
    '',
    '#0f172a', '#22d3ee', '#0b0e14', '#e5e7eb', '#ef4444', '#22c55e', NOW()
FROM tenants t
ON CONFLICT (tenant_id) DO NOTHING;
