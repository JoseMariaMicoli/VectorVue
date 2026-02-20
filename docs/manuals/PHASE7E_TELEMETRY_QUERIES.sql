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

-- Phase 7E telemetry analytics reference
-- Metrics target: MTTA, MTTR, Risk Awareness, Defensive Responsiveness

-- MTTA (Mean Time To Acknowledge) by tenant for critical findings
WITH first_view AS (
  SELECT
    tenant_id,
    object_id AS finding_id,
    MIN(timestamp) AS first_view_ts
  FROM client_activity_events
  WHERE event_type = 'FINDING_VIEWED'
    AND object_type = 'finding'
    AND severity = 'critical'
  GROUP BY tenant_id, object_id
),
first_ack AS (
  SELECT
    tenant_id,
    object_id AS finding_id,
    MIN(timestamp) AS first_ack_ts
  FROM client_activity_events
  WHERE event_type = 'FINDING_ACKNOWLEDGED'
    AND object_type = 'finding'
  GROUP BY tenant_id, object_id
)
SELECT
  v.tenant_id,
  ROUND(AVG(EXTRACT(EPOCH FROM (a.first_ack_ts - v.first_view_ts)) / 60.0)::numeric, 2) AS mtta_minutes,
  COUNT(*) AS acknowledged_findings
FROM first_view v
JOIN first_ack a
  ON a.tenant_id = v.tenant_id
 AND a.finding_id = v.finding_id
 AND a.first_ack_ts >= v.first_view_ts
GROUP BY v.tenant_id
ORDER BY v.tenant_id;

-- MTTR (Mean Time To Remediate) by tenant
WITH first_open AS (
  SELECT
    tenant_id,
    object_id AS remediation_id,
    MIN(timestamp) AS opened_ts
  FROM client_activity_events
  WHERE event_type = 'REMEDIATION_OPENED'
    AND object_type = 'remediation'
  GROUP BY tenant_id, object_id
),
first_complete AS (
  SELECT
    tenant_id,
    object_id AS remediation_id,
    MIN(timestamp) AS completed_ts
  FROM client_activity_events
  WHERE event_type = 'REMEDIATION_COMPLETED'
    AND object_type = 'remediation'
  GROUP BY tenant_id, object_id
)
SELECT
  o.tenant_id,
  ROUND(AVG(EXTRACT(EPOCH FROM (c.completed_ts - o.opened_ts)) / 3600.0)::numeric, 2) AS mttr_hours,
  COUNT(*) AS remediations_closed
FROM first_open o
JOIN first_complete c
  ON c.tenant_id = o.tenant_id
 AND c.remediation_id = o.remediation_id
 AND c.completed_ts >= o.opened_ts
GROUP BY o.tenant_id
ORDER BY o.tenant_id;

