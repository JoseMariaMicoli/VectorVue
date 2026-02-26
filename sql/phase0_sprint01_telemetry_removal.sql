-- Phase 0 Sprint 0.1
-- Telemetry capability removal from client API
-- Apply on dev/integration environments after backup validation.

BEGIN;

DROP TABLE IF EXISTS spectrastrike_events CASCADE;
DROP TABLE IF EXISTS spectrastrike_findings CASCADE;
DROP TABLE IF EXISTS spectrastrike_ingest_requests CASCADE;
DROP TABLE IF EXISTS spectrastrike_idempotency CASCADE;
DROP TABLE IF EXISTS client_activity_events CASCADE;

COMMIT;
