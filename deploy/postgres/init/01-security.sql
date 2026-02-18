-- VectorVue PostgreSQL role hardening bootstrap.
-- Executed automatically by postgres image on first initialization.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vectorvue_readonly') THEN
        CREATE ROLE vectorvue_readonly NOINHERIT;
    END IF;
END
$$;

ALTER ROLE vectorvue SET statement_timeout = '60s';
ALTER ROLE vectorvue SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE vectorvue SET lock_timeout = '10s';

GRANT CONNECT ON DATABASE vectorvue_db TO vectorvue_readonly;
\connect vectorvue_db
GRANT USAGE ON SCHEMA public TO vectorvue_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO vectorvue_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO vectorvue_readonly;
