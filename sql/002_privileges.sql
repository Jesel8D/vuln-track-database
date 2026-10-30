\set ON_ERROR_STOP on
BEGIN;
-- Grupo técnico NOLOGIN. El futuro login backend se provisiona fuera de Git.
CREATE ROLE vulntrack_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
REVOKE ALL ON DATABASE :"DBNAME" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"DBNAME" TO vulntrack_app;
GRANT USAGE ON SCHEMA vulntrack TO vulntrack_app;
GRANT EXECUTE ON FUNCTION vulntrack.valid_text(text, integer) TO vulntrack_app;
GRANT SELECT (id, username, active, created_at, updated_at) ON vulntrack.users TO vulntrack_app;
GRANT SELECT, INSERT ON vulntrack.assets, vulntrack.analysis_runs,
    vulntrack.findings, vulntrack.asset_registration_requests TO vulntrack_app;
GRANT UPDATE (status, coverage, source_timestamp, started_at, completed_at)
    ON vulntrack.analysis_runs TO vulntrack_app;
GRANT UPDATE (status) ON vulntrack.findings TO vulntrack_app;
-- Sin UPDATE/DELETE de activos, sin administración de usuarios ni acceso al hash.
ALTER DEFAULT PRIVILEGES IN SCHEMA vulntrack REVOKE ALL ON TABLES FROM PUBLIC;
REVOKE ALL ON FUNCTION vulntrack.touch_updated_at() FROM PUBLIC;
REVOKE ALL ON FUNCTION vulntrack.valid_text(text, integer) FROM PUBLIC;
COMMIT;
