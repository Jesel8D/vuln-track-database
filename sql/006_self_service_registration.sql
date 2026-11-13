-- Opt-in enrollment privilege. No table/column/data/RLS changes (D-002).
-- Apply once as maintenance operator after 004 and 005; never from HTTP startup.
-- Do NOT grant this role to every login or to vulntrack_app automatically.
\set ON_ERROR_STOP on
BEGIN;
DO $$
BEGIN
    IF to_regprocedure('vulntrack.establish_new_workspace_context(uuid,uuid,bigint,uuid,text)')
        IS NULL THEN
        RAISE EXCEPTION 'Database V2 005 required before registration privileges';
    END IF;
END $$;
CREATE ROLE vulntrack_registration NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS;
GRANT INSERT (id, username, password_hash, active)
    ON vulntrack.users TO vulntrack_registration;
-- An operator grants membership only to the dedicated registration-capable API login:
-- GRANT vulntrack_registration TO your_api_login;
-- Login also needs the existing vulntrack_app and SELECT(password_hash) privileges.
-- No UPDATE/DELETE on users, no DDL, no global application administrator exists.
COMMIT;
