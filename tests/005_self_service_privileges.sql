-- No passwords, hashes or persistent accounts are created by this rollback-only check.
\set ON_ERROR_STOP on
BEGIN;
DO $$
DECLARE privilege text; column_name text;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='vulntrack_registration'
        AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls OR rolreplication))
        OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='vulntrack_registration') THEN
        RAISE EXCEPTION 'unsafe registration role';
    END IF;
    RAISE NOTICE 'ok - registration role is NOLOGIN and unprivileged';
    FOREACH column_name IN ARRAY ARRAY['id','username','password_hash','active'] LOOP
        IF NOT has_column_privilege('vulntrack_registration','vulntrack.users',column_name,'INSERT') THEN
            RAISE EXCEPTION 'missing registration column grant';
        END IF;
        RAISE NOTICE 'ok - explicit insert column grant';
    END LOOP;
    FOREACH privilege IN ARRAY ARRAY['UPDATE','DELETE','TRUNCATE','TRIGGER'] LOOP
        IF has_table_privilege('vulntrack_registration','vulntrack.users',privilege) THEN
            RAISE EXCEPTION 'unexpected registration privilege';
        END IF;
        RAISE NOTICE 'ok - no existing-account mutation privilege';
    END LOOP;
    IF has_column_privilege('vulntrack_registration','vulntrack.users','created_at','INSERT')
        OR has_column_privilege('vulntrack_registration','vulntrack.users','password_hash','SELECT')
        OR pg_has_role('vulntrack_app','vulntrack_registration','MEMBER') THEN
        RAISE EXCEPTION 'registration privileges must be opt-in and bounded';
    END IF;
    RAISE NOTICE 'ok - registration role does not leak hashes or auto-enroll existing APIs';
END $$;
ROLLBACK;
