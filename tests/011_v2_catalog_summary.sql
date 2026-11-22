\set ON_ERROR_STOP on
BEGIN;
DO $$
BEGIN
    IF (SELECT count(*) FROM vulntrack_catalog.summary) <> 2 THEN
        RAISE EXCEPTION 'missing catalog summary source modes';
    END IF;
    RAISE NOTICE 'ok - summary has one row per source mode';
    IF NOT has_table_privilege('vulntrack_app','vulntrack_catalog.summary','SELECT')
       OR has_table_privilege('vulntrack_app','vulntrack_catalog.summary','INSERT,UPDATE,DELETE') THEN
        RAISE EXCEPTION 'catalog summary permissions';
    END IF;
    RAISE NOTICE 'ok - API observes catalog summary using read-only privileges';
END $$;
ROLLBACK;
