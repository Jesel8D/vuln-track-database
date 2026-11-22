\set ON_ERROR_STOP on
BEGIN;
DO $$
BEGIN
    IF NOT has_table_privilege('vulntrack_app','vulntrack_catalog.products','SELECT')
       OR has_table_privilege('vulntrack_app','vulntrack_catalog.products','INSERT,UPDATE,DELETE')
       OR has_table_privilege('vulntrack_app','vulntrack_catalog.sync_runs','UPDATE') THEN
        RAISE EXCEPTION 'catalog access grants';
    END IF;
    RAISE NOTICE 'ok - read only database grants for the public catalog';
    IF NOT (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
            WHERE oid='vulntrack_catalog_private.device_registrations'::regclass) THEN
        RAISE EXCEPTION 'registration RLS';
    END IF;
    RAISE NOTICE 'ok - registration receipts use FORCE RLS';
    IF to_regclass('vulntrack_catalog.catalog_search_idx') IS NULL
       OR to_regclass('vulntrack_catalog.catalog_product_version_idx') IS NULL THEN
        RAISE EXCEPTION 'missing catalog search indexes';
    END IF;
    RAISE NOTICE 'ok - catalog search and family/version indexes present';
    IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='vulntrack_devices'
              AND table_name='devices' AND column_name IN ('product_vendor','product')
              AND is_nullable<>'YES') THEN
        RAISE EXCEPTION 'unknown product must use null';
    END IF;
    RAISE NOTICE 'ok - pending device accepts unknown component product';
END $$;
ROLLBACK;
