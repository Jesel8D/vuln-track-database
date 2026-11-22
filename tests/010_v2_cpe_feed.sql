\set ON_ERROR_STOP on
BEGIN;
DO $$
BEGIN
    IF to_regclass('vulntrack_catalog.catalog_cpe_exact_idx') IS NULL
       OR to_regclass('vulntrack_catalog.catalog_vendor_prefix_idx') IS NULL
       OR to_regclass('vulntrack_catalog.catalog_family_browse_idx') IS NULL THEN
        RAISE EXCEPTION 'missing scaled catalog search indexes';
    END IF;
    RAISE NOTICE 'ok - scaled exact CPE, vendor and family index definitions';
    IF NOT has_table_privilege('vulntrack_app','vulntrack_catalog.feed_imports','SELECT')
       OR has_table_privilege('vulntrack_app','vulntrack_catalog.feed_imports','INSERT,UPDATE,DELETE') THEN
        RAISE EXCEPTION 'feed operator privileges';
    END IF;
    RAISE NOTICE 'ok - API can observe but cannot modify feed checkpoints';
    BEGIN
        INSERT INTO vulntrack_catalog.feed_imports(digest,source_modified,gz_bytes,json_bytes,
                                                    total_items,next_item,stored,status)
        VALUES (repeat('a',64),now(),1,2,2,1,1,'complete');
        RAISE EXCEPTION 'premature completion accepted';
    EXCEPTION WHEN check_violation THEN
        RAISE NOTICE 'ok - feed cannot be marked complete while items remain';
    END;
END $$;
ROLLBACK;
