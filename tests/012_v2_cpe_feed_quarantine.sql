\set ON_ERROR_STOP on
BEGIN;
DO $$
DECLARE
    dg text := repeat('a',64);
    id uuid := '38b903e9-19bb-4c83-bdf4-d90a0e71838d';
BEGIN
    INSERT INTO vulntrack_catalog.feed_imports
        (digest,source_modified,gz_bytes,json_bytes,total_items,next_item,stored,discarded,status)
    VALUES (dg,now(),1,1,1,1,0,1,'complete');
    INSERT INTO vulntrack_catalog.feed_quarantine(digest,cpe_name_id,ordinal,reason,original)
    VALUES (dg,id,1,'INVALID_CPE_LANGUAGE',jsonb_build_object('cpe',jsonb_build_object('cpeNameId',id)));
    RAISE NOTICE 'ok - quarantine retains raw official ID';
    BEGIN
        INSERT INTO vulntrack_catalog.feed_quarantine(digest,cpe_name_id,ordinal,reason,original)
        VALUES (repeat('b',64),id,1,'INVALID_CPE_LANGUAGE',jsonb_build_object('cpe',jsonb_build_object('cpeNameId',id)));
        RAISE EXCEPTION 'foreign feed accepted';
    EXCEPTION WHEN foreign_key_violation THEN
        RAISE NOTICE 'ok - quarantine requires a feed receipt';
    END;
    BEGIN
        INSERT INTO vulntrack_catalog.feed_quarantine(digest,cpe_name_id,ordinal,reason,original)
        VALUES (dg,id,2,'INVALID_CPE_LANGUAGE','{}');
        RAISE EXCEPTION 'missing original UUID accepted';
    EXCEPTION WHEN check_violation THEN
        RAISE NOTICE 'ok - quarantine validates raw official ID';
    END;
    IF has_table_privilege('vulntrack_app','vulntrack_catalog.feed_quarantine','SELECT,INSERT') THEN
        RAISE EXCEPTION 'application has access to rejected records';
    END IF;
    RAISE NOTICE 'ok - quarantine not available through application role';
END
$$;
ROLLBACK;
