-- Run ONLY in a disposable cluster after bootstrap_mvp_a or Alembic 0003.
\set ON_ERROR_STOP on
BEGIN;
CREATE FUNCTION pg_temp.expect_error(statement text, expected text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE actual text;
BEGIN
    BEGIN
        EXECUTE statement;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS actual = RETURNED_SQLSTATE;
        IF actual = expected THEN RETURN; END IF;
        RAISE EXCEPTION 'Expected SQLSTATE %, got %', expected, actual;
    END;
    RAISE EXCEPTION 'Expected rejection did not happen';
END $$;
INSERT INTO vulntrack.users(id,username) VALUES
('91000000-0000-4000-8000-000000000001','mvp_sql_owner'),
('91000000-0000-4000-8000-000000000002','mvp_sql_other');
SET LOCAL ROLE vulntrack_app;
INSERT INTO vulntrack.assets(id,created_by,device_type,manufacturer,model,version,site_label) VALUES
('92000000-0000-4000-8000-000000000001','91000000-0000-4000-8000-000000000001','router','Cisco','RV340',NULL,'LAB'),
('92000000-0000-4000-8000-000000000002','91000000-0000-4000-8000-000000000001','router','Cisco','RV340','1.0.0.33','LAB');
-- Basic version validity remains enforced.
SELECT pg_temp.expect_error($q$INSERT INTO vulntrack.assets(id,device_type,manufacturer,model,version,site_label)
VALUES ('92000000-0000-4000-8000-000000000003','router','Cisco','RV340','','LAB')$q$,'23514');
INSERT INTO vulntrack.asset_cpe_identifications
(id,asset_id,state,cpe_name,cpe_name_id,component_kind,observed_version,source,validated_at,
recorded_by,recorded_at,reason,idempotency_key,request_hash) VALUES
('93000000-0000-4000-8000-000000000001','92000000-0000-4000-8000-000000000001','confirmed',
'cpe:2.3:o:cisco:small_business_rv340_firmware:1.0.0.33:*:*:*:*:*:*:*',
'c817e5ba-62c1-41e7-a15c-fb851fea761e','firmware',NULL,'NVD',statement_timestamp(),
'91000000-0000-4000-8000-000000000001',statement_timestamp(),'Verified fixture',
'94000000-0000-4000-8000-000000000001',repeat('a',64));
SET CONSTRAINTS ALL IMMEDIATE;
SET CONSTRAINTS ALL DEFERRED;
SELECT pg_temp.expect_error($q$UPDATE vulntrack.asset_cpe_identifications SET reason='tampered'$q$,'42501');
SELECT pg_temp.expect_error($q$DELETE FROM vulntrack.asset_cpe_identifications$q$,'42501');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.assets SET id='92000000-0000-4000-8000-000000000004'
WHERE id='92000000-0000-4000-8000-000000000001'$q$,'23514');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.assets SET created_by='91000000-0000-4000-8000-000000000002'$q$,'42501');
-- Owner mismatch must fail even when all referenced rows exist.
SELECT pg_temp.expect_error($q$INSERT INTO vulntrack.asset_cpe_identifications
SELECT '93000000-0000-4000-8000-000000000002',asset_id,state,cpe_name,cpe_name_id,component_kind,
observed_version,source,validated_at,'91000000-0000-4000-8000-000000000002',recorded_at,
reason,replaces_id,valid_to,'94000000-0000-4000-8000-000000000002',request_hash
FROM vulntrack.asset_cpe_identifications WHERE id='93000000-0000-4000-8000-000000000001'$q$,'23514');
-- Closing without a replacement must fail at transaction constraint validation.
DO $$ BEGIN
    BEGIN
        UPDATE vulntrack.asset_cpe_identifications SET valid_to=clock_timestamp()
        WHERE id='93000000-0000-4000-8000-000000000001';
        SET CONSTRAINTS ALL IMMEDIATE;
        RAISE EXCEPTION 'Orphan closure accepted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
END $$;
RESET ROLE;
-- Administrators also cannot mutate immutable snapshots or remove history.
SELECT pg_temp.expect_error($q$UPDATE vulntrack.asset_cpe_identifications SET reason='tampered'
WHERE id='93000000-0000-4000-8000-000000000001'$q$,'23514');
SELECT pg_temp.expect_error($q$DELETE FROM vulntrack.asset_cpe_identifications
WHERE id='93000000-0000-4000-8000-000000000001'$q$,'23514');
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='vulntrack' AND indexname='cpe_current_unique'
        AND indexdef LIKE '%UNIQUE%WHERE (valid_to IS NULL)%') THEN
        RAISE EXCEPTION 'Current uniqueness index missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='cpe_replaces_same_asset'
        AND conrelid='vulntrack.asset_cpe_identifications'::regclass AND contype='f') THEN
        RAISE EXCEPTION 'Composite history FK missing';
    END IF;
END $$;
ROLLBACK;
SELECT 'MVP-A SQL: nullable version, ownership, permissions, immutable snapshots, chain and indexes passed';
