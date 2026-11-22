\set ON_ERROR_STOP on
BEGIN;
CREATE FUNCTION pg_temp.assert_device(ok boolean, label text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF ok IS DISTINCT FROM true THEN RAISE EXCEPTION 'device check failed: %',label; END IF;
    RAISE NOTICE 'ok - %', label;
END $$;
SELECT pg_temp.assert_device((SELECT count(*)=5 FROM pg_tables
    WHERE schemaname='vulntrack_devices' AND tablename <> 'revisions'),'five device tables');
SELECT pg_temp.assert_device((SELECT bool_and(relrowsecurity AND relforcerowsecurity)
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='vulntrack_devices' AND c.relkind='r'),'forced RLS for all device tables');
SELECT pg_temp.assert_device((SELECT count(*)=13 FROM pg_policies
    WHERE schemaname='vulntrack_devices' AND tablename <> 'revisions'),'thirteen scoped policies');
SELECT pg_temp.assert_device(NOT has_schema_privilege('vulntrack_registration','vulntrack_devices','USAGE'),
    'registration cannot use the device schema');
SELECT pg_temp.assert_device(NOT has_schema_privilege('vulntrack_app','vulntrack_devices','CREATE'),
    'API cannot add device schema objects');
SELECT pg_temp.assert_device((SELECT bool_and(
    NOT has_table_privilege('vulntrack_app',format('%I.%I',schemaname,tablename),'DELETE,TRUNCATE,TRIGGER'))
    FROM pg_tables WHERE schemaname='vulntrack_devices'),'no delete or truncate grants');
SELECT pg_temp.assert_device(NOT has_table_privilege('vulntrack_app','vulntrack_devices.identifications','UPDATE'),
    'identifications are append only');
SELECT pg_temp.assert_device(NOT has_column_privilege('vulntrack_app','vulntrack_devices.runs','selected_cpe','UPDATE'),
    'run CPE snapshot is immutable');
SELECT pg_temp.assert_device(NOT has_column_privilege('vulntrack_app','vulntrack_devices.findings','evidence','UPDATE'),
    'original CVE evidence is immutable');
SELECT pg_temp.assert_device((SELECT count(*)=4 FROM pg_constraint c
    JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace
    WHERE n.nspname='vulntrack_devices' AND t.relname <> 'revisions'
      AND c.contype='f' AND array_length(c.conkey,1)>=2),
    'composite membership of device, identity, run and finding');
SELECT pg_temp.assert_device((SELECT indexdef LIKE '%WHERE (status = ''running''::text)%'
    FROM pg_indexes WHERE schemaname='vulntrack_devices' AND indexname='device_one_running_idx'),
    'one running consultation per device');
SELECT pg_temp.assert_device((SELECT count(*)=29 FROM pg_policies WHERE schemaname='vulntrack'),
    'legacy V2 policies intact');
SELECT pg_temp.assert_device((SELECT version_num='0004_mvp_cve' FROM public.alembic_version),
    'legacy Alembic head intact');
SET LOCAL ROLE vulntrack_app;
SELECT pg_temp.assert_device((SELECT count(*)=0 FROM vulntrack_devices.devices),
    'API without signed workspace context cannot read inventory');
ROLLBACK;
