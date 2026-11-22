\set ON_ERROR_STOP on
DO $$
BEGIN
    IF NOT (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
            WHERE oid='vulntrack_devices.revisions'::regclass) THEN
        RAISE EXCEPTION 'revision RLS missing';
    END IF;
    RAISE NOTICE 'ok - revision table forces RLS';
    IF NOT has_table_privilege('vulntrack_app','vulntrack_devices.revisions','SELECT')
        OR has_table_privilege('vulntrack_app','vulntrack_devices.revisions','INSERT,UPDATE,DELETE,TRUNCATE')
    THEN
        RAISE EXCEPTION 'revision privilege drift';
    END IF;
    RAISE NOTICE 'ok - app role can only read revisions';
    IF has_column_privilege('vulntrack_app','vulntrack_devices.devices','record_version','UPDATE')
        OR has_column_privilege('vulntrack_app','vulntrack_devices.devices','identity_generation','UPDATE')
        OR has_column_privilege('vulntrack_app','vulntrack_devices.runs','evaluated_technology','UPDATE')
    THEN
        RAISE EXCEPTION 'metadata write privilege drift';
    END IF;
    RAISE NOTICE 'ok - trigger owns version and snapshot metadata';
    IF (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O'
        AND tgname IN ('device_revision_before_update','device_identification_generation_before_insert',
                       'device_run_technology_before_insert')
        AND tgrelid IN ('vulntrack_devices.devices'::regclass,
                        'vulntrack_devices.identifications'::regclass,
                        'vulntrack_devices.runs'::regclass)) <> 3 THEN
        RAISE EXCEPTION 'missing evidence write guards';
    END IF;
    RAISE NOTICE 'ok - edit, identity and analysis guards are enabled';
END $$;
