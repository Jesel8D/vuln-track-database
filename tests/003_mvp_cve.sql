\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN
 IF (SELECT count(*) FROM pg_attribute WHERE attrelid='vulntrack.analysis_runs'::regclass
      AND attname IN ('identification_id','page_count','next_index','page_manifest','retry_count')
      AND NOT attisdropped) <> 5 THEN RAISE EXCEPTION 'Missing analysis metadata'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_indexes WHERE schemaname='vulntrack'
       AND indexname='analysis_active_unique' AND indexdef LIKE '%UNIQUE%WHERE%queued%running%') THEN
  RAISE EXCEPTION 'Missing active-run unique index'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='vulntrack.findings'::regclass
       AND conname='findings_cve_unique' AND contype='u') THEN RAISE EXCEPTION 'Missing per-run CVE uniqueness'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='vulntrack.analysis_runs'::regclass
       AND conname='analysis_identification_fk' AND contype='f') THEN RAISE EXCEPTION 'Missing identity FK'; END IF;
 IF has_table_privilege('vulntrack_app','vulntrack.analysis_runs','DELETE')
    OR has_table_privilege('vulntrack_app','vulntrack.findings','DELETE')
    OR has_column_privilege('vulntrack_app','vulntrack.analysis_runs','selected_cpe','UPDATE')
    OR has_column_privilege('vulntrack_app','vulntrack.findings','evidence','UPDATE') THEN
  RAISE EXCEPTION 'Runtime history mutation privilege'; END IF;
 IF NOT has_column_privilege('vulntrack_app','vulntrack.analysis_runs','page_count','UPDATE')
    OR NOT has_column_privilege('vulntrack_app','vulntrack.findings','reviewed_by','UPDATE') THEN
  RAISE EXCEPTION 'Missing runtime write privilege'; END IF;
 IF (SELECT count(*) FROM pg_trigger WHERE tgrelid IN ('vulntrack.analysis_runs'::regclass,
      'vulntrack.findings'::regclass) AND tgname IN ('analysis_guard','finding_guard')
      AND tgenabled='O')<>2 THEN RAISE EXCEPTION 'Missing immutable history guards'; END IF;
 IF EXISTS(SELECT 1 FROM vulntrack.analysis_runs WHERE identification_id IS NULL AND
       (idempotency_key IS NOT NULL OR observed_version IS NOT NULL)) THEN
  RAISE EXCEPTION 'Legacy snapshots changed'; END IF;
END $$;
ROLLBACK;
SELECT 'MVP-B SQL: run metadata, FK, unique indexes, guards and least privileges passed';
