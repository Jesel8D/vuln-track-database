-- Rollback-only catalog/constraint regression. No user data changes.
\set ON_ERROR_STOP on
BEGIN;
DO $$
DECLARE definition text;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO definition FROM pg_constraint
      WHERE conrelid='vulntrack.application_findings'::regclass
        AND conname='app_findings_applicability_valid' AND convalidated;
    IF definition IS DISTINCT FROM
      'CHECK ((applicability = ANY (ARRAY[''potential''::text, ''confirmed''::text, ''undetermined''::text, ''not_applicable''::text])))' THEN
        RAISE EXCEPTION 'SQL007 missing or drifted';
    END IF;
    RAISE NOTICE 'ok - undetermined accepted by validated constraint';
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='vulntrack.application_findings'::regclass
        AND tgname='nvd_finding_guard' AND tgenabled='O') THEN
        RAISE EXCEPTION 'immutable finding guard missing';
    END IF;
    RAISE NOTICE 'ok - immutable evidence guard remains enabled';
    IF (SELECT count(*) FROM pg_policies WHERE schemaname='vulntrack') <> 29 THEN
        RAISE EXCEPTION 'unexpected RLS policy count';
    END IF;
    RAISE NOTICE 'ok - 29 RLS policies retained';
    IF NOT (SELECT relrowsecurity FROM pg_class WHERE oid='vulntrack.application_findings'::regclass) THEN
        RAISE EXCEPTION 'RLS disabled';
    END IF;
    RAISE NOTICE 'ok - findings RLS remains enabled';
END $$;
ROLLBACK;
