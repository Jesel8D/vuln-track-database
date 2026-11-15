-- Incremental V2 stabilization. Apply once after 004/005/006 as maintenance operator.
-- Retains every historical value/row and all RLS/privilege/immutability guards.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';
DO $$
BEGIN
    IF to_regclass('vulntrack.application_findings') IS NULL
       OR to_regprocedure('vulntrack.guard_nvd_finding()') IS NULL
       OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='vulntrack_registration') THEN
        RAISE EXCEPTION 'SQL004/005/006 required before SQL007';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='vulntrack.application_findings'::regclass
          AND conname='app_findings_applicability_valid'
          AND pg_get_constraintdef(oid) =
              'CHECK ((applicability = ANY (ARRAY[''potential''::text, ''confirmed''::text, ''not_applicable''::text])))'
    ) THEN
        RAISE EXCEPTION 'Expected original V2 applicability constraint; inspect drift or prior application';
    END IF;
END $$;
ALTER TABLE vulntrack.application_findings
    DROP CONSTRAINT app_findings_applicability_valid,
    ADD CONSTRAINT app_findings_applicability_valid
        CHECK (applicability IN ('potential','confirmed','undetermined','not_applicable')) NOT VALID;
ALTER TABLE vulntrack.application_findings VALIDATE CONSTRAINT app_findings_applicability_valid;
COMMENT ON CONSTRAINT app_findings_applicability_valid ON vulntrack.application_findings IS
    'V2 stabilization SQL007: undetermined matches the existing API/evaluator; retains historical confirmed';
COMMIT;
