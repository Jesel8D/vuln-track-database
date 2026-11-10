-- Persistencia acotada para consultas NVD CVE 2.0 desde Backend.
-- Aditiva: conserva V1 y V2. Ejecutar una vez tras 004 en instalaciones existentes.
\set ON_ERROR_STOP on
BEGIN;

ALTER TABLE vulntrack.application_analysis_runs
    ADD COLUMN request_key uuid,
    ADD COLUMN request_hash text,
    ADD COLUMN query_parameters jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN total_results integer,
    ADD COLUMN retrieved_count integer NOT NULL DEFAULT 0,
    ADD COLUMN stored_count integer NOT NULL DEFAULT 0,
    ADD COLUMN page_count integer NOT NULL DEFAULT 0,
    ADD COLUMN next_index integer NOT NULL DEFAULT 0,
    ADD COLUMN warning_codes jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN source_timestamps jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN page_manifest jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN failure_code text,
    ADD CONSTRAINT app_runs_request_hash_valid CHECK (
        request_hash IS NULL OR request_hash ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT app_runs_idempotency_pair CHECK (
        (request_key IS NULL AND request_hash IS NULL)
        OR (request_key IS NOT NULL AND request_hash IS NOT NULL)),
    ADD CONSTRAINT app_runs_idempotency_unique UNIQUE (workspace_id, initiated_by, request_key),
    ADD CONSTRAINT app_runs_nvd_counts_valid CHECK (
        retrieved_count >= 0 AND stored_count >= 0 AND stored_count <= retrieved_count
        AND page_count BETWEEN 0 AND 5 AND next_index >= 0
        AND (total_results IS NULL OR total_results >= 0)),
    ADD CONSTRAINT app_runs_nvd_metadata_valid CHECK (
        jsonb_typeof(query_parameters) = 'object' AND octet_length(query_parameters::text) <= 4096
        AND jsonb_typeof(warning_codes) = 'array' AND jsonb_array_length(warning_codes) <= 20
        AND jsonb_typeof(source_timestamps) = 'array' AND jsonb_array_length(source_timestamps) <= 5
        AND jsonb_typeof(page_manifest) = 'array' AND jsonb_array_length(page_manifest) <= 5
        AND octet_length(page_manifest::text) <= 8192),
    ADD CONSTRAINT app_runs_failure_code_valid CHECK (
        failure_code IS NULL OR failure_code ~ '^[A-Z][A-Z0-9_]{0,79}$'),
    ADD CONSTRAINT app_runs_nvd_outcome_valid CHECK (
        request_key IS NULL
        OR ((status IN ('queued','running') AND coverage IS NULL AND failure_code IS NULL)
        OR (status='completed' AND page_count > 0 AND coverage IS NOT NULL
            AND (coverage='partial' OR (failure_code IS NULL
                AND next_index=total_results AND stored_count=total_results)))
        OR (status='failed' AND coverage IS NULL AND failure_code IS NOT NULL)));

ALTER TABLE vulntrack.application_findings
    ADD COLUMN evidence jsonb,
    ADD COLUMN published_at timestamptz,
    ADD COLUMN last_modified_at timestamptz,
    ADD CONSTRAINT app_findings_evidence_valid CHECK (
        evidence IS NULL OR (jsonb_typeof(evidence) = 'object'
            AND octet_length(evidence::text) <= 65536));

CREATE INDEX app_runs_queue_idx
    ON vulntrack.application_analysis_runs (created_at, id) WHERE status = 'queued';
CREATE INDEX app_runs_idempotency_lookup_idx
    ON vulntrack.application_analysis_runs (workspace_id, initiated_by, request_key)
    WHERE request_key IS NOT NULL;
CREATE UNIQUE INDEX app_runs_one_active_technology_idx
    ON vulntrack.application_analysis_runs (workspace_id, technology_id)
    WHERE request_key IS NOT NULL AND status IN ('queued','running');

CREATE FUNCTION vulntrack.guard_nvd_analysis_run() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, vulntrack AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'El historial de análisis es inmutable' USING ERRCODE = '23514';
    ELSIF TG_OP = 'INSERT' THEN
        IF NEW.kind <> 'nvd_cve' OR NEW.status <> 'queued' OR NEW.page_count <> 0
           OR NEW.retrieved_count <> 0 OR NEW.stored_count <> 0 OR NEW.next_index <> 0
           OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
            RAISE EXCEPTION 'La consulta NVD debe iniciar en queued' USING ERRCODE = '23514';
        END IF;
    ELSE
        IF ROW(NEW.id,NEW.workspace_id,NEW.application_id,NEW.target_id,NEW.technology_id,
               NEW.kind,NEW.initiated_by,NEW.selected_cpe,NEW.request_key,NEW.request_hash,
               NEW.query_parameters,NEW.created_at)
           IS DISTINCT FROM
           ROW(OLD.id,OLD.workspace_id,OLD.application_id,OLD.target_id,OLD.technology_id,
               OLD.kind,OLD.initiated_by,OLD.selected_cpe,OLD.request_key,OLD.request_hash,
               OLD.query_parameters,OLD.created_at)
           OR OLD.status IN ('completed','failed')
           OR NOT ((OLD.status='queued' AND NEW.status IN ('running','failed'))
                OR (OLD.status='running' AND NEW.status IN ('running','completed','failed')))
           OR NEW.retrieved_count < OLD.retrieved_count
           OR NEW.stored_count < OLD.stored_count
           OR NEW.page_count < OLD.page_count
           OR NEW.next_index < OLD.next_index
           OR (OLD.total_results IS NOT NULL AND NEW.total_results IS DISTINCT FROM OLD.total_results)
           OR NOT (NEW.warning_codes @> OLD.warning_codes)
           OR NOT (NEW.source_timestamps @> OLD.source_timestamps)
           OR NOT (NEW.page_manifest @> OLD.page_manifest)
           OR (OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at) THEN
            RAISE EXCEPTION 'Transición o snapshot NVD inválido' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER nvd_analysis_run_guard
    BEFORE INSERT OR UPDATE OR DELETE ON vulntrack.application_analysis_runs
    FOR EACH ROW EXECUTE FUNCTION vulntrack.guard_nvd_analysis_run();

CREATE FUNCTION vulntrack.guard_nvd_finding() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, vulntrack AS $$
DECLARE analysis_status text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Los hallazgos NVD son inmutables' USING ERRCODE = '23514';
    END IF;
    SELECT status INTO analysis_status FROM vulntrack.application_analysis_runs
      WHERE workspace_id=NEW.workspace_id AND id=NEW.analysis_id FOR UPDATE;
    IF TG_OP = 'INSERT' THEN
        IF analysis_status <> 'running' OR NEW.evidence IS NULL
           OR NEW.applicability NOT IN ('potential','undetermined') OR NEW.status <> 'open' THEN
            RAISE EXCEPTION 'Hallazgo NVD debe provenir de una consulta activa y evidencia' USING ERRCODE = '23514';
        END IF;
    ELSIF ROW(NEW.id,NEW.workspace_id,NEW.analysis_id,NEW.source,NEW.external_id,NEW.title,
              NEW.severity,NEW.cvss,NEW.evidence,NEW.published_at,NEW.last_modified_at,
              NEW.observed_at,NEW.created_at)
          IS DISTINCT FROM
          ROW(OLD.id,OLD.workspace_id,OLD.analysis_id,OLD.source,OLD.external_id,OLD.title,
              OLD.severity,OLD.cvss,OLD.evidence,OLD.published_at,OLD.last_modified_at,
              OLD.observed_at,OLD.created_at)
          OR OLD.status <> 'open' OR analysis_status NOT IN ('completed','failed')
          OR NEW.status <> 'reviewed' THEN
        RAISE EXCEPTION 'Solo se permite revisión humana de un hallazgo NVD terminado' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER nvd_finding_guard
    BEFORE INSERT OR UPDATE OR DELETE ON vulntrack.application_findings
    FOR EACH ROW EXECUTE FUNCTION vulntrack.guard_nvd_finding();

-- Permite a un usuario autenticado crear su primer workspace. El contexto
-- normal requiere membresía previa, lo que de otro modo hace imposible bootstrap.
CREATE FUNCTION vulntrack.establish_new_workspace_context(
    requested_user uuid, requested_workspace uuid, expires_epoch bigint,
    request_nonce uuid, request_signature text
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, vulntrack, vulntrack_private AS $$
DECLARE context_key bytea; signed_payload text;
BEGIN
    IF requested_user IS NULL OR requested_workspace IS NULL OR expires_epoch IS NULL
       OR request_nonce IS NULL OR request_signature IS NULL
       OR expires_epoch <= floor(extract(epoch FROM clock_timestamp()))::bigint
       OR expires_epoch > floor(extract(epoch FROM clock_timestamp()))::bigint + 60
       OR request_signature !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'contexto firmado inválido o expirado' USING ERRCODE = '28000';
    END IF;
    SELECT hmac_key INTO STRICT context_key
      FROM vulntrack_private.context_keys WHERE singleton;
    signed_payload := 'v1|' || requested_user::text || '|' || requested_workspace::text || '|'
        || expires_epoch::text || '|' || request_nonce::text;
    IF public.hmac(convert_to(signed_payload, 'UTF8'), context_key, 'sha256')
       <> decode(request_signature, 'hex') THEN
        RAISE EXCEPTION 'firma de contexto inválida' USING ERRCODE = '28000';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM vulntrack.users u
                   WHERE u.id=requested_user AND u.active) THEN
        RAISE EXCEPTION 'usuario inactivo' USING ERRCODE = '42501';
    END IF;
    PERFORM set_config('vulntrack.context_user', requested_user::text, true);
    PERFORM set_config('vulntrack.context_workspace', requested_workspace::text, true);
    PERFORM set_config('vulntrack.context_expiry', expires_epoch::text, true);
    PERFORM set_config('vulntrack.context_nonce', request_nonce::text, true);
    PERFORM set_config('vulntrack.context_signature', request_signature, true);
END $$;

-- Enumera solo los workspaces del usuario autenticado, para que el cliente
-- pueda recuperar su lista sin conocer previamente un workspace_id.
CREATE FUNCTION vulntrack.list_user_workspaces(
    requested_user uuid, expires_epoch bigint, request_nonce uuid, request_signature text
) RETURNS TABLE(workspace_id uuid, name text, role text, created_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = pg_catalog, vulntrack, vulntrack_private AS $$
DECLARE context_key bytea; signed_payload text;
BEGIN
    IF requested_user IS NULL OR expires_epoch IS NULL
       OR request_nonce IS NULL OR request_signature IS NULL
       OR expires_epoch <= floor(extract(epoch FROM clock_timestamp()))::bigint
       OR expires_epoch > floor(extract(epoch FROM clock_timestamp()))::bigint + 60
       OR request_signature !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'contexto firmado inválido o expirado' USING ERRCODE = '28000';
    END IF;
    SELECT hmac_key INTO STRICT context_key
      FROM vulntrack_private.context_keys WHERE singleton;
    signed_payload := 'v1-directory|' || requested_user::text || '|'
        || expires_epoch::text || '|' || request_nonce::text;
    IF public.hmac(convert_to(signed_payload, 'UTF8'), context_key, 'sha256')
       <> decode(request_signature, 'hex') THEN
        RAISE EXCEPTION 'firma de contexto inválida' USING ERRCODE = '28000';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM vulntrack.users u
                   WHERE u.id=requested_user AND u.active) THEN
        RAISE EXCEPTION 'usuario inactivo' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT w.id,w.name,wm.role,w.created_at
        FROM vulntrack.workspace_members wm
        JOIN vulntrack.workspaces w ON w.id=wm.workspace_id
        WHERE wm.user_id=requested_user ORDER BY w.created_at DESC,w.id;
END $$;

REVOKE ALL ON FUNCTION vulntrack.guard_nvd_analysis_run() FROM PUBLIC;
REVOKE ALL ON FUNCTION vulntrack.guard_nvd_finding() FROM PUBLIC;
REVOKE ALL ON FUNCTION vulntrack.establish_new_workspace_context(uuid,uuid,bigint,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION vulntrack.list_user_workspaces(uuid,bigint,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vulntrack.establish_new_workspace_context(uuid,uuid,bigint,uuid,text)
    TO vulntrack_app;
GRANT EXECUTE ON FUNCTION vulntrack.list_user_workspaces(uuid,bigint,uuid,text) TO vulntrack_app;

GRANT UPDATE (total_results, retrieved_count, stored_count, page_count, next_index,
    warning_codes, source_timestamps, page_manifest, failure_code)
    ON vulntrack.application_analysis_runs TO vulntrack_app;

COMMENT ON COLUMN vulntrack.application_analysis_runs.query_parameters IS
    'Parámetros normalizados de NVD; nunca contiene credenciales ni secretos.';
COMMENT ON COLUMN vulntrack.application_analysis_runs.page_manifest IS
    'Huella y metadatos acotados de páginas recuperadas; la evidencia CVE vive en findings.';
COMMENT ON COLUMN vulntrack.application_findings.evidence IS
    'Fragmento NVD acotado y saneado para trazabilidad; no acredita aplicabilidad.';

COMMIT;
