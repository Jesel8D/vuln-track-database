-- V2 aditiva: espacios de trabajo y gestión de aplicaciones web.
-- Preserva las tablas V1; no asigna propiedad ni transforma activos heredados.
-- Ejecutar una sola vez por operador con privilegios de migración, tras backup.
\set ON_ERROR_STOP on
BEGIN;

CREATE TABLE vulntrack.workspaces (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    created_by uuid NOT NULL REFERENCES vulntrack.users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT workspaces_name_valid CHECK (vulntrack.valid_text(name, 120)),
    CONSTRAINT workspaces_time_order CHECK (updated_at >= created_at),
    UNIQUE (id, created_by)
);

CREATE TABLE vulntrack.workspace_members (
    workspace_id uuid NOT NULL,
    user_id uuid NOT NULL REFERENCES vulntrack.users(id) ON DELETE RESTRICT,
    role text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (workspace_id, user_id),
    CONSTRAINT workspace_members_workspace_fk FOREIGN KEY (workspace_id)
        REFERENCES vulntrack.workspaces(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT workspace_members_role CHECK (role IN ('owner', 'editor', 'viewer'))
);

-- El creador queda vinculado como owner mediante FK compuesta, evitando que
-- una fila de membresía relacione un workspace con otro usuario como creador.
ALTER TABLE vulntrack.workspaces ADD CONSTRAINT workspaces_creator_membership_fk
    FOREIGN KEY (id, created_by) REFERENCES vulntrack.workspace_members(workspace_id, user_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE vulntrack.applications (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES vulntrack.workspaces(id) ON DELETE RESTRICT,
    name text NOT NULL,
    description text,
    status text NOT NULL DEFAULT 'active',
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT applications_name_valid CHECK (vulntrack.valid_text(name, 160)),
    CONSTRAINT applications_description_valid CHECK (
        description IS NULL OR vulntrack.valid_text(description, 2000)),
    CONSTRAINT applications_status_valid CHECK (status IN ('active', 'archived')),
    CONSTRAINT applications_time_order CHECK (updated_at >= created_at),
    CONSTRAINT applications_creator_member_fk FOREIGN KEY (workspace_id, created_by)
        REFERENCES vulntrack.workspace_members(workspace_id, user_id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, id)
);

CREATE TABLE vulntrack.application_targets (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    application_id uuid NOT NULL,
    url text NOT NULL,
    label text,
    authorization_status text NOT NULL DEFAULT 'pending',
    authorization_expires_at timestamptz,
    authorization_reference text,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT targets_application_fk FOREIGN KEY (workspace_id, application_id)
        REFERENCES vulntrack.applications(workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT targets_creator_member_fk FOREIGN KEY (workspace_id, created_by)
        REFERENCES vulntrack.workspace_members(workspace_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT targets_url_valid CHECK (
        vulntrack.valid_text(url, 2048)
        AND url ~* '^https?://[^/@[:space:]]+(:[0-9]{1,5})?(/[^[:space:]]*)?$'
        AND url !~ '[#[:cntrl:]]'),
    CONSTRAINT targets_label_valid CHECK (label IS NULL OR vulntrack.valid_text(label, 120)),
    CONSTRAINT targets_authorization_valid CHECK (
        authorization_status IN ('pending', 'approved', 'rejected', 'expired')),
    CONSTRAINT targets_approval_has_expiry CHECK (
        authorization_status <> 'approved' OR authorization_expires_at IS NOT NULL),
    CONSTRAINT targets_reference_valid CHECK (
        authorization_reference IS NULL OR vulntrack.valid_text(authorization_reference, 500)),
    CONSTRAINT targets_time_order CHECK (updated_at >= created_at),
    UNIQUE (workspace_id, application_id, id)
);

CREATE TABLE vulntrack.technologies (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    application_id uuid NOT NULL,
    product text NOT NULL,
    vendor text,
    version text NOT NULL,
    selected_cpe text,
    detection_method text NOT NULL,
    confidence text NOT NULL DEFAULT 'unconfirmed',
    observed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT technologies_application_fk FOREIGN KEY (workspace_id, application_id)
        REFERENCES vulntrack.applications(workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT technologies_creator_member_fk FOREIGN KEY (workspace_id, created_by)
        REFERENCES vulntrack.workspace_members(workspace_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT technologies_product_valid CHECK (vulntrack.valid_text(product, 160)),
    CONSTRAINT technologies_vendor_valid CHECK (vendor IS NULL OR vulntrack.valid_text(vendor, 160)),
    CONSTRAINT technologies_version_valid CHECK (vulntrack.valid_text(version, 120)),
    CONSTRAINT technologies_cpe_valid CHECK (
        selected_cpe IS NULL OR (left(selected_cpe, 8) = 'cpe:2.3:'
            AND vulntrack.valid_text(selected_cpe, 1024))),
    CONSTRAINT technologies_method_valid CHECK (
        detection_method IN ('manual', 'http_fingerprint', 'manifest_import')),
    CONSTRAINT technologies_confidence_valid CHECK (
        confidence IN ('unconfirmed', 'user_confirmed', 'high', 'medium', 'low')),
    CONSTRAINT technologies_time_order CHECK (updated_at >= created_at),
    UNIQUE (workspace_id, application_id, id)
);

CREATE TABLE vulntrack.application_analysis_runs (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    application_id uuid NOT NULL,
    target_id uuid,
    technology_id uuid,
    kind text NOT NULL DEFAULT 'nvd_cve',
    initiated_by uuid NOT NULL,
    selected_cpe text,
    status text NOT NULL DEFAULT 'queued',
    coverage text,
    source_timestamp timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT app_runs_application_fk FOREIGN KEY (workspace_id, application_id)
        REFERENCES vulntrack.applications(workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT app_runs_target_fk FOREIGN KEY (workspace_id, application_id, target_id)
        REFERENCES vulntrack.application_targets(workspace_id, application_id, id) ON DELETE RESTRICT,
    CONSTRAINT app_runs_technology_fk FOREIGN KEY (workspace_id, application_id, technology_id)
        REFERENCES vulntrack.technologies(workspace_id, application_id, id) ON DELETE RESTRICT,
    CONSTRAINT app_runs_initiator_fk FOREIGN KEY (workspace_id, initiated_by)
        REFERENCES vulntrack.workspace_members(workspace_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT app_runs_kind_v2 CHECK (kind = 'nvd_cve'),
    CONSTRAINT app_runs_nvd_cpe CHECK (
        selected_cpe IS NOT NULL AND left(selected_cpe, 8) = 'cpe:2.3:'
        AND vulntrack.valid_text(selected_cpe, 1024)),
    CONSTRAINT app_runs_status_valid CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    CONSTRAINT app_runs_coverage_valid CHECK (coverage IN ('complete', 'partial')),
    CONSTRAINT app_runs_lifecycle CHECK (
        (status = 'queued' AND started_at IS NULL AND completed_at IS NULL AND coverage IS NULL)
        OR (status = 'running' AND started_at IS NOT NULL AND completed_at IS NULL AND coverage IS NULL)
        OR (status = 'completed' AND started_at IS NOT NULL AND completed_at IS NOT NULL AND coverage IS NOT NULL)
        OR (status = 'failed' AND completed_at IS NOT NULL)),
    CONSTRAINT app_runs_time_order CHECK (completed_at >= started_at AND updated_at >= created_at),
    UNIQUE (workspace_id, id)
);

CREATE TABLE vulntrack.application_findings (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    analysis_id uuid NOT NULL,
    source text NOT NULL DEFAULT 'NVD',
    external_id text NOT NULL,
    title text,
    severity text,
    cvss jsonb,
    applicability text NOT NULL DEFAULT 'potential',
    status text NOT NULL DEFAULT 'open',
    observed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT app_findings_run_fk FOREIGN KEY (workspace_id, analysis_id)
        REFERENCES vulntrack.application_analysis_runs(workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT app_findings_source_valid CHECK (source = 'NVD'),
    CONSTRAINT app_findings_external_id_valid CHECK (external_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    CONSTRAINT app_findings_title_valid CHECK (title IS NULL OR vulntrack.valid_text(title, 500)),
    CONSTRAINT app_findings_severity_valid CHECK (
        severity IS NULL OR severity IN ('critical', 'high', 'medium', 'low', 'none', 'unknown')),
    CONSTRAINT app_findings_cvss_object CHECK (cvss IS NULL OR jsonb_typeof(cvss) = 'object'),
    CONSTRAINT app_findings_applicability_valid CHECK (applicability IN ('potential', 'confirmed', 'not_applicable')),
    CONSTRAINT app_findings_status_valid CHECK (status IN ('open', 'reviewed', 'resolved', 'accepted_risk')),
    CONSTRAINT app_findings_time_order CHECK (updated_at >= created_at),
    UNIQUE (workspace_id, analysis_id, source, external_id),
    UNIQUE (workspace_id, id)
);

CREATE TABLE vulntrack.recommendations (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    recommendation text NOT NULL,
    source_url text,
    status text NOT NULL DEFAULT 'pending',
    assigned_to uuid,
    created_by uuid NOT NULL,
    due_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT recommendations_finding_fk FOREIGN KEY (workspace_id, finding_id)
        REFERENCES vulntrack.application_findings(workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT recommendations_assignee_fk FOREIGN KEY (workspace_id, assigned_to)
        REFERENCES vulntrack.workspace_members(workspace_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT recommendations_creator_fk FOREIGN KEY (workspace_id, created_by)
        REFERENCES vulntrack.workspace_members(workspace_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT recommendations_text_valid CHECK (vulntrack.valid_text(recommendation, 4000)),
    CONSTRAINT recommendations_source_url_valid CHECK (
        source_url IS NULL OR (vulntrack.valid_text(source_url, 2048)
            AND source_url ~* '^https?://[^/@[:space:]]+(/[^[:space:]]*)?$')),
    CONSTRAINT recommendations_status_valid CHECK (
        status IN ('pending', 'in_progress', 'fixed', 'accepted_risk')),
    CONSTRAINT recommendations_fixed_has_time CHECK (status <> 'fixed' OR completed_at IS NOT NULL),
    CONSTRAINT recommendations_time_order CHECK (updated_at >= created_at),
    UNIQUE (workspace_id, id)
);

CREATE TABLE vulntrack.dependency_imports (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    application_id uuid NOT NULL,
    format text NOT NULL,
    content_sha256 text NOT NULL,
    dependency_count integer NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'completed',
    imported_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT imports_application_fk FOREIGN KEY (workspace_id, application_id)
        REFERENCES vulntrack.applications(workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT imports_actor_fk FOREIGN KEY (workspace_id, imported_by)
        REFERENCES vulntrack.workspace_members(workspace_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT imports_format_valid CHECK (format IN ('package_json', 'requirements_txt', 'pom_xml', 'composer_json')),
    CONSTRAINT imports_hash_valid CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT imports_count_valid CHECK (dependency_count BETWEEN 0 AND 100000),
    CONSTRAINT imports_status_valid CHECK (status IN ('completed', 'failed'))
);

CREATE TABLE vulntrack.audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES vulntrack.workspaces(id) ON DELETE RESTRICT,
    actor_id uuid NOT NULL,
    action text NOT NULL,
    object_type text NOT NULL,
    object_id uuid,
    occurred_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT audit_actor_member_fk FOREIGN KEY (workspace_id, actor_id)
        REFERENCES vulntrack.workspace_members(workspace_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT audit_action_valid CHECK (vulntrack.valid_text(action, 80)),
    CONSTRAINT audit_object_type_valid CHECK (vulntrack.valid_text(object_type, 80))
);

CREATE INDEX applications_workspace_created_idx ON vulntrack.applications (workspace_id, created_at DESC, id);
CREATE INDEX targets_application_idx ON vulntrack.application_targets (workspace_id, application_id, id);
CREATE INDEX technologies_application_idx ON vulntrack.technologies (workspace_id, application_id, id);
CREATE INDEX app_runs_application_created_idx ON vulntrack.application_analysis_runs (workspace_id, application_id, created_at DESC, id);
CREATE INDEX app_runs_target_idx ON vulntrack.application_analysis_runs (workspace_id, application_id, target_id);
CREATE INDEX app_runs_technology_idx ON vulntrack.application_analysis_runs (workspace_id, application_id, technology_id);
CREATE INDEX app_findings_run_idx ON vulntrack.application_findings (workspace_id, analysis_id, id);
CREATE INDEX recommendations_finding_idx ON vulntrack.recommendations (workspace_id, finding_id, id);
CREATE INDEX imports_application_idx ON vulntrack.dependency_imports (workspace_id, application_id, created_at DESC);
CREATE INDEX audit_events_workspace_time_idx ON vulntrack.audit_events (workspace_id, occurred_at DESC, id);

-- El trigger compartido valida id/created_at inmutables y mantiene updated_at.
CREATE TRIGGER workspaces_touch BEFORE UPDATE ON vulntrack.workspaces
FOR EACH ROW EXECUTE FUNCTION vulntrack.touch_updated_at();
CREATE TRIGGER applications_touch BEFORE UPDATE ON vulntrack.applications
FOR EACH ROW EXECUTE FUNCTION vulntrack.touch_updated_at();
CREATE TRIGGER targets_touch BEFORE UPDATE ON vulntrack.application_targets
FOR EACH ROW EXECUTE FUNCTION vulntrack.touch_updated_at();
CREATE TRIGGER technologies_touch BEFORE UPDATE ON vulntrack.technologies
FOR EACH ROW EXECUTE FUNCTION vulntrack.touch_updated_at();
CREATE TRIGGER app_runs_touch BEFORE UPDATE ON vulntrack.application_analysis_runs
FOR EACH ROW EXECUTE FUNCTION vulntrack.touch_updated_at();
CREATE TRIGGER app_findings_touch BEFORE UPDATE ON vulntrack.application_findings
FOR EACH ROW EXECUTE FUNCTION vulntrack.touch_updated_at();
CREATE TRIGGER recommendations_touch BEFORE UPDATE ON vulntrack.recommendations
FOR EACH ROW EXECUTE FUNCTION vulntrack.touch_updated_at();

CREATE FUNCTION vulntrack.require_workspace_owner()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, vulntrack AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM vulntrack.workspace_members wm
        WHERE wm.workspace_id = NEW.id AND wm.user_id = NEW.created_by AND wm.role = 'owner'
    ) THEN
        RAISE EXCEPTION 'el creador debe ser owner del workspace' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER workspaces_require_owner
AFTER INSERT OR UPDATE ON vulntrack.workspaces
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION vulntrack.require_workspace_owner();

CREATE FUNCTION vulntrack.reject_audit_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'los eventos de auditoría son inmutables' USING ERRCODE = '23514';
END $$;
CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON vulntrack.audit_events
FOR EACH ROW EXECUTE FUNCTION vulntrack.reject_audit_mutation();

GRANT SELECT, INSERT ON vulntrack.workspaces, vulntrack.workspace_members,
    vulntrack.applications, vulntrack.application_targets, vulntrack.technologies,
    vulntrack.application_analysis_runs, vulntrack.application_findings,
    vulntrack.recommendations, vulntrack.dependency_imports TO vulntrack_app;
GRANT UPDATE (name) ON vulntrack.workspaces TO vulntrack_app;
GRANT UPDATE (name, description, status) ON vulntrack.applications TO vulntrack_app;
GRANT UPDATE (authorization_status, authorization_expires_at, authorization_reference)
    ON vulntrack.application_targets TO vulntrack_app;
GRANT UPDATE (confidence, selected_cpe) ON vulntrack.technologies TO vulntrack_app;
GRANT UPDATE (status, coverage, source_timestamp, started_at, completed_at)
    ON vulntrack.application_analysis_runs TO vulntrack_app;
GRANT UPDATE (applicability, status) ON vulntrack.application_findings TO vulntrack_app;
GRANT UPDATE (recommendation, source_url, status, assigned_to, due_at, completed_at)
    ON vulntrack.recommendations TO vulntrack_app;
GRANT INSERT ON vulntrack.audit_events TO vulntrack_app;
GRANT USAGE, SELECT ON SEQUENCE vulntrack.audit_events_id_seq TO vulntrack_app;
REVOKE ALL ON FUNCTION vulntrack.require_workspace_owner() FROM PUBLIC;
REVOKE ALL ON FUNCTION vulntrack.reject_audit_mutation() FROM PUBLIC;

-- Membresía owner se inserta en la misma transacción que el workspace.
-- DEFERRABLE permite crear ambas filas sin una ventana inconsistente.
COMMENT ON TABLE vulntrack.audit_events IS 'Eventos de auditoría sin payload; acceso de escritura es append-only.';
COMMENT ON TABLE vulntrack.application_targets IS 'Registrar URL no acredita autorización ni permite ejecutar un análisis.';
COMMENT ON TABLE vulntrack.application_findings IS 'Hallazgos NVD; aplicabilidad confirmada solo mediante revisión humana.';

COMMIT;
