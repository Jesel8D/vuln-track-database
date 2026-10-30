-- Baseline V1 de inicialización; PROPUESTA implementada para revisión.
-- No es una migración Alembic ni un script para reaplicar en una base existente.
\set ON_ERROR_STOP on
BEGIN;
CREATE SCHEMA vulntrack;
REVOKE ALL ON SCHEMA vulntrack FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Rechaza cadenas vacías o con espacios ASCII en sus extremos; la API deberá
-- normalizar Unicode y validar semántica, permisos y contenido no sensible.
CREATE FUNCTION vulntrack.valid_text(value text, maximum integer)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT char_length(value) BETWEEN 1 AND maximum
       AND value !~ '^[[:space:]]|[[:space:]]$' $$;

CREATE TABLE vulntrack.users (
    id uuid PRIMARY KEY,
    username text NOT NULL UNIQUE,
    password_hash text,
    active boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT users_username_valid CHECK (
        username ~ '^[a-z0-9][a-z0-9_.-]{0,79}$'),
    -- Filtro de formato, no verificador criptográfico ni autenticación.
    CONSTRAINT users_hash_not_plaintext CHECK (
        password_hash IS NULL OR password_hash ~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$'),
    CONSTRAINT users_time_order CHECK (updated_at >= created_at)
);

CREATE TABLE vulntrack.assets (
    id uuid PRIMARY KEY,
    device_type text NOT NULL,
    manufacturer text NOT NULL,
    model text NOT NULL,
    version text NOT NULL,
    site_label text NOT NULL,
    inventory_label text,
    notes text,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT assets_device_type_valid CHECK (vulntrack.valid_text(device_type, 80)),
    CONSTRAINT assets_manufacturer_valid CHECK (vulntrack.valid_text(manufacturer, 120)),
    CONSTRAINT assets_model_valid CHECK (vulntrack.valid_text(model, 120)),
    CONSTRAINT assets_version_valid CHECK (vulntrack.valid_text(version, 120)),
    CONSTRAINT assets_site_label_valid CHECK (vulntrack.valid_text(site_label, 120)),
    CONSTRAINT assets_inventory_label_valid CHECK (
        inventory_label IS NULL OR vulntrack.valid_text(inventory_label, 120)),
    CONSTRAINT assets_notes_valid CHECK (notes IS NULL OR vulntrack.valid_text(notes, 1000)),
    CONSTRAINT assets_time_order CHECK (updated_at >= created_at)
);

CREATE TABLE vulntrack.analysis_runs (
    id uuid PRIMARY KEY,
    kind text NOT NULL DEFAULT 'nvd_cve',
    asset_id uuid NOT NULL REFERENCES vulntrack.assets(id) ON DELETE RESTRICT,
    initiated_by uuid NOT NULL REFERENCES vulntrack.users(id) ON DELETE RESTRICT,
    selected_cpe text NOT NULL,
    status text NOT NULL DEFAULT 'queued',
    coverage text,
    source_timestamp timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    -- ZAP se rechaza en V1: no existe todavía catálogo de destinos seguro.
    CONSTRAINT analysis_runs_kind_v1 CHECK (kind = 'nvd_cve'),
    -- Solo guarda el CPE elegido; no sustituye validación CPE 2.3 de la API.
    CONSTRAINT analysis_runs_cpe_valid CHECK (
        left(selected_cpe, 8) = 'cpe:2.3:' AND vulntrack.valid_text(selected_cpe, 1024)),
    CONSTRAINT analysis_runs_status_valid CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    CONSTRAINT analysis_runs_coverage_valid CHECK (coverage IN ('complete', 'partial')),
    CONSTRAINT analysis_runs_lifecycle CHECK (
        (status = 'queued' AND started_at IS NULL AND completed_at IS NULL AND coverage IS NULL)
        OR (status = 'running' AND started_at IS NOT NULL AND completed_at IS NULL AND coverage IS NULL)
        OR (status = 'completed' AND started_at IS NOT NULL AND completed_at IS NOT NULL AND coverage IS NOT NULL)
        OR (status = 'failed' AND completed_at IS NOT NULL)
    ),
    CONSTRAINT analysis_runs_execution_order CHECK (completed_at >= started_at),
    CONSTRAINT analysis_runs_time_order CHECK (updated_at >= created_at)
);

CREATE TABLE vulntrack.findings (
    id uuid PRIMARY KEY,
    analysis_id uuid NOT NULL REFERENCES vulntrack.analysis_runs(id) ON DELETE RESTRICT,
    source text NOT NULL DEFAULT 'NVD',
    external_id text NOT NULL,
    title text,
    applicability text NOT NULL DEFAULT 'potential',
    status text NOT NULL DEFAULT 'open',
    cvss jsonb,
    observed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT findings_source_v1 CHECK (source = 'NVD'),
    CONSTRAINT findings_cve_valid CHECK (external_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    CONSTRAINT findings_title_valid CHECK (title IS NULL OR vulntrack.valid_text(title, 500)),
    CONSTRAINT findings_applicability_v1 CHECK (applicability = 'potential'),
    CONSTRAINT findings_status_valid CHECK (status IN ('open', 'reviewed')),
    -- Se conserva la representación original, sin elegir ni convertir versión.
    CONSTRAINT findings_cvss_object CHECK (cvss IS NULL OR jsonb_typeof(cvss) = 'object'),
    CONSTRAINT findings_time_order CHECK (updated_at >= created_at)
);

-- Soporte de persistencia, no garantía de idempotencia extremo a extremo.
-- Backend deberá crear activo y registro en la MISMA transacción, autorizar al
-- actor, calcular la huella, devolver snapshot y resolver expiración/conflictos.
CREATE TABLE vulntrack.asset_registration_requests (
    user_id uuid NOT NULL REFERENCES vulntrack.users(id) ON DELETE RESTRICT,
    method text NOT NULL DEFAULT 'POST',
    route text NOT NULL DEFAULT '/assets',
    idempotency_key uuid NOT NULL,
    request_hash text NOT NULL,
    asset_id uuid NOT NULL REFERENCES vulntrack.assets(id) ON DELETE RESTRICT,
    response_status smallint NOT NULL DEFAULT 201,
    response_body jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT statement_timestamp() + interval '24 hours',
    PRIMARY KEY (user_id, method, route, idempotency_key),
    CONSTRAINT registration_scope CHECK (method = 'POST' AND route = '/assets'),
    CONSTRAINT registration_hash_valid CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT registration_response_status CHECK (response_status = 201),
    CONSTRAINT registration_response_valid CHECK (
        jsonb_typeof(response_body) = 'object'
        AND response_body ? 'id'
        AND response_body->>'id' IS NOT NULL
        AND response_body->>'id' = asset_id::text),
    CONSTRAINT registration_expiry CHECK (expires_at > created_at)
);

-- Índices a partir de las consultas previstas, además de PK y UNIQUE.
CREATE INDEX assets_created_id_idx ON vulntrack.assets (created_at, id);
CREATE INDEX analysis_runs_asset_started_idx ON vulntrack.analysis_runs (asset_id, started_at DESC, id);
CREATE INDEX analysis_runs_initiated_by_idx ON vulntrack.analysis_runs (initiated_by);
CREATE INDEX findings_analysis_id_idx ON vulntrack.findings (analysis_id, id);
CREATE INDEX registration_asset_id_idx ON vulntrack.asset_registration_requests (asset_id);

CREATE FUNCTION vulntrack.touch_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'id y created_at son inmutables' USING ERRCODE = '23514';
    END IF;
    NEW.updated_at := greatest(clock_timestamp(), OLD.updated_at);
    RETURN NEW;
END $$;

CREATE TRIGGER users_touch BEFORE UPDATE ON vulntrack.users
FOR EACH ROW EXECUTE FUNCTION vulntrack.touch_updated_at();
CREATE TRIGGER assets_touch BEFORE UPDATE ON vulntrack.assets
FOR EACH ROW EXECUTE FUNCTION vulntrack.touch_updated_at();
CREATE TRIGGER analysis_runs_touch BEFORE UPDATE ON vulntrack.analysis_runs
FOR EACH ROW EXECUTE FUNCTION vulntrack.touch_updated_at();
CREATE TRIGGER findings_touch BEFORE UPDATE ON vulntrack.findings
FOR EACH ROW EXECUTE FUNCTION vulntrack.touch_updated_at();
COMMENT ON SCHEMA vulntrack IS 'Database V1: esquema provisional, PROPUESTA técnica implementada';
COMMENT ON TABLE vulntrack.assets IS 'Inventario; registrar un dispositivo no autoriza escanearlo';
COMMENT ON TABLE vulntrack.analysis_runs IS 'Solo consultas NVD V1; no ejecuta integraciones';
COMMENT ON TABLE vulntrack.findings IS 'CVE potencialmente aplicables, nunca confirmados automáticamente';
COMMENT ON TABLE vulntrack.asset_registration_requests IS 'Soporte transaccional; API e idempotencia E2E pendientes';
COMMIT;
