\set ON_ERROR_STOP on
\o /dev/null
BEGIN;
CREATE FUNCTION pg_temp.assert_true(condition boolean, label text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF condition IS DISTINCT FROM true THEN RAISE EXCEPTION 'FALLO: %', label; END IF;
    RAISE NOTICE 'ok - %', label;
END $$;
CREATE FUNCTION pg_temp.expect_error(command text, expected_state text, label text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    BEGIN
        EXECUTE command;
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE <> expected_state THEN RAISE; END IF;
        RAISE NOTICE 'ok - % (%)', label, expected_state;
        RETURN;
    END;
    RAISE EXCEPTION 'FALLO: se esperaba %: %', expected_state, label;
END $$;
CREATE FUNCTION pg_temp.make_context_signature(
    user_id uuid, workspace_id uuid, expiry bigint, nonce uuid
) RETURNS text LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, vulntrack_private AS $$
    SELECT encode(public.hmac(
        convert_to('v1|' || user_id::text || '|' || workspace_id::text || '|'
            || expiry::text || '|' || nonce::text, 'UTF8'),
        (SELECT hmac_key FROM vulntrack_private.context_keys WHERE singleton), 'sha256'), 'hex')
$$;

INSERT INTO vulntrack.users (id, username, active) VALUES
('00000000-0000-4000-8000-000000000002', 'tenant_b', true)
ON CONFLICT (id) DO NOTHING;
INSERT INTO vulntrack.users (id, username, active) VALUES
('00000000-0000-4000-8000-000000000003', 'tenant_a_viewer', true)
ON CONFLICT (id) DO NOTHING;
UPDATE vulntrack.users SET active = true
WHERE id = '00000000-0000-4000-8000-000000000001';

-- Dos tenants independientes; workspace y owner se confirman juntos al COMMIT.
INSERT INTO vulntrack.workspaces (id, name, created_by) VALUES
('50000000-0000-4000-8000-000000000001', 'Tenant A', '00000000-0000-4000-8000-000000000001'),
('50000000-0000-4000-8000-000000000002', 'Tenant B', '00000000-0000-4000-8000-000000000002');
INSERT INTO vulntrack.workspace_members (workspace_id, user_id, role) VALUES
('50000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000001', 'owner'),
('50000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000003', 'viewer'),
('50000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000002', 'owner');
INSERT INTO vulntrack.applications (id, workspace_id, name, created_by) VALUES
('51000000-0000-4000-8000-000000000001', '50000000-0000-4000-8000-000000000001', 'App A', '00000000-0000-4000-8000-000000000001'),
('51000000-0000-4000-8000-000000000002', '50000000-0000-4000-8000-000000000002', 'App B', '00000000-0000-4000-8000-000000000002');
INSERT INTO vulntrack.application_targets
    (id, workspace_id, application_id, url, authorization_status, authorization_expires_at, created_by)
VALUES
('52000000-0000-4000-8000-000000000001', '50000000-0000-4000-8000-000000000001',
 '51000000-0000-4000-8000-000000000001', 'https://a.example.test', 'approved', now() + interval '1 day',
 '00000000-0000-4000-8000-000000000001'),
('52000000-0000-4000-8000-000000000002', '50000000-0000-4000-8000-000000000002',
 '51000000-0000-4000-8000-000000000002', 'https://b.example.test', 'approved', now() + interval '1 day',
 '00000000-0000-4000-8000-000000000002');
INSERT INTO vulntrack.technologies
    (id, workspace_id, application_id, product, version, selected_cpe, detection_method, created_by)
VALUES ('53000000-0000-4000-8000-000000000001', '50000000-0000-4000-8000-000000000001',
 '51000000-0000-4000-8000-000000000001', 'Demo', '1.0',
 'cpe:2.3:a:demo:product:1.0:*:*:*:*:*:*:*', 'manual', '00000000-0000-4000-8000-000000000001');

INSERT INTO vulntrack.application_analysis_runs
    (id, workspace_id, application_id, target_id, technology_id, initiated_by, selected_cpe)
VALUES ('54000000-0000-4000-8000-000000000001', '50000000-0000-4000-8000-000000000001',
 '51000000-0000-4000-8000-000000000001', '52000000-0000-4000-8000-000000000001',
 '53000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000001',
 'cpe:2.3:a:demo:product:1.0:*:*:*:*:*:*:*');

SELECT pg_temp.expect_error($q$INSERT INTO vulntrack.application_analysis_runs
    (id,workspace_id,application_id,target_id,initiated_by,selected_cpe)
    VALUES ('54000000-0000-4000-8000-000000000002','50000000-0000-4000-8000-000000000001',
    '51000000-0000-4000-8000-000000000001','52000000-0000-4000-8000-000000000002',
    '00000000-0000-4000-8000-000000000001','cpe:2.3:a:demo:product:1.0:*:*:*:*:*:*:*')$q$,
    '23503', 'target de otro workspace rechazado');
SELECT pg_temp.expect_error($q$INSERT INTO vulntrack.application_analysis_runs
    (id,workspace_id,application_id,initiated_by,selected_cpe)
    VALUES ('54000000-0000-4000-8000-000000000003','50000000-0000-4000-8000-000000000001',
    '51000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002',
    'cpe:2.3:a:demo:product:1.0:*:*:*:*:*:*:*')$q$,
    '23503', 'iniciador ajeno al workspace rechazado');
SET CONSTRAINTS vulntrack.workspaces_require_owner IMMEDIATE;
SELECT pg_temp.expect_error($q$INSERT INTO vulntrack.workspaces(id,name,created_by)
    VALUES ('50000000-0000-4000-8000-000000000003','Sin owner','00000000-0000-4000-8000-000000000001')$q$,
    '23514', 'workspace sin owner rechazado');
SELECT pg_temp.expect_error($q$INSERT INTO vulntrack.application_targets
    (id,workspace_id,application_id,url,created_by)
    VALUES ('52000000-0000-4000-8000-000000000003','50000000-0000-4000-8000-000000000001',
    '51000000-0000-4000-8000-000000000001','http://user:secret@a.example.test',
    '00000000-0000-4000-8000-000000000001')$q$,
    '23514', 'credenciales embebidas en URL rechazadas');
SELECT pg_temp.expect_error($q$INSERT INTO vulntrack.application_targets
    (id,workspace_id,application_id,url,created_by)
    VALUES ('52000000-0000-4000-8000-000000000004','50000000-0000-4000-8000-000000000001',
    '51000000-0000-4000-8000-000000000001','file:///etc/passwd',
    '00000000-0000-4000-8000-000000000001')$q$,
    '23514', 'esquema URL no HTTP rechazado');

INSERT INTO vulntrack.application_findings (id, workspace_id, analysis_id, external_id, title)
VALUES ('55000000-0000-4000-8000-000000000001', '50000000-0000-4000-8000-000000000001',
 '54000000-0000-4000-8000-000000000001', 'CVE-2026-12345', 'Hallazgo sintético');
INSERT INTO vulntrack.recommendations (id, workspace_id, finding_id, recommendation, created_by)
VALUES ('56000000-0000-4000-8000-000000000001', '50000000-0000-4000-8000-000000000001',
 '55000000-0000-4000-8000-000000000001', 'Actualizar a una versión corregida',
 '00000000-0000-4000-8000-000000000001');
INSERT INTO vulntrack.audit_events (workspace_id, actor_id, action, object_type, object_id)
VALUES ('50000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000001',
 'finding.reviewed', 'finding', '55000000-0000-4000-8000-000000000001');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.audit_events SET action = 'forged'$q$,
    '23514', 'auditoría append-only');
SELECT pg_temp.assert_true((SELECT count(*) = 2 FROM vulntrack.applications), 'aplicaciones separadas por workspace');
SET CONSTRAINTS vulntrack.workspace_members_owner_guard IMMEDIATE;
SELECT pg_temp.expect_error($q$UPDATE vulntrack.workspace_members SET role = 'viewer'
    WHERE workspace_id = '50000000-0000-4000-8000-000000000001'
      AND user_id = '00000000-0000-4000-8000-000000000001'$q$,
    '23514', 'workspace conserva el rol owner de su creador');

-- RLS debe proteger frente a consultas sin filtro explícito de workspace.
-- La firma HMAC ata el usuario y workspace; cambiar solo los GUC invalida el contexto.
SELECT floor(extract(epoch FROM clock_timestamp()))::bigint + 30 AS context_expiry,
       '57000000-0000-4000-8000-000000000001'::uuid AS context_nonce \gset
SELECT pg_temp.make_context_signature(
    '00000000-0000-4000-8000-000000000001',
    '50000000-0000-4000-8000-000000000001', :context_expiry, :'context_nonce'
) AS context_signature \gset
SET LOCAL ROLE vulntrack_app;
SELECT vulntrack.establish_context('00000000-0000-4000-8000-000000000001',
    '50000000-0000-4000-8000-000000000001', :context_expiry, :'context_nonce', :'context_signature');
SELECT pg_temp.assert_true((SELECT count(*) = 1 FROM vulntrack.applications),
    'RLS oculta aplicaciones del otro workspace incluso sin WHERE tenant');
SELECT set_config('vulntrack.context_user', '00000000-0000-4000-8000-000000000002', true);
SELECT set_config('vulntrack.context_workspace', '50000000-0000-4000-8000-000000000002', true);
SELECT pg_temp.assert_true(NOT vulntrack.context_is_valid(),
    'GUC falsificados no pasan la verificación HMAC');
SELECT pg_temp.assert_true((SELECT count(*) = 0 FROM vulntrack.applications),
    'contexto falsificado deja el acceso RLS vacío');
SELECT vulntrack.establish_context('00000000-0000-4000-8000-000000000001',
    '50000000-0000-4000-8000-000000000001', :context_expiry, :'context_nonce', :'context_signature');
SELECT pg_temp.expect_error($q$INSERT INTO vulntrack.applications(id,workspace_id,name,created_by)
    VALUES ('51000000-0000-4000-8000-000000000003','50000000-0000-4000-8000-000000000002',
    'Escritura cruzada','00000000-0000-4000-8000-000000000001')$q$,
    '42501', 'RLS rechaza escritura en workspace ajeno');
SELECT floor(extract(epoch FROM clock_timestamp()))::bigint + 30 AS context_expiry,
       '57000000-0000-4000-8000-000000000002'::uuid AS context_nonce \gset
SELECT pg_temp.make_context_signature(
    '00000000-0000-4000-8000-000000000003',
    '50000000-0000-4000-8000-000000000001', :context_expiry, :'context_nonce'
) AS context_signature \gset
SELECT vulntrack.establish_context('00000000-0000-4000-8000-000000000003',
    '50000000-0000-4000-8000-000000000001', :context_expiry, :'context_nonce', :'context_signature');
SELECT pg_temp.expect_error($q$INSERT INTO vulntrack.applications(id,workspace_id,name,created_by)
    VALUES ('51000000-0000-4000-8000-000000000004','50000000-0000-4000-8000-000000000001',
    'Escritura viewer','00000000-0000-4000-8000-000000000003')$q$,
    '42501', 'RLS rechaza escritura del rol viewer');
SELECT set_config('vulntrack.context_workspace', '50000000-0000-4000-8000-000000000002', true);
SELECT pg_temp.assert_true(NOT vulntrack.context_is_valid(), 'cambiar workspace sin nueva firma invalida contexto');
SELECT pg_temp.assert_true((SELECT count(*) = 0 FROM vulntrack.applications),
    'membresía impide consultar workspace ajeno al actor');
RESET ROLE;
ROLLBACK;
\o
\echo 'Seguridad V2: restricciones de pertenencia y relaciones cruzadas comprobadas.'
