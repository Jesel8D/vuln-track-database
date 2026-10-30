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

SELECT pg_temp.assert_true((SELECT count(*) = 5 FROM information_schema.tables
    WHERE table_schema = 'vulntrack' AND table_type = 'BASE TABLE'), 'cinco tablas V1');
SELECT pg_temp.assert_true((SELECT count(*) = 5 FROM pg_constraint c
    JOIN pg_namespace n ON n.oid = c.connamespace WHERE n.nspname = 'vulntrack' AND c.contype = 'p'), 'cinco claves primarias');
SELECT pg_temp.assert_true((SELECT count(*) = 5 FROM pg_constraint c
    JOIN pg_namespace n ON n.oid = c.connamespace WHERE n.nspname = 'vulntrack' AND c.contype = 'f'), 'cinco claves foráneas');
SELECT pg_temp.assert_true((SELECT count(*) = 3 FROM vulntrack.assets), 'seed repetible: tres activos');
SELECT pg_temp.assert_true((SELECT count(*) = 2 FROM vulntrack.analysis_runs), 'dos evaluaciones asociadas');
SELECT pg_temp.assert_true((SELECT count(*) = 1 FROM vulntrack.findings), 'un hallazgo potencial');
SELECT pg_temp.assert_true((SELECT inventory_label IS NULL AND notes IS NULL FROM vulntrack.assets
    WHERE id = '10000000-0000-4000-8000-000000000001'), 'opcionales admiten null');
SELECT pg_temp.assert_true((SELECT count(*) = 1 FROM vulntrack.analysis_runs r
    WHERE status = 'completed' AND coverage = 'complete' AND NOT EXISTS
    (SELECT 1 FROM vulntrack.findings f WHERE f.analysis_id = r.id)), 'consulta completa con cero hallazgos');
SELECT pg_temp.assert_true((SELECT count(*) = 1 FROM vulntrack.assets a WHERE NOT EXISTS
    (SELECT 1 FROM vulntrack.analysis_runs r WHERE r.asset_id = a.id)), 'sin evaluación no equivale a cero CVE');
SELECT pg_temp.assert_true((SELECT password_hash IS NULL AND NOT active FROM vulntrack.users LIMIT 1), 'demo no tiene credenciales ni acceso activo');
SELECT pg_temp.assert_true((SELECT cvss IS NULL AND applicability = 'potential' FROM vulntrack.findings LIMIT 1), 'CVSS ausente no se convierte en cero');
SELECT pg_temp.assert_true(current_setting('TimeZone') = 'UTC', 'sesión en UTC');
SELECT pg_temp.assert_true((SELECT NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
    AND NOT rolcreaterole FROM pg_roles WHERE rolname = 'vulntrack_app'), 'grupo app sin login ni privilegios de administración');
SELECT pg_temp.assert_true((SELECT bool_and(auth_method = 'scram-sha-256') FROM pg_hba_file_rules
    WHERE type = 'host'), 'autenticación TCP SCRAM');

SELECT pg_temp.expect_error($q$INSERT INTO vulntrack.assets(id,device_type,manufacturer,model,version,site_label)
    SELECT id,device_type,manufacturer,model,version,site_label FROM vulntrack.assets LIMIT 1$q$, '23505', 'PK duplicada');
SELECT pg_temp.expect_error($q$INSERT INTO vulntrack.users(id,username) VALUES
    ('00000000-0000-4000-8000-000000000002','demo_operator')$q$, '23505', 'username único');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.users SET password_hash = 'plaintext'$q$, '23514', 'rechazar contraseña en texto plano');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.assets SET manufacturer = NULL$q$, '23502', 'campo obligatorio');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.assets SET model = ''$q$, '23514', 'vacío inválido');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.assets SET version = ' 1.2'$q$, '23514', 'espacios en extremos');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.assets SET notes = repeat('x',1001)$q$, '23514', 'notas demasiado largas');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.assets SET inventory_label = ''$q$, '23514', 'opcional vacío no es null');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.assets SET id = 'no-uuid'$q$, '22P02', 'identificador UUID');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.assets SET created_at = created_at + interval '1 day'$q$, '23514', 'fecha de creación inmutable');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.analysis_runs SET asset_id = 'ffffffff-ffff-4fff-8fff-ffffffffffff'$q$, '23503', 'activo inexistente');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.analysis_runs SET initiated_by = 'ffffffff-ffff-4fff-8fff-ffffffffffff'$q$, '23503', 'usuario inexistente');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.findings SET analysis_id = 'ffffffff-ffff-4fff-8fff-ffffffffffff'$q$, '23503', 'evaluación inexistente');
SELECT pg_temp.expect_error($q$DELETE FROM vulntrack.users$q$, '23503', 'usuario con historial protegido');
SELECT pg_temp.expect_error($q$DELETE FROM vulntrack.assets WHERE id = '10000000-0000-4000-8000-000000000001'$q$, '23503', 'activo con historial protegido');
SELECT pg_temp.expect_error($q$DELETE FROM vulntrack.analysis_runs WHERE id = '20000000-0000-4000-8000-000000000001'$q$, '23503', 'evaluación con hallazgos protegida');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.analysis_runs SET kind = 'zap_baseline'$q$, '23514', 'ZAP rechazado en V1');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.analysis_runs SET selected_cpe = 'producto'$q$, '23514', 'prefijo CPE requerido');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.analysis_runs SET status = 'unknown'$q$, '23514', 'estado inválido');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.analysis_runs SET completed_at = started_at - interval '1 minute'$q$, '23514', 'orden temporal');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.analysis_runs SET coverage = NULL$q$, '23514', 'completado exige cobertura explícita');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.findings SET external_id = 'CVE-invalido'$q$, '23514', 'CVE inválido');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.findings SET source = 'ZAP'$q$, '23514', 'fuente V1 solo NVD');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.findings SET applicability = 'confirmed'$q$, '23514', 'sin confirmación automática');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.findings SET cvss = '[]'::jsonb$q$, '23514', 'CVSS debe ser objeto');

INSERT INTO vulntrack.assets (id,device_type,manufacturer,model,version,site_label,inventory_label)
SELECT '10000000-0000-4000-8000-000000000004',device_type,manufacturer,model,version,site_label,inventory_label
FROM vulntrack.assets WHERE id = '10000000-0000-4000-8000-000000000002';
SELECT pg_temp.assert_true((SELECT count(*) = 2 FROM vulntrack.assets WHERE inventory_label = 'INV-DEMO-2'), 'inventario no impone unicidad no aprobada');
UPDATE vulntrack.assets SET notes = 'Observación sintética' WHERE id = '10000000-0000-4000-8000-000000000004';
SELECT pg_temp.assert_true((SELECT updated_at > created_at AND notes = 'Observación sintética'
    FROM vulntrack.assets WHERE id = '10000000-0000-4000-8000-000000000004'), 'actualización temporal por trigger');

INSERT INTO vulntrack.asset_registration_requests
    (user_id,idempotency_key,request_hash,asset_id,response_body)
VALUES ('00000000-0000-4000-8000-000000000001','40000000-0000-4000-8000-000000000001',
    repeat('a',64),'10000000-0000-4000-8000-000000000004','{"id":"10000000-0000-4000-8000-000000000004"}');
SELECT pg_temp.expect_error($q$INSERT INTO vulntrack.asset_registration_requests SELECT * FROM vulntrack.asset_registration_requests$q$, '23505', 'clave idempotente única');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.asset_registration_requests SET request_hash = 'x'$q$, '23514', 'huella inválida');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.asset_registration_requests SET expires_at = created_at$q$, '23514', 'expiración posterior');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.asset_registration_requests SET response_body = '{"id":null}'$q$, '23514', 'snapshot sin id no admitido');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.asset_registration_requests SET asset_id = 'ffffffff-ffff-4fff-8fff-ffffffffffff', response_body = '{"id":"ffffffff-ffff-4fff-8fff-ffffffffffff"}'$q$, '23503', 'FK de idempotencia');

SET LOCAL ROLE vulntrack_app;
SELECT pg_temp.assert_true((SELECT count(*) = 4 FROM vulntrack.assets), 'rol app lee activos');
INSERT INTO vulntrack.assets (id,device_type,manufacturer,model,version,site_label)
VALUES ('10000000-0000-4000-8000-000000000005','router','Demo','Demo','1','LAB');
SELECT pg_temp.assert_true((SELECT count(*) = 5 FROM vulntrack.assets), 'rol app registra activo');
INSERT INTO vulntrack.analysis_runs (id,asset_id,initiated_by,selected_cpe)
VALUES ('20000000-0000-4000-8000-000000000003','10000000-0000-4000-8000-000000000005',
    '00000000-0000-4000-8000-000000000001','cpe:2.3:a:demo:producto:1:*:*:*:*:*:*:*');
UPDATE vulntrack.analysis_runs SET status = 'running', started_at = clock_timestamp()
WHERE id = '20000000-0000-4000-8000-000000000003';
UPDATE vulntrack.analysis_runs SET status = 'completed', coverage = 'partial', completed_at = clock_timestamp()
WHERE id = '20000000-0000-4000-8000-000000000003';
SELECT pg_temp.assert_true((SELECT status = 'completed' AND coverage = 'partial'
    FROM vulntrack.analysis_runs WHERE id = '20000000-0000-4000-8000-000000000003'), 'rol app conserva cobertura parcial y ciclo temporal');
UPDATE vulntrack.findings SET status = 'reviewed';
SELECT pg_temp.assert_true((SELECT status = 'reviewed' AND applicability = 'potential'
    FROM vulntrack.findings LIMIT 1), 'revisión no confirma vulnerabilidad');
SELECT pg_temp.expect_error($q$SELECT password_hash FROM vulntrack.users$q$, '42501', 'rol app no lee hashes');
SELECT pg_temp.expect_error($q$UPDATE vulntrack.assets SET notes = 'Cambio'$q$, '42501', 'rol app no actualiza activos');
SELECT pg_temp.expect_error($q$DELETE FROM vulntrack.assets$q$, '42501', 'rol app no elimina activos');
SELECT pg_temp.expect_error($q$TRUNCATE vulntrack.assets$q$, '42501', 'rol app no trunca activos');
SELECT pg_temp.expect_error($q$CREATE TABLE vulntrack.forbidden (id integer)$q$, '42501', 'rol app no modifica esquema');
RESET ROLE;
ROLLBACK;
\o
\echo 'Integridad y privilegios: todas las comprobaciones pasaron; datos de prueba revertidos.'
