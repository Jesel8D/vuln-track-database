\set ON_ERROR_STOP on
\o /dev/null
BEGIN;
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
CREATE FUNCTION pg_temp.assert_true(condition boolean, label text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF condition IS DISTINCT FROM true THEN RAISE EXCEPTION 'FALLO: %', label; END IF;
    RAISE NOTICE 'ok - %', label;
END $$;
CREATE FUNCTION pg_temp.sign_context(user_id uuid, workspace_id uuid, expiry bigint, nonce uuid)
RETURNS text LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, vulntrack_private AS $$
    SELECT encode(public.hmac(convert_to('v1|' || user_id::text || '|' || workspace_id::text
        || '|' || expiry::text || '|' || nonce::text, 'UTF8'),
        (SELECT hmac_key FROM vulntrack_private.context_keys WHERE singleton), 'sha256'), 'hex')
$$;
CREATE FUNCTION pg_temp.sign_directory(user_id uuid, expiry bigint, nonce uuid)
RETURNS text LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, vulntrack_private AS $$
    SELECT encode(public.hmac(convert_to('v1-directory|' || user_id::text || '|'
        || expiry::text || '|' || nonce::text, 'UTF8'),
        (SELECT hmac_key FROM vulntrack_private.context_keys WHERE singleton), 'sha256'), 'hex')
$$;

INSERT INTO vulntrack.users(id,username,active)
VALUES ('00000000-0000-4000-8000-000000000009','workspace_bootstrap_test',true);
SELECT floor(extract(epoch FROM clock_timestamp()))::bigint + 30 AS expiry,
       '59000000-0000-4000-8000-000000000001'::uuid AS nonce \gset
SELECT pg_temp.sign_context('00000000-0000-4000-8000-000000000009',
    '59000000-0000-4000-8000-000000000002', :expiry, :'nonce') AS signature \gset
SELECT pg_temp.sign_directory('00000000-0000-4000-8000-000000000009',
    :expiry, :'nonce') AS directory_signature \gset

SET LOCAL ROLE vulntrack_app;
SELECT vulntrack.establish_new_workspace_context('00000000-0000-4000-8000-000000000009',
    '59000000-0000-4000-8000-000000000002', :expiry, :'nonce', :'signature');
INSERT INTO vulntrack.workspaces(id,name,created_by)
VALUES ('59000000-0000-4000-8000-000000000002','Workspace bootstrap','00000000-0000-4000-8000-000000000009');
INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role)
VALUES ('59000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000009','owner');
SET CONSTRAINTS vulntrack.workspaces_require_owner, vulntrack.workspace_members_owner_guard IMMEDIATE;
SELECT pg_temp.expect_error(format(
    'SELECT vulntrack.establish_new_workspace_context(%L,%L,%s,%L,%L)',
    '00000000-0000-4000-8000-000000000009','59000000-0000-4000-8000-000000000003',
    :expiry, :'nonce', repeat('0',64)), '28000', 'bootstrap exige firma HMAC válida');
SELECT pg_temp.expect_error($q$SELECT vulntrack.establish_new_workspace_context(
    '00000000-0000-4000-8000-000000000009',
    '59000000-0000-4000-8000-000000000003',NULL,NULL,NULL)$q$,
    '28000', 'bootstrap rechaza parámetros nulos');
SELECT pg_temp.assert_true((SELECT count(*)=1 AND bool_and(workspace_id='59000000-0000-4000-8000-000000000002')
    FROM vulntrack.list_user_workspaces('00000000-0000-4000-8000-000000000009',
        :expiry, :'nonce', :'directory_signature')),
    'directorio firmado devuelve solo los workspaces del usuario');
SELECT pg_temp.expect_error(format(
    'SELECT * FROM vulntrack.list_user_workspaces(%L,%s,%L,%L)',
    '00000000-0000-4000-8000-000000000009', :expiry, :'nonce', repeat('0',64)),
    '28000', 'directorio rechaza firma inválida');
SELECT pg_temp.expect_error($q$SELECT * FROM vulntrack.list_user_workspaces(
    '00000000-0000-4000-8000-000000000009',NULL,NULL,NULL)$q$,
    '28000', 'directorio rechaza parámetros nulos');
SELECT pg_temp.assert_true((SELECT count(*)=1 FROM vulntrack.workspaces
    WHERE id='59000000-0000-4000-8000-000000000002'), 'owner ve su workspace recién creado');
ROLLBACK;
\o
\echo 'Bootstrap V2: workspace y owner creados con contexto firmado; prueba revertida.'
