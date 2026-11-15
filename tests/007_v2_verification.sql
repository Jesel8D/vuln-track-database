\set ON_ERROR_STOP on
BEGIN;
CREATE FUNCTION pg_temp.assert_verification(ok boolean,label text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN IF ok IS DISTINCT FROM true THEN RAISE EXCEPTION 'verification check failed: %',label;
END IF; RAISE NOTICE 'ok - %',label; END $$;
SELECT pg_temp.assert_verification((SELECT count(*)=2 FROM pg_class c JOIN pg_namespace n
    ON n.oid=c.relnamespace WHERE n.nspname='vulntrack_verification' AND c.relkind='r'),'two minimal tables');
SELECT pg_temp.assert_verification((SELECT bool_and(relrowsecurity AND relforcerowsecurity)
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='vulntrack_verification' AND c.relkind='r'),'RLS forced');
SELECT pg_temp.assert_verification((SELECT count(*)=6 FROM pg_policies
    WHERE schemaname='vulntrack_verification'),'scoped read/insert/update policies');
SELECT pg_temp.assert_verification((SELECT bool_and(NOT rolsuper AND NOT rolbypassrls
    AND NOT rolcanlogin AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication)
    FROM pg_roles WHERE rolname IN ('vulntrack_verification_owner','vulntrack_verification_lab')),'non-login minimal roles');
SELECT pg_temp.assert_verification(NOT has_schema_privilege('vulntrack_registration','vulntrack_verification','USAGE'),'registration isolated');
SELECT pg_temp.assert_verification(NOT pg_has_role('vulntrack_app','vulntrack_verification_owner','MEMBER'),'API not definer owner');
SELECT pg_temp.assert_verification(NOT pg_has_role('vulntrack_app','vulntrack_verification_lab','MEMBER'),'API not lab worker');
SELECT pg_temp.assert_verification(NOT pg_has_role('vulntrack_registration','vulntrack_verification_lab','MEMBER'),'registration not lab worker');
SELECT pg_temp.assert_verification(NOT has_column_privilege('vulntrack_app','vulntrack_verification.challenges','proof_sha256','SELECT'),'API cannot read token digest');
SELECT pg_temp.assert_verification(has_column_privilege('vulntrack_app','vulntrack_verification.challenges','state','SELECT'),'API can read scoped metadata');
SELECT pg_temp.assert_verification(NOT has_table_privilege('vulntrack_app','vulntrack_verification.challenges','INSERT'),'no raw API insert');
SELECT pg_temp.assert_verification(NOT has_table_privilege('vulntrack_app','vulntrack_verification.challenges','UPDATE'),'no raw API update');
SELECT pg_temp.assert_verification(NOT has_table_privilege('vulntrack_app','vulntrack_verification.challenges','DELETE'),'no API delete');
SELECT pg_temp.assert_verification(NOT has_table_privilege('vulntrack_verification_lab','vulntrack_verification.attempts','UPDATE'),'no raw lab mutation');
SELECT pg_temp.assert_verification(NOT has_function_privilege('vulntrack_app',
    'vulntrack_verification.claim_laboratory(uuid,uuid,uuid,uuid,uuid)','EXECUTE'),'API cannot consume lab proof');
SELECT pg_temp.assert_verification(NOT has_function_privilege('vulntrack_verification_lab',
    'vulntrack_verification.issue(uuid,uuid,uuid,uuid,uuid,timestamptz,text,text)','EXECUTE'),'lab cannot issue challenges');
SELECT pg_temp.assert_verification(NOT EXISTS(SELECT 1 FROM pg_proc p,
    aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl
    WHERE p.oid='vulntrack_verification.issue(uuid,uuid,uuid,uuid,uuid,timestamptz,text,text)'::regprocedure
    AND acl.grantee=0 AND acl.privilege_type='EXECUTE'),'public cannot issue');
SELECT pg_temp.assert_verification((SELECT bool_and(pg_get_userbyid(proowner)='vulntrack_verification_owner'
    AND proconfig=ARRAY['search_path=pg_catalog']) FROM pg_proc p JOIN pg_namespace n
    ON n.oid=p.pronamespace WHERE n.nspname='vulntrack_verification' AND prosecdef),'definer owner and fixed path');
SELECT pg_temp.assert_verification((SELECT count(*)=2 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='vulntrack_verification'
    AND NOT t.tgisinternal AND t.tgenabled='O'),'immutable identity/evidence guards');
SELECT pg_temp.assert_verification((SELECT indexdef LIKE '%WHERE (state = ''pending''::text)%'
    FROM pg_indexes WHERE schemaname='vulntrack_verification' AND indexname='challenge_one_pending_target'),'one pending challenge per target');
SELECT pg_temp.assert_verification((SELECT count(*)=2 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
    JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='vulntrack_verification'
    AND c.contype='f' AND c.conname IN ('challenge_target_fk','attempt_challenge_fk')),'composite scope FKs');
SELECT pg_temp.assert_verification(NOT EXISTS(SELECT 1 FROM information_schema.columns
    WHERE table_schema='vulntrack_verification' AND column_name IN ('token','body','password','http_body')),'no plaintext token/body/credentials');
SELECT pg_temp.assert_verification((SELECT count(*)=29 FROM pg_policies WHERE schemaname='vulntrack'),'legacy RLS unchanged');
SELECT pg_temp.assert_verification((SELECT version_num='0004_mvp_cve' FROM public.alembic_version),'legacy Alembic unchanged');
ROLLBACK;
