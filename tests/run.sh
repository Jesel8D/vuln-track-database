#!/usr/bin/env bash
# Crea únicamente un proyecto nuevo y aislado; nunca borra volúmenes.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
project="${VULNTRACK_TEST_PROJECT:-vulntrack-v1-test-$(date +%s)-$$}"
if [[ ! "$project" =~ ^vulntrack-v1-test-[a-z0-9-]+$ ]]; then
  printf 'Nombre de proyecto de prueba no válido.\n' >&2
  exit 1
fi
if [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$project")" ||
      -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$project")" ]]; then
  printf 'El proyecto ya existe; no se tocará: %s\n' "$project" >&2
  exit 1
fi
export POSTGRES_PORT=0
# No reutilizar por accidente credenciales de otro proyecto desde el shell.
compose=(env -u POSTGRES_PASSWORD -u POSTGRES_USER -u POSTGRES_DB
  docker compose --env-file .env.example -p "$project")
db() {
  "${compose[@]}" exec -T postgres sh -c \
    'exec psql -X -q -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 "$@"' sh "$@"
}
stop_test_project() {
  "${compose[@]}" stop --timeout 10 postgres >/dev/null
  printf 'Proyecto de prueba detenido; contenedor y volumen conservados: %s\n' "$project"
}
trap stop_test_project EXIT
printf 'Proyecto aislado: %s\n' "$project"
"${compose[@]}" config --quiet
"${compose[@]}" up -d --wait --wait-timeout 90 postgres
[[ "$("${compose[@]}" port postgres 5432)" == 127.0.0.1:* ]]
printf 'ok - puerto publicado únicamente en localhost\n'
db -Atc 'SELECT version();'
"${compose[@]}" exec -T postgres sh -c \
  'PGPASSWORD="$POSTGRES_PASSWORD" psql -X -q -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -c "SELECT 1"' >/dev/null
if wrong_password_output=$("${compose[@]}" exec -T postgres sh -c \
  'PGPASSWORD=incorrect-test-only psql -X -q -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT 1"' 2>&1); then
  printf 'Una contraseña incorrecta fue aceptada.\n' >&2
  exit 1
fi
[[ "$wrong_password_output" == *'password authentication failed'* ]]
printf 'ok - conexión TCP autenticada y rechazo de contraseña incorrecta\n'
if baseline_output=$(db -v VERBOSITY=verbose -f /vulntrack/sql/001_schema.sql 2>&1); then
  printf 'El baseline no debe reaplicarse sobre un esquema existente.\n' >&2
  exit 1
fi
[[ "$baseline_output" == *'42P06'* ]]
printf 'ok - reaplicación del baseline rechazada sin sobrescribir datos\n'
db -f /vulntrack/seed/001_demo.sql
db -f /vulntrack/seed/001_demo.sql
db -f /vulntrack/tests/001_integrity.sql
db -f /vulntrack/sql/003_queries.sql

# Dos conexiones intentan confirmar el mismo intento lógico. La unicidad del
# registro técnico revierte el segundo activo si ambas escrituras son atómicas.
first_sql="SET application_name = 'vulntrack-idempotency-first';
BEGIN;
SET LOCAL ROLE vulntrack_app;
INSERT INTO vulntrack.assets(id,device_type,manufacturer,model,version,site_label)
VALUES ('90000000-0000-4000-8000-000000000001','router','Test','Test','1','LAB');
INSERT INTO vulntrack.asset_registration_requests(user_id,idempotency_key,request_hash,asset_id,response_body)
VALUES ('00000000-0000-4000-8000-000000000001','90000000-0000-4000-8000-000000000010',repeat('b',64),
'90000000-0000-4000-8000-000000000001','{\"id\":\"90000000-0000-4000-8000-000000000001\"}');
SELECT pg_sleep(2);
COMMIT;"
db -c "$first_sql" >/dev/null &
first_pid=$!
sleeping=0
for ((attempt=0; attempt<20; attempt++)); do
  if [[ "$(db -Atc "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'vulntrack-idempotency-first' AND wait_event = 'PgSleep';")" == 1 ]]; then
    sleeping=1
    break
  fi
  sleep 0.1
done
if [[ "$sleeping" != 1 ]]; then
  wait "$first_pid"
  printf 'No se pudo sincronizar la prueba concurrente.\n' >&2
  exit 1
fi
second_sql="BEGIN;
SET LOCAL ROLE vulntrack_app;
INSERT INTO vulntrack.assets(id,device_type,manufacturer,model,version,site_label)
VALUES ('90000000-0000-4000-8000-000000000002','router','Test','Test','1','LAB');
INSERT INTO vulntrack.asset_registration_requests(user_id,idempotency_key,request_hash,asset_id,response_body)
VALUES ('00000000-0000-4000-8000-000000000001','90000000-0000-4000-8000-000000000010',repeat('b',64),
'90000000-0000-4000-8000-000000000002','{\"id\":\"90000000-0000-4000-8000-000000000002\"}');
COMMIT;"
if second_output=$(db -v VERBOSITY=verbose -c "$second_sql" 2>&1); then
  printf 'La segunda transacción debió fallar.\n' >&2
  exit 1
fi
wait "$first_pid"
if [[ "$second_output" != *'23505'* ]]; then
  printf '%s\n' "$second_output" >&2
  exit 1
fi
if [[ "$(db -Atc "SELECT count(*) FROM vulntrack.assets WHERE id IN ('90000000-0000-4000-8000-000000000001','90000000-0000-4000-8000-000000000002');")" != 1 ]]; then
  printf 'Rollback concurrente falló.\n' >&2
  exit 1
fi
if [[ "$(db -Atc "SELECT response_body->>'id' FROM vulntrack.asset_registration_requests WHERE idempotency_key = '90000000-0000-4000-8000-000000000010';")" != '90000000-0000-4000-8000-000000000001' ]]; then
  printf 'No se conservó el snapshot de la primera transacción.\n' >&2
  exit 1
fi
printf 'ok - concurrencia: un activo confirmado y segundo revertido; snapshot recuperable\n'

snapshot_sql="SELECT (SELECT count(*) FROM vulntrack.assets), (SELECT count(*) FROM vulntrack.analysis_runs), (SELECT count(*) FROM vulntrack.findings), (SELECT count(*) FROM vulntrack.asset_registration_requests);"
before=$(db -Atc "$snapshot_sql")
"${compose[@]}" restart postgres
"${compose[@]}" up -d --wait --wait-timeout 90 postgres
[[ "$(db -Atc "$snapshot_sql")" == "$before" ]]
printf 'ok - datos conservados tras reinicio\n'
"${compose[@]}" up -d --force-recreate --wait --wait-timeout 90 postgres
[[ "$(db -Atc "$snapshot_sql")" == "$before" ]]
printf 'ok - datos conservados tras recrear contenedor con el mismo volumen\n'
printf 'PRUEBAS V1 CORRECTAS. No se ha probado una API ni idempotencia extremo a extremo.\n'
