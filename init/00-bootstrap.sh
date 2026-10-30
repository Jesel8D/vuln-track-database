#!/bin/sh
# Ejecutado exclusivamente por el entrypoint oficial con PGDATA vacío.
set -eu
psql -X --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set ON_ERROR_STOP=1 --file /vulntrack/sql/001_schema.sql
psql -X --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set ON_ERROR_STOP=1 --file /vulntrack/sql/002_privileges.sql
