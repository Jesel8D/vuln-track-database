#!/bin/sh
# Fresh PGDATA only; existing installations use Backend Alembic.
set -eu
if [ "${VULNTRACK_SCHEMA:-v1}" = "mvp-b" ]; then
    psql -X --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
        --set ON_ERROR_STOP=1 --file /vulntrack/sql/bootstrap_mvp_b.sql
fi
