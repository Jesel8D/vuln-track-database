#!/bin/sh
# Optional new installation only; entrypoint runs scripts only with empty PGDATA.
set -eu
if [ "${VULNTRACK_SCHEMA:-v1}" = "mvp-a" ]; then
    psql -X --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
        --set ON_ERROR_STOP=1 --file /vulntrack/sql/bootstrap_mvp_a.sql
fi
