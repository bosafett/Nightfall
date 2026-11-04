#!/bin/sh
# Docker entrypoint hook: create roles and the nightfall database.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -f /docker-entrypoint-initdb.d/init.sql.in
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -c "CREATE DATABASE nightfall OWNER nightfall_owner"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d nightfall -c "REVOKE ALL ON SCHEMA public FROM PUBLIC; GRANT ALL ON SCHEMA public TO nightfall_owner; ALTER SCHEMA public OWNER TO nightfall_owner;"
