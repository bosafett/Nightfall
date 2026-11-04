#!/bin/sh
# Creates the NIGHTFALL roles and the given databases on an existing Postgres cluster.
# Usage: PSQL="psql -h 127.0.0.1 -U postgres" infra/postgres/setup-databases.sh nightfall nightfall_test
# (or as the postgres OS user: PSQL="psql" sudo -u postgres -E infra/postgres/setup-databases.sh ...)
set -eu
PSQL=${PSQL:-psql}
DIR=$(dirname "$0")
$PSQL -v ON_ERROR_STOP=1 -q -f "$DIR/init.sql"
for db in "$@"; do
  $PSQL -v ON_ERROR_STOP=1 -q -c "DROP DATABASE IF EXISTS $db" -c "CREATE DATABASE $db OWNER nightfall_owner"
  $PSQL -v ON_ERROR_STOP=1 -q -d "$db" -c "REVOKE ALL ON SCHEMA public FROM PUBLIC; ALTER SCHEMA public OWNER TO nightfall_owner;"
done
