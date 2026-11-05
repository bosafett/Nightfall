#!/bin/bash
# Start-up for the single-container Render deployment.
#  1. Builds the three database URLs from Render's database fields: the default database
#     user owns the schema; the API and the worker get their own restricted roles.
#  2. Creates/updates those roles, runs migrations, creates the first owner once.
#  3. Drops the owner credentials from the environment, then starts the API on loopback
#     and the web server on $PORT. If either exits, the container exits.
set -euo pipefail

: "${DB_HOST:?}" "${DB_NAME:?}" "${DB_USER:?}" "${DB_PASSWORD:?}"
: "${NIGHTFALL_APP_DB_PASSWORD:?}" "${NIGHTFALL_WORKER_DB_PASSWORD:?}"

enc() { python -I -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
base="${DB_HOST}:${DB_PORT:-5432}/${DB_NAME}"
export NIGHTFALL_MIGRATION_DATABASE_URL="postgresql://$(enc "$DB_USER"):$(enc "$DB_PASSWORD")@${base}"
export NIGHTFALL_DATABASE_URL="postgresql://nightfall_app:$(enc "$NIGHTFALL_APP_DB_PASSWORD")@${base}"
export NIGHTFALL_WORKER_DATABASE_URL="postgresql://nightfall_worker:$(enc "$NIGHTFALL_WORKER_DB_PASSWORD")@${base}"
export NIGHTFALL_PUBLIC_ORIGIN="${NIGHTFALL_PUBLIC_ORIGIN:-${RENDER_EXTERNAL_URL:?}}"

cd /app/api
nightfall-admin bootstrap-roles
alembic upgrade head
nightfall-admin bootstrap-owner

# The running services never hold the schema-owner credentials or the owner's password.
unset NIGHTFALL_MIGRATION_DATABASE_URL DB_USER DB_PASSWORD NIGHTFALL_ADMIN_PASSWORD \
  NIGHTFALL_APP_DB_PASSWORD NIGHTFALL_WORKER_DB_PASSWORD

uvicorn nightfall.asgi:app --host 127.0.0.1 --port 8000 --no-server-header &
cd /app/web
HOSTNAME=0.0.0.0 PORT="${PORT:-10000}" node server.js &
wait -n
echo "start.sh: a process exited; stopping the container" >&2
exit 1
