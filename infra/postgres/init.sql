-- Creates the two database roles NIGHTFALL uses. Run once per cluster as a superuser.
-- Dev passwords only; production sets real ones via the compose env / secret store.
--   nightfall_owner : owns the schema, runs migrations, used by the admin CLI.
--   nightfall_app    : used by the API. Not superuser, no BYPASSRLS, limited grants.
--   nightfall_worker : used by the background worker. Claims operations across workspaces;
--                      everything else is still limited by RLS. No access to users/sessions.
--   nightfall_blacksite  : the host-only BLACKSITE listener on the lab machine. Lab work only.
--   nightfall_lab_worker : the isolated lab machine's worker (Phase 6b). Lab operations only.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nightfall_owner') THEN
    CREATE ROLE nightfall_owner LOGIN PASSWORD 'owner_dev_only';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nightfall_app') THEN
    CREATE ROLE nightfall_app LOGIN PASSWORD 'app_dev_only' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nightfall_worker') THEN
    CREATE ROLE nightfall_worker LOGIN PASSWORD 'worker_dev_only' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nightfall_blacksite') THEN
    CREATE ROLE nightfall_blacksite LOGIN PASSWORD 'blacksite_dev_only' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nightfall_lab_worker') THEN
    CREATE ROLE nightfall_lab_worker LOGIN PASSWORD 'lab_worker_dev_only' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;
