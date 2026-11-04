-- Creates the two database roles NIGHTFALL uses. Run once per cluster as a superuser.
-- Dev passwords only; production sets real ones via the compose env / secret store.
--   nightfall_owner : owns the schema, runs migrations, used by the admin CLI.
--   nightfall_app   : used by the API. Not superuser, no BYPASSRLS, limited grants.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nightfall_owner') THEN
    CREATE ROLE nightfall_owner LOGIN PASSWORD 'owner_dev_only';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nightfall_app') THEN
    CREATE ROLE nightfall_app LOGIN PASSWORD 'app_dev_only' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;
