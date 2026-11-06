"""BLACK OPS (Addendum 4): playbook runs.

A playbook is a reviewed, versioned definition in code (nightfall.blackops.catalog). A run
records which definition was used (id, version and SHA-256 of the definition) and expands
into ordinary operations, one per step. Those operations go through the same scope checks,
approvals, worker re-checks and BLACK ICE ingest as any other; nothing here is a second
execution path.

  * playbook_runs: immutable for every role (no UPDATE or DELETE grants). Its profile must
    match its scope: 'lab' only with a lab scope, 'live' only with a normal one.
  * operations.playbook_run_id / playbook_step: an operation can join a run only at insert,
    with the run's project, scope, target and lab flag (trigger), so a run can't gather
    operations it didn't define.
  * playbook_settings: per-workspace enable/disable switch, with who changed it last.

Revision ID: 0012
"""

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TABLE playbook_runs (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id          uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  project_id            uuid NOT NULL,
  scope_id              uuid NOT NULL,
  playbook_id           text NOT NULL CHECK (playbook_id ~ '^[a-z0-9-]{1,64}$'),
  playbook_version      text NOT NULL CHECK (length(playbook_version) BETWEEN 1 AND 32),
  definition_sha256     text NOT NULL CHECK (definition_sha256 ~ '^[0-9a-f]{64}$'),
  profile               text NOT NULL CHECK (profile IN ('live', 'lab')),
  target_value          text NOT NULL CHECK (length(target_value) BETWEEN 1 AND 300),
  requested_by_user_id  uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, workspace_id),
  FOREIGN KEY (project_id, workspace_id) REFERENCES projects (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (scope_id, workspace_id) REFERENCES scopes (id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX playbook_runs_workspace_idx ON playbook_runs (workspace_id, created_at DESC);

CREATE FUNCTION nf_playbook_run_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE lab boolean; scope_project uuid;
BEGIN
  SELECT is_lab, project_id INTO lab, scope_project FROM scopes WHERE id = NEW.scope_id;
  IF scope_project IS DISTINCT FROM NEW.project_id THEN
    RAISE EXCEPTION 'playbook run scope belongs to another project' USING ERRCODE = 'check_violation';
  END IF;
  IF lab IS DISTINCT FROM (NEW.profile = 'lab') THEN
    RAISE EXCEPTION 'playbook run profile does not match its scope' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER playbook_runs_guard BEFORE INSERT ON playbook_runs
  FOR EACH ROW EXECUTE FUNCTION nf_playbook_run_guard();

ALTER TABLE operations ADD COLUMN playbook_run_id uuid;
ALTER TABLE operations ADD COLUMN playbook_step smallint;
ALTER TABLE operations ADD FOREIGN KEY (playbook_run_id, workspace_id)
  REFERENCES playbook_runs (id, workspace_id) ON DELETE RESTRICT;
ALTER TABLE operations ADD CONSTRAINT operations_playbook_step
  CHECK ((playbook_run_id IS NULL) = (playbook_step IS NULL) AND (playbook_step IS NULL OR playbook_step BETWEEN 1 AND 20));
CREATE INDEX operations_playbook_run_idx ON operations (playbook_run_id) WHERE playbook_run_id IS NOT NULL;

CREATE FUNCTION nf_operation_playbook_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE run playbook_runs%ROWTYPE;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.playbook_run_id IS DISTINCT FROM OLD.playbook_run_id
       OR NEW.playbook_step IS DISTINCT FROM OLD.playbook_step THEN
      RAISE EXCEPTION 'an operation''s playbook run cannot change' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.playbook_run_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT * INTO run FROM playbook_runs WHERE id = NEW.playbook_run_id;
  IF NOT FOUND
     OR run.project_id <> NEW.project_id OR run.scope_id <> NEW.scope_id
     OR run.target_value <> NEW.target_value OR (run.profile = 'lab') <> NEW.is_lab
     OR run.requested_by_user_id IS DISTINCT FROM NEW.requested_by_user_id THEN
    RAISE EXCEPTION 'operation does not match its playbook run' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER operations_playbook_guard BEFORE INSERT OR UPDATE ON operations
  FOR EACH ROW EXECUTE FUNCTION nf_operation_playbook_guard();

CREATE TABLE playbook_settings (
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  playbook_id         text NOT NULL CHECK (playbook_id ~ '^[a-z0-9-]{1,64}$'),
  enabled             boolean NOT NULL,
  updated_by_user_id  uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  updated_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, playbook_id)
);

ALTER TABLE playbook_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY playbook_runs_tenant ON playbook_runs
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
ALTER TABLE playbook_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY playbook_settings_tenant ON playbook_settings
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());

-- Runs are a record: insert-only. The workers never need them.
GRANT SELECT, INSERT ON playbook_runs TO nightfall_app;
GRANT SELECT, INSERT, UPDATE ON playbook_settings TO nightfall_app;
"""

DOWNGRADE = r"""
DROP TABLE IF EXISTS playbook_settings;
DROP TRIGGER IF EXISTS operations_playbook_guard ON operations;
DROP FUNCTION IF EXISTS nf_operation_playbook_guard();
DROP INDEX IF EXISTS operations_playbook_run_idx;
ALTER TABLE operations DROP CONSTRAINT IF EXISTS operations_playbook_step;
ALTER TABLE operations DROP COLUMN IF EXISTS playbook_step;
ALTER TABLE operations DROP COLUMN IF EXISTS playbook_run_id;
DROP TABLE IF EXISTS playbook_runs;
DROP FUNCTION IF EXISTS nf_playbook_run_guard();
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
