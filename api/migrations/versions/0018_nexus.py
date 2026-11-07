"""NEXUS v1: workflow runs (docs/designs/2026-11-nexus.md).

  * workflow_runs: one run of a reviewed, versioned workflow definition (in code) on a
    project. Only its state and cancellation columns can change, and only from running to
    a final state.
  * workflow_steps: one row per step of a run. Only state and progress columns can change,
    and the state only along the allowed transitions (trigger nf_workflow_step_guard).
  * workflow_step_events: one insert-only row per step state change, written by trigger
    whatever role made the change. CHRONICLE reads it.

NEXUS has no database role of its own: the app role changes these tables on behalf of a
signed-in person; the worker may only read them.

Revision ID: 0018
"""

from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TYPE workflow_run_state AS ENUM ('running', 'succeeded', 'failed', 'cancelled', 'timed_out');
CREATE TYPE workflow_step_state AS ENUM
  ('pending', 'ready', 'blocked', 'running', 'succeeded', 'failed', 'skipped', 'cancelled', 'timed_out');

CREATE TABLE workflow_runs (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id         uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  project_id           uuid NOT NULL,
  definition_id        text NOT NULL CHECK (length(definition_id) BETWEEN 1 AND 100),
  definition_version   text NOT NULL CHECK (length(definition_version) BETWEEN 1 AND 32),
  definition_sha256    text NOT NULL CHECK (definition_sha256 ~ '^[0-9a-f]{64}$'),
  inputs               jsonb NOT NULL DEFAULT '{}'::jsonb,
  state                workflow_run_state NOT NULL DEFAULT 'running',
  started_by_user_id   uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  started_at           timestamptz NOT NULL DEFAULT now(),
  deadline             timestamptz NOT NULL,
  finished_at          timestamptz,
  cancelled_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
  cancel_reason        text NOT NULL DEFAULT '' CHECK (length(cancel_reason) <= 1000),
  FOREIGN KEY (project_id, workspace_id) REFERENCES projects (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (id, workspace_id)
);
CREATE INDEX workflow_runs_project_idx ON workflow_runs (project_id, started_at DESC);
ALTER TABLE workflow_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY workflow_runs_tenant ON workflow_runs
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON workflow_runs TO nightfall_app;
GRANT UPDATE (state, finished_at, cancelled_by_user_id, cancel_reason) ON workflow_runs TO nightfall_app;
GRANT SELECT ON workflow_runs TO nightfall_worker;

CREATE FUNCTION nf_workflow_run_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.state <> 'running' THEN
    RAISE EXCEPTION 'a finished workflow run cannot change' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER workflow_runs_guard BEFORE UPDATE ON workflow_runs
  FOR EACH ROW EXECUTE FUNCTION nf_workflow_run_guard();

CREATE TABLE workflow_steps (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  run_id              uuid NOT NULL,
  key                 text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]{0,39}$'),
  kind                text NOT NULL CHECK (kind IN ('playbook', 'rerun', 'review', 'checkpoint', 'wait')),
  position            integer NOT NULL CHECK (position >= 1),
  depends_on          text[] NOT NULL DEFAULT '{}',
  state               workflow_step_state NOT NULL DEFAULT 'pending',
  attempt             integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 3),
  started_by_user_id  uuid REFERENCES users(id) ON DELETE RESTRICT,
  started_at          timestamptz,
  deadline            timestamptz,
  finished_at         timestamptz,
  detail              text NOT NULL DEFAULT '' CHECK (length(detail) <= 2000),
  outputs             jsonb NOT NULL DEFAULT '{}'::jsonb,
  FOREIGN KEY (run_id, workspace_id) REFERENCES workflow_runs (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (run_id, key),
  UNIQUE (id, workspace_id)
);
ALTER TABLE workflow_steps ENABLE ROW LEVEL SECURITY;
CREATE POLICY workflow_steps_tenant ON workflow_steps
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON workflow_steps TO nightfall_app;
GRANT UPDATE (state, attempt, started_by_user_id, started_at, deadline, finished_at, detail, outputs)
  ON workflow_steps TO nightfall_app;
GRANT SELECT ON workflow_steps TO nightfall_worker;

-- Allowed step transitions (design §3). Anything else is refused, whoever asks.
CREATE FUNCTION nf_workflow_step_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'pending' THEN
      RAISE EXCEPTION 'a workflow step starts as pending' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'pending' AND NEW.state IN ('ready', 'skipped', 'cancelled'))
    OR (OLD.state = 'ready'   AND NEW.state IN ('running', 'blocked', 'cancelled'))
    OR (OLD.state = 'blocked' AND NEW.state IN ('running', 'blocked', 'cancelled'))
    OR (OLD.state = 'running' AND NEW.state IN ('succeeded', 'failed', 'timed_out', 'cancelled'))
    OR (OLD.state IN ('failed', 'timed_out') AND NEW.state IN ('ready', 'cancelled'))
  ) THEN
    RAISE EXCEPTION 'workflow step cannot go from % to %', OLD.state, NEW.state
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.state IN ('succeeded', 'skipped', 'cancelled') THEN
    RAISE EXCEPTION 'a finished workflow step cannot change' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER workflow_steps_guard BEFORE INSERT OR UPDATE ON workflow_steps
  FOR EACH ROW EXECUTE FUNCTION nf_workflow_step_guard();

CREATE TABLE workflow_step_events (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id   uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  run_id         uuid NOT NULL,
  step_id        uuid NOT NULL,
  step_key       text NOT NULL,
  from_state     workflow_step_state,
  to_state       workflow_step_state NOT NULL,
  actor_user_id  uuid REFERENCES users(id) ON DELETE RESTRICT,
  detail         text NOT NULL DEFAULT '',
  occurred_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (step_id, workspace_id) REFERENCES workflow_steps (id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX workflow_step_events_run_idx ON workflow_step_events (run_id, occurred_at);
ALTER TABLE workflow_step_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY workflow_step_events_tenant ON workflow_step_events
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT ON workflow_step_events TO nightfall_app, nightfall_worker;

-- Written by the database, so no code path can skip it; runs as the owner because no
-- other role may insert into workflow_step_events.
CREATE FUNCTION nf_workflow_step_event() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  actor uuid := nullif(current_setting('app.user_id', true), '')::uuid;
BEGIN
  IF TG_OP = 'INSERT' OR NEW.state IS DISTINCT FROM OLD.state THEN
    INSERT INTO workflow_step_events
      (workspace_id, run_id, step_id, step_key, from_state, to_state, actor_user_id, detail)
    VALUES (NEW.workspace_id, NEW.run_id, NEW.id, NEW.key,
            CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD.state END, NEW.state, actor,
            left(NEW.detail, 2000));
  END IF;
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION nf_workflow_step_event() FROM PUBLIC;
CREATE TRIGGER workflow_steps_events AFTER INSERT OR UPDATE ON workflow_steps
  FOR EACH ROW EXECUTE FUNCTION nf_workflow_step_event();
"""

DOWNGRADE = r"""
DROP TRIGGER workflow_steps_events ON workflow_steps;
DROP FUNCTION nf_workflow_step_event();
DROP TABLE workflow_step_events;
DROP TRIGGER workflow_steps_guard ON workflow_steps;
DROP FUNCTION nf_workflow_step_guard();
DROP TABLE workflow_steps;
DROP TRIGGER workflow_runs_guard ON workflow_runs;
DROP FUNCTION nf_workflow_run_guard();
DROP TABLE workflow_runs;
DROP TYPE workflow_step_state;
DROP TYPE workflow_run_state;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
