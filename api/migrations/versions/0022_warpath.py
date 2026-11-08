"""WARPATH v1 (docs/designs/2026-11-warpath.md): purple-team exercises in the lab.

  * warpath_exercises: a plan (ordered lab playbook steps, each tagged with an ATT&CK
    technique) on a project with a lab scope. Editable as a draft; once the owner approves
    it the plan and its SHA-256 are frozen, and only the state moves on
    (approved -> running -> finished, or cancelled).
  * warpath_scores: insert-only detection scores per step (attack result, detection,
    time to detect, note, who). Re-scoring adds a row; the latest counts.
  * alerts.kind gains 'detection.gap' (a missed or partly detected step). The app role may
    insert alerts of that kind only (restrictive policy); every other kind stays worker-only.

Revision ID: 0022
"""

from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TABLE warpath_exercises (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id          uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  project_id            uuid NOT NULL,
  name                  text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  objective             text NOT NULL DEFAULT '' CHECK (length(objective) <= 2000),
  source_path_id        uuid,
  plan                  jsonb NOT NULL,
  plan_sha256           text NOT NULL CHECK (plan_sha256 ~ '^[0-9a-f]{64}$'),
  state                 text NOT NULL DEFAULT 'draft'
                        CHECK (state IN ('draft', 'approved', 'running', 'finished', 'cancelled')),
  created_by_user_id    uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at            timestamptz NOT NULL DEFAULT now(),
  approved_by_user_id   uuid REFERENCES users(id) ON DELETE RESTRICT,
  approved_at           timestamptz,
  workflow_run_id       uuid,
  CHECK ((state = 'draft') = (approved_at IS NULL)),
  CHECK (jsonb_typeof(plan) = 'array' AND jsonb_array_length(plan) BETWEEN 1 AND 20),
  FOREIGN KEY (project_id, workspace_id) REFERENCES projects (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (workflow_run_id, workspace_id) REFERENCES workflow_runs (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (id, workspace_id)
);
ALTER TABLE warpath_exercises ENABLE ROW LEVEL SECURITY;
CREATE POLICY warpath_exercises_tenant ON warpath_exercises
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT, DELETE ON warpath_exercises TO nightfall_app;
GRANT UPDATE (name, objective, plan, plan_sha256, state, approved_by_user_id, approved_at, workflow_run_id)
  ON warpath_exercises TO nightfall_app;

-- Drafts change freely; an approved plan is frozen; the state only moves forward.
CREATE FUNCTION nf_warpath_exercise_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.state <> 'draft' THEN
      RAISE EXCEPTION 'only a draft exercise can be deleted' USING ERRCODE = 'check_violation';
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.state IN ('finished', 'cancelled') THEN
    RAISE EXCEPTION 'a finished exercise cannot change' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.state <> 'draft' AND (NEW.plan IS DISTINCT FROM OLD.plan OR NEW.plan_sha256 IS DISTINCT FROM OLD.plan_sha256
       OR NEW.name IS DISTINCT FROM OLD.name OR NEW.objective IS DISTINCT FROM OLD.objective
       OR NEW.approved_by_user_id IS DISTINCT FROM OLD.approved_by_user_id
       OR NEW.approved_at IS DISTINCT FROM OLD.approved_at) THEN
    RAISE EXCEPTION 'an approved exercise plan cannot change' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'draft' AND NEW.state = 'approved')
    OR (OLD.state = 'approved' AND NEW.state IN ('running', 'cancelled'))
    OR (OLD.state = 'running' AND NEW.state IN ('finished', 'cancelled'))) THEN
    RAISE EXCEPTION 'exercise cannot go from % to %', OLD.state, NEW.state USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.workflow_run_id IS DISTINCT FROM OLD.workflow_run_id AND OLD.workflow_run_id IS NOT NULL THEN
    RAISE EXCEPTION 'an exercise''s run cannot change' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER warpath_exercises_guard BEFORE UPDATE OR DELETE ON warpath_exercises
  FOR EACH ROW EXECUTE FUNCTION nf_warpath_exercise_guard();

CREATE TABLE warpath_scores (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id       uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  exercise_id        uuid NOT NULL,
  step               integer NOT NULL CHECK (step BETWEEN 1 AND 20),
  technique_id       text NOT NULL CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
  attack_result      text NOT NULL CHECK (attack_result IN ('succeeded', 'failed', 'blocked')),
  detection          text NOT NULL CHECK (detection IN ('detected', 'partial', 'missed', 'not_applicable')),
  minutes_to_detect  integer CHECK (minutes_to_detect BETWEEN 0 AND 100000),
  note               text NOT NULL DEFAULT '' CHECK (length(note) <= 2000),
  scored_by_user_id  uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  scored_at          timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (exercise_id, workspace_id) REFERENCES warpath_exercises (id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX warpath_scores_exercise_idx ON warpath_scores (exercise_id, step, scored_at DESC);
ALTER TABLE warpath_scores ENABLE ROW LEVEL SECURITY;
CREATE POLICY warpath_scores_tenant ON warpath_scores
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON warpath_scores TO nightfall_app;

ALTER TABLE alerts DROP CONSTRAINT alerts_kind_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_kind_check CHECK (kind IN (
  'cert.expiring', 'cert.changed', 'tls.weakened', 'headers.regressed', 'ct.new_names',
  'dns.changed', 'finding.reopened', 'monitor.failed', 'monitor.expiring', 'monitor.ended',
  'detection.gap'));
GRANT INSERT ON alerts TO nightfall_app;
CREATE POLICY alerts_app_insert_detection_gap ON alerts AS RESTRICTIVE FOR INSERT TO nightfall_app
  WITH CHECK (kind = 'detection.gap');

-- BLACKSITE (host-only, lab-confined role) starts WARPATH attack steps: it may see and advance
-- WARPATH workflow runs only, and exercises of lab projects only (restrictive policies AND
-- with the tenant policies, like its other lab confinement in migration 0013).
GRANT SELECT ON warpath_exercises, workflow_runs, workflow_steps, workflow_step_events
  TO nightfall_blacksite;
GRANT UPDATE (state) ON warpath_exercises TO nightfall_blacksite;
GRANT UPDATE (state, finished_at, cancelled_by_user_id, cancel_reason) ON workflow_runs
  TO nightfall_blacksite;
GRANT UPDATE (state, attempt, started_by_user_id, started_at, deadline, finished_at, detail, outputs)
  ON workflow_steps TO nightfall_blacksite;
CREATE POLICY blacksite_workflow_runs ON workflow_runs AS RESTRICTIVE TO nightfall_blacksite
  USING (definition_id = 'warpath-exercise') WITH CHECK (definition_id = 'warpath-exercise');
CREATE POLICY blacksite_workflow_steps ON workflow_steps AS RESTRICTIVE TO nightfall_blacksite
  USING (run_id IN (SELECT id FROM workflow_runs)) WITH CHECK (run_id IN (SELECT id FROM workflow_runs));
CREATE POLICY blacksite_workflow_step_events ON workflow_step_events AS RESTRICTIVE
  TO nightfall_blacksite USING (run_id IN (SELECT id FROM workflow_runs));
CREATE POLICY blacksite_warpath_exercises ON warpath_exercises AS RESTRICTIVE TO nightfall_blacksite
  USING (project_id IN (SELECT project_id FROM scopes)) WITH CHECK (project_id IN (SELECT project_id FROM scopes));
"""

DOWNGRADE = r"""
DROP POLICY IF EXISTS blacksite_warpath_exercises ON warpath_exercises;
DROP POLICY IF EXISTS blacksite_workflow_step_events ON workflow_step_events;
DROP POLICY IF EXISTS blacksite_workflow_steps ON workflow_steps;
DROP POLICY IF EXISTS blacksite_workflow_runs ON workflow_runs;
REVOKE ALL ON workflow_runs, workflow_steps, workflow_step_events FROM nightfall_blacksite;
DROP POLICY alerts_app_insert_detection_gap ON alerts;
REVOKE INSERT ON alerts FROM nightfall_app;
ALTER TABLE alerts DROP CONSTRAINT alerts_kind_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_kind_check CHECK (kind IN (
  'cert.expiring', 'cert.changed', 'tls.weakened', 'headers.regressed', 'ct.new_names',
  'dns.changed', 'finding.reopened', 'monitor.failed', 'monitor.expiring', 'monitor.ended')) NOT VALID;
DROP TABLE warpath_scores;
DROP TRIGGER warpath_exercises_guard ON warpath_exercises;
DROP FUNCTION nf_warpath_exercise_guard();
DROP TABLE warpath_exercises;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
