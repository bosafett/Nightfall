"""Phase 5a: agent tasks.

Agents are defined in code (nightfall/agents/registry.py: prompts and allowlists are
reviewed like any other code; the prompt version is recorded on every task). This table
is the queue and the record: what was asked, of which agent, with which model, what came
back, and what it cost.

Database-level guarantees:
  * An agent-proposed operation or finding names the task that proposed it.
  * The worker can claim tasks across workspaces (like operations) and sets the task's
    workspace context before touching anything else.

Revision ID: 0008
"""

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TYPE agent_task_status AS ENUM ('queued', 'running', 'succeeded', 'failed', 'cancelled');

CREATE TABLE agent_tasks (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id          uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  project_id            uuid NOT NULL,
  agent                 text NOT NULL CHECK (agent IN (
    'director', 'scout', 'investigator', 'hunter', 'adversary', 'guardian', 'analyst')),
  parent_task_id        uuid,
  subject_finding_id    uuid,
  objective             text NOT NULL CHECK (length(objective) BETWEEN 1 AND 2000),
  context               jsonb NOT NULL DEFAULT '{}'::jsonb,
  status                agent_task_status NOT NULL DEFAULT 'queued',
  result                jsonb NOT NULL DEFAULT '{}'::jsonb,
  error                 text,
  provider              text,
  model                 text,
  prompt_version        text,
  input_tokens          integer,
  output_tokens         integer,
  latency_ms            integer,
  requested_by_user_id  uuid REFERENCES users(id) ON DELETE RESTRICT,
  attempts              integer NOT NULL DEFAULT 0,
  queued_at             timestamptz NOT NULL DEFAULT now(),
  started_at            timestamptz,
  finished_at           timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (project_id, workspace_id) REFERENCES projects (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (parent_task_id, workspace_id) REFERENCES agent_tasks (id, workspace_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (subject_finding_id, workspace_id) REFERENCES findings (id, workspace_id)
    ON DELETE RESTRICT,
  UNIQUE (id, workspace_id)
);
CREATE INDEX agent_tasks_queue_idx ON agent_tasks (queued_at) WHERE status IN ('queued', 'running');
CREATE INDEX agent_tasks_project_idx ON agent_tasks (project_id, created_at DESC);
-- One open run per project and agent (Guardian reviews: one per finding).
CREATE UNIQUE INDEX agent_tasks_one_open ON agent_tasks
  (project_id, agent, COALESCE(subject_finding_id, '00000000-0000-0000-0000-000000000000'::uuid))
  WHERE status IN ('queued', 'running');
CREATE TRIGGER agent_tasks_updated BEFORE UPDATE ON agent_tasks
  FOR EACH ROW EXECUTE FUNCTION nf_set_updated_at();

ALTER TABLE agent_tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY agent_tasks_tenant ON agent_tasks
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
CREATE POLICY agent_tasks_worker_claim ON agent_tasks TO nightfall_worker USING (true) WITH CHECK (true);

ALTER TABLE operations ADD COLUMN proposed_by_task_id uuid;
ALTER TABLE operations ADD FOREIGN KEY (proposed_by_task_id, workspace_id)
  REFERENCES agent_tasks (id, workspace_id) ON DELETE RESTRICT;
ALTER TABLE findings ADD COLUMN proposed_by_task_id uuid;
ALTER TABLE findings ADD FOREIGN KEY (proposed_by_task_id, workspace_id)
  REFERENCES agent_tasks (id, workspace_id) ON DELETE RESTRICT;
ALTER TABLE findings ADD COLUMN guardian_review jsonb;
-- Agent findings start as hypotheses; only a person can move them on (CHECK in 0005).
ALTER TABLE findings ADD CONSTRAINT findings_agent_origin_named
  CHECK (origin <> 'agent' OR proposed_by_task_id IS NOT NULL);

GRANT SELECT, INSERT, UPDATE ON agent_tasks TO nightfall_app;
GRANT SELECT, INSERT, UPDATE ON agent_tasks TO nightfall_worker;
GRANT INSERT ON operations TO nightfall_worker;
"""

DOWNGRADE = r"""
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_agent_origin_named;
ALTER TABLE findings DROP COLUMN IF EXISTS guardian_review;
ALTER TABLE findings DROP COLUMN IF EXISTS proposed_by_task_id;
ALTER TABLE operations DROP COLUMN IF EXISTS proposed_by_task_id;
REVOKE INSERT ON operations FROM nightfall_worker;
DROP TABLE IF EXISTS agent_tasks;
DROP TYPE IF EXISTS agent_task_status;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
