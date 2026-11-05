"""Phase 5b: Director, Investigator, Adversary, Analyst.

  * agent_tasks.subject_asset_id: what an Investigator run explains. One open run per
    project, agent and subject (finding or asset).
  * attack_paths.proposed_by_task_id: Adversary's paths name the task that proposed them,
    start as low-confidence hypotheses, and (CHECK in 0005) only a person can review them.
  * asset_relationships.proposed_by_task_id: Investigator's relationships enter as
    hypotheses. A collector that later observes the same relationship promotes it with its
    own rule and evidence; until then, an agent-proposed row can't claim to be observed.
  * The worker may insert attack paths (it never updates their status).

Revision ID: 0009
"""

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

UPGRADE = r"""
ALTER TABLE agent_tasks ADD COLUMN subject_asset_id uuid;
ALTER TABLE agent_tasks ADD FOREIGN KEY (subject_asset_id, workspace_id)
  REFERENCES assets (id, workspace_id) ON DELETE RESTRICT;
DROP INDEX agent_tasks_one_open;
CREATE UNIQUE INDEX agent_tasks_one_open ON agent_tasks
  (project_id, agent,
   COALESCE(subject_finding_id, subject_asset_id, '00000000-0000-0000-0000-000000000000'::uuid))
  WHERE status IN ('queued', 'running');

ALTER TABLE attack_paths ADD COLUMN proposed_by_task_id uuid;
ALTER TABLE attack_paths ADD FOREIGN KEY (proposed_by_task_id, workspace_id)
  REFERENCES agent_tasks (id, workspace_id) ON DELETE RESTRICT;
ALTER TABLE attack_paths ADD CONSTRAINT attack_paths_agent_low_confidence
  CHECK (proposed_by_task_id IS NULL OR status <> 'hypothesis' OR confidence = 'low');

ALTER TABLE asset_relationships ADD COLUMN proposed_by_task_id uuid;
ALTER TABLE asset_relationships ADD FOREIGN KEY (proposed_by_task_id, workspace_id)
  REFERENCES agent_tasks (id, workspace_id) ON DELETE RESTRICT;
ALTER TABLE asset_relationships ADD CONSTRAINT asset_relationships_agent_hypothesis
  CHECK (rule_id NOT LIKE 'agent:%' OR (status = 'hypothesis' AND proposed_by_task_id IS NOT NULL));

GRANT SELECT, INSERT ON attack_paths, attack_path_steps TO nightfall_worker;
"""

DOWNGRADE = r"""
REVOKE SELECT, INSERT ON attack_paths, attack_path_steps FROM nightfall_worker;
ALTER TABLE asset_relationships DROP CONSTRAINT IF EXISTS asset_relationships_agent_hypothesis;
ALTER TABLE asset_relationships DROP COLUMN IF EXISTS proposed_by_task_id;
ALTER TABLE attack_paths DROP CONSTRAINT IF EXISTS attack_paths_agent_low_confidence;
ALTER TABLE attack_paths DROP COLUMN IF EXISTS proposed_by_task_id;
DROP INDEX agent_tasks_one_open;
CREATE UNIQUE INDEX agent_tasks_one_open ON agent_tasks
  (project_id, agent, COALESCE(subject_finding_id, '00000000-0000-0000-0000-000000000000'::uuid))
  WHERE status IN ('queued', 'running');
ALTER TABLE agent_tasks DROP COLUMN IF EXISTS subject_asset_id;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
