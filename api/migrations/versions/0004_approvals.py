"""Phase 3b: human approvals for operations above "passive".

Only users approve (no agent column exists), never the person who requested the
operation (trigger), and every approval records the scope version it was given under.

Revision ID: 0004
"""

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TYPE approval_decision AS ENUM ('approved', 'rejected');

CREATE TABLE approvals (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id          uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  operation_id          uuid NOT NULL UNIQUE,
  approver_user_id      uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  decision              approval_decision NOT NULL,
  reason                text NOT NULL DEFAULT '' CHECK (length(reason) <= 1000),
  scope_id_at_decision  uuid NOT NULL,
  decided_at            timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (operation_id, workspace_id) REFERENCES operations (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (scope_id_at_decision, workspace_id) REFERENCES scopes (id, workspace_id) ON DELETE RESTRICT
);

CREATE FUNCTION nf_approval_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE requester uuid;
BEGIN
  SELECT requested_by_user_id INTO requester FROM operations WHERE id = NEW.operation_id;
  IF requester IS NOT NULL AND requester = NEW.approver_user_id THEN
    RAISE EXCEPTION 'an operation cannot be approved by the person who requested it'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER approvals_guard BEFORE INSERT OR UPDATE ON approvals
  FOR EACH ROW EXECUTE FUNCTION nf_approval_guard();

-- Approval-pending operations count as pending for de-duplication.
DROP INDEX operations_one_pending;
CREATE UNIQUE INDEX operations_one_pending ON operations (project_id, tool, target_value)
  WHERE status IN ('awaiting_approval', 'queued', 'running');

ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
CREATE POLICY approvals_tenant ON approvals
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());

-- Decisions are final: no UPDATE/DELETE for either role.
GRANT SELECT, INSERT ON approvals TO nightfall_app;
GRANT SELECT ON approvals TO nightfall_worker;
"""

DOWNGRADE = r"""
DROP INDEX operations_one_pending;
CREATE UNIQUE INDEX operations_one_pending ON operations (project_id, tool, target_value)
  WHERE status IN ('queued', 'running');
DROP TABLE approvals;
DROP FUNCTION nf_approval_guard();
DROP TYPE approval_decision;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
