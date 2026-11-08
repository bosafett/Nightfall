"""BLACK OPS Profile B step 3: moderate-risk operations outside the lab, only in Profile B.

Until now operations_moderate_only_in_lab allowed moderate risk only on the isolated lab.
Profile B's playbooks (design §3) are moderate risk on real targets whose control is
proven. The CHECK becomes a trigger that allows a non-lab moderate operation only as a
step of a Profile B ('validation') playbook run, whose own insert already required a fresh
proof of control and valid test identities (migration 0019). Everything else stays as it
was: high risk is still refused everywhere, and a plain collection request can't be
moderate outside the lab.

Revision ID: 0020
"""

from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None

UPGRADE = r"""
ALTER TABLE operations DROP CONSTRAINT operations_moderate_only_in_lab;

CREATE FUNCTION nf_operation_moderate_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' AND NEW.risk_class = 'moderate' AND NOT NEW.is_lab THEN
    IF NEW.playbook_run_id IS NULL OR NOT EXISTS (
         SELECT 1 FROM playbook_runs r
          WHERE r.id = NEW.playbook_run_id AND r.workspace_id = NEW.workspace_id
            AND r.profile = 'validation') THEN
      RAISE EXCEPTION 'moderate risk outside the lab only as a step of a Profile B run'
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.risk_class IS DISTINCT FROM OLD.risk_class THEN
    RAISE EXCEPTION 'an operation''s risk class cannot change' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER operations_moderate_guard BEFORE INSERT OR UPDATE ON operations
  FOR EACH ROW EXECUTE FUNCTION nf_operation_moderate_guard();
"""

DOWNGRADE = r"""
DROP TRIGGER operations_moderate_guard ON operations;
DROP FUNCTION nf_operation_moderate_guard();
ALTER TABLE operations ADD CONSTRAINT operations_moderate_only_in_lab
  CHECK (risk_class <> 'moderate' OR is_lab);
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
