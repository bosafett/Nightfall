"""Phase 6b: isolated lab.

  * scopes.is_lab: a lab scope may only name addresses inside the lab networks (checked by
    the API when targets are added and when the scope is authorized, and again by the lab
    worker before anything is sent). Copied to every operation (operations.is_lab) when it
    is requested, so routing never depends on a later scope change.
  * nightfall_lab_worker: the role the lab machine uses. Restrictive policies limit it to
    lab operations; the normal worker is limited to non-lab operations the same way, so
    neither can run the other's jobs. The lab role has no access to agent tasks, attack
    paths, users or sessions, and can add evidence content but never read it back.
  * Moderate-risk operations are allowed only in a lab scope (still with an approval).

Revision ID: 0010
"""

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

UPGRADE = r"""
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nightfall_lab_worker') THEN
    CREATE ROLE nightfall_lab_worker NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

ALTER TABLE scopes ADD COLUMN is_lab boolean NOT NULL DEFAULT false;
ALTER TABLE operations ADD COLUMN is_lab boolean NOT NULL DEFAULT false;
ALTER TABLE operations ADD CONSTRAINT operations_moderate_only_in_lab
  CHECK (risk_class <> 'moderate' OR is_lab);
CREATE INDEX operations_lab_queue_idx ON operations (queued_at)
  WHERE is_lab AND status IN ('queued', 'running');

-- Who may claim what. Restrictive policies are ANDed with the permissive ones.
CREATE POLICY operations_worker_not_lab ON operations AS RESTRICTIVE TO nightfall_worker
  USING (NOT is_lab) WITH CHECK (NOT is_lab);
CREATE POLICY operations_lab_claim ON operations TO nightfall_lab_worker
  USING (is_lab) WITH CHECK (is_lab);
CREATE POLICY operations_lab_only ON operations AS RESTRICTIVE TO nightfall_lab_worker
  USING (is_lab) WITH CHECK (is_lab);
CREATE POLICY evidence_blobs_lab_insert ON evidence_blobs FOR INSERT TO nightfall_lab_worker
  WITH CHECK (true);

GRANT USAGE ON SCHEMA public TO nightfall_lab_worker;
GRANT EXECUTE ON FUNCTION nf_current_workspace(), nf_current_user() TO nightfall_lab_worker;
GRANT SELECT ON organizations, projects, scopes, scope_targets, scope_exclusions, approvals
  TO nightfall_lab_worker;
GRANT SELECT, UPDATE ON operations TO nightfall_lab_worker;
GRANT SELECT, INSERT, UPDATE ON assets, asset_relationships, findings TO nightfall_lab_worker;
GRANT SELECT, INSERT ON evidence, finding_evidence TO nightfall_lab_worker;
GRANT INSERT ON evidence_blobs, audit_events TO nightfall_lab_worker;
GRANT SELECT, INSERT, UPDATE ON worker_heartbeats TO nightfall_lab_worker;
"""

DOWNGRADE = r"""
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM nightfall_lab_worker;
REVOKE EXECUTE ON FUNCTION nf_current_workspace(), nf_current_user() FROM nightfall_lab_worker;
REVOKE USAGE ON SCHEMA public FROM nightfall_lab_worker;
DROP POLICY IF EXISTS evidence_blobs_lab_insert ON evidence_blobs;
DROP POLICY IF EXISTS operations_lab_only ON operations;
DROP POLICY IF EXISTS operations_lab_claim ON operations;
DROP POLICY IF EXISTS operations_worker_not_lab ON operations;
DROP INDEX IF EXISTS operations_lab_queue_idx;
ALTER TABLE operations DROP CONSTRAINT IF EXISTS operations_moderate_only_in_lab;
ALTER TABLE operations DROP COLUMN IF EXISTS is_lab;
ALTER TABLE scopes DROP COLUMN IF EXISTS is_lab;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
