"""Confine the lab worker's role to lab data (authorization review finding F1).

Migration 0010 limited nightfall_lab_worker to lab *operations*, but on every other table
it relied on the workspace context it sets itself, so the lab credential could read and
write any workspace's assets, findings and scopes. These restrictive policies (ANDed with
the tenant policies) tie each table to lab work:

  operations           is_lab (0010)
  projects             has a lab operation
  organizations        owns a lab project
  scopes (+ entries)   is_lab
  approvals, evidence  belong to a lab operation
  finding_evidence     links lab evidence
  findings             in a lab project
  assets               private IPv4 addresses (the only thing a lab scope can name) in an
                       organization with a lab project
  asset_relationships  both ends are such assets
  audit_events         workspace has lab operations

Subqueries are evaluated with the lab role's own row-level security, so "lab operation"
always means one this role can see (is_lab).

Revision ID: 0011
"""

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


UPGRADE = r"""
CREATE OR REPLACE FUNCTION nf_is_private_ipv4(v text) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN v ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' THEN
      v::inet <<= ANY (ARRAY['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']::inet[])
    ELSE false END
$$;
GRANT EXECUTE ON FUNCTION nf_is_private_ipv4(text) TO nightfall_lab_worker;

CREATE POLICY lab_projects ON projects AS RESTRICTIVE TO nightfall_lab_worker
  USING (id IN (SELECT project_id FROM operations));
CREATE POLICY lab_organizations ON organizations AS RESTRICTIVE TO nightfall_lab_worker
  USING (id IN (SELECT organization_id FROM projects));
CREATE POLICY lab_scopes ON scopes AS RESTRICTIVE TO nightfall_lab_worker
  USING (is_lab);
CREATE POLICY lab_scope_targets ON scope_targets AS RESTRICTIVE TO nightfall_lab_worker
  USING (scope_id IN (SELECT id FROM scopes));
CREATE POLICY lab_scope_exclusions ON scope_exclusions AS RESTRICTIVE TO nightfall_lab_worker
  USING (scope_id IN (SELECT id FROM scopes));
CREATE POLICY lab_approvals ON approvals AS RESTRICTIVE TO nightfall_lab_worker
  USING (operation_id IN (SELECT id FROM operations));
CREATE POLICY lab_evidence ON evidence AS RESTRICTIVE TO nightfall_lab_worker
  USING (operation_id IN (SELECT id FROM operations))
  WITH CHECK (operation_id IN (SELECT id FROM operations));
CREATE POLICY lab_finding_evidence ON finding_evidence AS RESTRICTIVE TO nightfall_lab_worker
  USING (evidence_id IN (SELECT id FROM evidence))
  WITH CHECK (evidence_id IN (SELECT id FROM evidence));
CREATE POLICY lab_findings ON findings AS RESTRICTIVE TO nightfall_lab_worker
  USING (project_id IN (SELECT project_id FROM operations))
  WITH CHECK (project_id IN (SELECT project_id FROM operations));
CREATE POLICY lab_assets ON assets AS RESTRICTIVE TO nightfall_lab_worker
  USING (nf_is_private_ipv4(value) AND organization_id IN (SELECT organization_id FROM projects))
  WITH CHECK (nf_is_private_ipv4(value) AND organization_id IN (SELECT organization_id FROM projects));
CREATE POLICY lab_asset_relationships ON asset_relationships AS RESTRICTIVE TO nightfall_lab_worker
  USING (from_asset_id IN (SELECT id FROM assets) AND to_asset_id IN (SELECT id FROM assets))
  WITH CHECK (from_asset_id IN (SELECT id FROM assets) AND to_asset_id IN (SELECT id FROM assets));
CREATE POLICY lab_audit_events ON audit_events AS RESTRICTIVE FOR INSERT TO nightfall_lab_worker
  WITH CHECK (workspace_id IN (SELECT workspace_id FROM operations));
"""

DOWNGRADE = r"""
DROP POLICY IF EXISTS lab_audit_events ON audit_events;
DROP POLICY IF EXISTS lab_asset_relationships ON asset_relationships;
DROP POLICY IF EXISTS lab_assets ON assets;
DROP POLICY IF EXISTS lab_findings ON findings;
DROP POLICY IF EXISTS lab_finding_evidence ON finding_evidence;
DROP POLICY IF EXISTS lab_evidence ON evidence;
DROP POLICY IF EXISTS lab_approvals ON approvals;
DROP POLICY IF EXISTS lab_scope_exclusions ON scope_exclusions;
DROP POLICY IF EXISTS lab_scope_targets ON scope_targets;
DROP POLICY IF EXISTS lab_scopes ON scopes;
DROP POLICY IF EXISTS lab_organizations ON organizations;
DROP POLICY IF EXISTS lab_projects ON projects;
REVOKE EXECUTE ON FUNCTION nf_is_private_ipv4(text) FROM nightfall_lab_worker;
DROP FUNCTION IF EXISTS nf_is_private_ipv4(text);
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
