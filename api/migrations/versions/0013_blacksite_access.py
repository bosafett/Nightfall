"""JANUS Phase 1: single-operator approval policy, BLACKSITE database role, lab boundary.

  * workspaces.approval_policy: 'single_operator' (default, owner decision D1) or
    'two_person'. Under single_operator only a workspace owner may approve an operation
    they requested; the API also requires two-factor verified in the last 15 minutes. Under
    two_person nobody approves their own request (the earlier rule, kept for later).
  * nightfall_blacksite: the role of the host-only BLACKSITE listener on the lab machine.
    NOLOGIN until its password is configured. Restrictive policies confine it to lab work;
    it can add audit events but never change or delete them.
  * Lab boundary (D3): the hosted API role (nightfall_app) may read lab records but can no
    longer create, approve or change lab operations or lab playbook runs. Only BLACKSITE can.

Revision ID: 0013
"""

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

UPGRADE = r"""
ALTER TABLE workspaces ADD COLUMN approval_policy text NOT NULL DEFAULT 'single_operator'
  CHECK (approval_policy IN ('single_operator', 'two_person'));

-- SECURITY DEFINER: the decision can't depend on what the caller's RLS lets it see.
CREATE OR REPLACE FUNCTION nf_approval_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE requester uuid; ws uuid; policy text;
BEGIN
  SELECT requested_by_user_id, workspace_id INTO requester, ws
    FROM operations WHERE id = NEW.operation_id;
  IF requester IS NOT NULL AND requester = NEW.approver_user_id THEN
    SELECT approval_policy INTO policy FROM workspaces WHERE id = ws;
    IF policy IS DISTINCT FROM 'single_operator' OR NOT EXISTS (
         SELECT 1 FROM workspace_members
         WHERE workspace_id = ws AND user_id = NEW.approver_user_id AND role = 'owner') THEN
      RAISE EXCEPTION 'an operation cannot be approved by the person who requested it'
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nightfall_blacksite') THEN
    CREATE ROLE nightfall_blacksite NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO nightfall_blacksite;
GRANT EXECUTE ON FUNCTION nf_current_workspace(), nf_current_user(),
  nf_user_workspace_count(uuid) TO nightfall_blacksite;
-- Sign-in through the tunnel: its own sessions, TOTP replay counter, throttling.
GRANT SELECT, INSERT, UPDATE ON users, sessions TO nightfall_blacksite;
GRANT SELECT, INSERT, DELETE ON rate_limit_hits TO nightfall_blacksite;
GRANT SELECT ON workspaces, workspace_members, organizations, projects, scopes, scope_targets,
  scope_exclusions, evidence, findings, playbook_settings TO nightfall_blacksite;
GRANT SELECT, INSERT, UPDATE ON operations TO nightfall_blacksite;
GRANT SELECT, INSERT ON approvals, playbook_runs TO nightfall_blacksite;
GRANT INSERT ON audit_events TO nightfall_blacksite;

-- Confinement: lab records only (restrictive policies AND with the tenant policies).
CREATE POLICY blacksite_operations ON operations AS RESTRICTIVE TO nightfall_blacksite
  USING (is_lab) WITH CHECK (is_lab);
CREATE POLICY blacksite_approvals ON approvals AS RESTRICTIVE TO nightfall_blacksite
  USING (operation_id IN (SELECT id FROM operations))
  WITH CHECK (operation_id IN (SELECT id FROM operations));
CREATE POLICY blacksite_playbook_runs ON playbook_runs AS RESTRICTIVE TO nightfall_blacksite
  USING (profile = 'lab') WITH CHECK (profile = 'lab');
CREATE POLICY blacksite_scopes ON scopes AS RESTRICTIVE TO nightfall_blacksite USING (is_lab);
CREATE POLICY blacksite_scope_targets ON scope_targets AS RESTRICTIVE TO nightfall_blacksite
  USING (scope_id IN (SELECT id FROM scopes));
CREATE POLICY blacksite_scope_exclusions ON scope_exclusions AS RESTRICTIVE TO nightfall_blacksite
  USING (scope_id IN (SELECT id FROM scopes));
CREATE POLICY blacksite_projects ON projects AS RESTRICTIVE TO nightfall_blacksite
  USING (id IN (SELECT project_id FROM scopes));
CREATE POLICY blacksite_organizations ON organizations AS RESTRICTIVE TO nightfall_blacksite
  USING (id IN (SELECT organization_id FROM projects));
CREATE POLICY blacksite_evidence ON evidence AS RESTRICTIVE TO nightfall_blacksite
  USING (operation_id IN (SELECT id FROM operations));
CREATE POLICY blacksite_findings ON findings AS RESTRICTIVE TO nightfall_blacksite
  USING (project_id IN (SELECT project_id FROM operations));

-- Lab boundary for the hosted API: read-only on lab work.
CREATE POLICY app_no_lab_operation_insert ON operations AS RESTRICTIVE FOR INSERT
  TO nightfall_app WITH CHECK (NOT is_lab);
CREATE POLICY app_no_lab_operation_update ON operations AS RESTRICTIVE FOR UPDATE
  TO nightfall_app USING (NOT is_lab) WITH CHECK (NOT is_lab);
CREATE POLICY app_no_lab_approvals ON approvals AS RESTRICTIVE FOR INSERT TO nightfall_app
  WITH CHECK (operation_id IN (SELECT id FROM operations WHERE NOT is_lab));
CREATE POLICY app_no_lab_playbook_runs ON playbook_runs AS RESTRICTIVE FOR INSERT
  TO nightfall_app WITH CHECK (profile <> 'lab');
"""

DOWNGRADE = r"""
DROP POLICY IF EXISTS app_no_lab_playbook_runs ON playbook_runs;
DROP POLICY IF EXISTS app_no_lab_approvals ON approvals;
DROP POLICY IF EXISTS app_no_lab_operation_update ON operations;
DROP POLICY IF EXISTS app_no_lab_operation_insert ON operations;
DROP POLICY IF EXISTS blacksite_findings ON findings;
DROP POLICY IF EXISTS blacksite_evidence ON evidence;
DROP POLICY IF EXISTS blacksite_organizations ON organizations;
DROP POLICY IF EXISTS blacksite_projects ON projects;
DROP POLICY IF EXISTS blacksite_scope_exclusions ON scope_exclusions;
DROP POLICY IF EXISTS blacksite_scope_targets ON scope_targets;
DROP POLICY IF EXISTS blacksite_scopes ON scopes;
DROP POLICY IF EXISTS blacksite_playbook_runs ON playbook_runs;
DROP POLICY IF EXISTS blacksite_approvals ON approvals;
DROP POLICY IF EXISTS blacksite_operations ON operations;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM nightfall_blacksite;
REVOKE EXECUTE ON FUNCTION nf_current_workspace(), nf_current_user(),
  nf_user_workspace_count(uuid) FROM nightfall_blacksite;
REVOKE USAGE ON SCHEMA public FROM nightfall_blacksite;
CREATE OR REPLACE FUNCTION nf_approval_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE requester uuid;
BEGIN
  SELECT requested_by_user_id INTO requester FROM operations WHERE id = NEW.operation_id;
  IF requester IS NOT NULL AND requester = NEW.approver_user_id THEN
    RAISE EXCEPTION 'an operation cannot be approved by the person who requested it'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
ALTER TABLE workspaces DROP COLUMN IF EXISTS approval_policy;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
