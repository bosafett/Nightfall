"""Probe results into BLACK ICE, and a finding-number fix.

  * nf_finding_number() is now SECURITY DEFINER. It numbered a new finding from the rows
    the *calling* role could see; a confined role (lab worker, BLACKSITE) sees only lab
    findings, so it could reuse a number already taken in the workspace.
  * nightfall_blacksite may create and refresh findings and link evidence, for lab projects
    and lab evidence only (the restrictive policies of migration 0013 now also check
    writes). Findings it creates start unverified; only a person changes that (0005 CHECK).

Revision ID: 0015
"""

from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE OR REPLACE FUNCTION nf_finding_number() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('findings:' || NEW.workspace_id::text));
  SELECT coalesce(max(number), 0) + 1 INTO NEW.number FROM findings
    WHERE workspace_id = NEW.workspace_id;
  RETURN NEW;
END $$;

GRANT INSERT, UPDATE ON findings TO nightfall_blacksite;
GRANT SELECT, INSERT ON finding_evidence TO nightfall_blacksite;
DROP POLICY blacksite_findings ON findings;
CREATE POLICY blacksite_findings ON findings AS RESTRICTIVE TO nightfall_blacksite
  USING (project_id IN (SELECT project_id FROM operations))
  WITH CHECK (project_id IN (SELECT project_id FROM operations));
CREATE POLICY blacksite_finding_evidence ON finding_evidence AS RESTRICTIVE TO nightfall_blacksite
  USING (evidence_id IN (SELECT id FROM evidence))
  WITH CHECK (evidence_id IN (SELECT id FROM evidence));
"""

DOWNGRADE = r"""
DROP POLICY IF EXISTS blacksite_finding_evidence ON finding_evidence;
REVOKE SELECT, INSERT ON finding_evidence FROM nightfall_blacksite;
REVOKE INSERT, UPDATE ON findings FROM nightfall_blacksite;
DROP POLICY IF EXISTS blacksite_findings ON findings;
CREATE POLICY blacksite_findings ON findings AS RESTRICTIVE TO nightfall_blacksite
  USING (project_id IN (SELECT project_id FROM operations));
CREATE OR REPLACE FUNCTION nf_finding_number() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('findings:' || NEW.workspace_id::text));
  SELECT coalesce(max(number), 0) + 1 INTO NEW.number FROM findings
    WHERE workspace_id = NEW.workspace_id;
  RETURN NEW;
END $$;
ALTER FUNCTION nf_finding_number() SECURITY INVOKER;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
