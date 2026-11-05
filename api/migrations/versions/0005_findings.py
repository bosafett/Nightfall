"""Phase 4a: findings, finding↔evidence links, attack paths, assessment snapshots.

Database-level guarantees:
  * validated / false_positive / remediated findings must name the human who decided;
  * a validated attack path must name its human reviewer;
  * snapshots (what reports are rendered from) are insert-only.

Revision ID: 0005
"""

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE validation_status AS ENUM (
  'hypothesis', 'unverified', 'validated', 'false_positive', 'remediated');
CREATE TYPE finding_origin AS ENUM ('human', 'deterministic_check', 'agent');
CREATE TYPE attack_path_status AS ENUM ('hypothesis', 'validated', 'rejected');

CREATE TABLE findings (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id          uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  number                integer NOT NULL,
  project_id            uuid NOT NULL,
  asset_id              uuid,
  title                 text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
  description           text NOT NULL DEFAULT '' CHECK (length(description) <= 20000),
  severity              severity NOT NULL,
  confidence            confidence_level NOT NULL,
  validation_status     validation_status NOT NULL,
  origin                finding_origin NOT NULL,
  check_id              text CHECK (length(check_id) <= 200),
  rule_id               text,
  discovery_source      text NOT NULL DEFAULT '' CHECK (length(discovery_source) <= 300),
  impact                text NOT NULL DEFAULT '' CHECK (length(impact) <= 10000),
  remediation           text NOT NULL DEFAULT '' CHECK (length(remediation) <= 10000),
  first_observed_at     timestamptz NOT NULL DEFAULT now(),
  last_observed_at      timestamptz NOT NULL DEFAULT now(),
  validated_by_user_id  uuid REFERENCES users(id) ON DELETE RESTRICT,
  validated_at          timestamptz,
  status_note           text NOT NULL DEFAULT '' CHECK (length(status_note) <= 2000),
  created_by_user_id    uuid REFERENCES users(id) ON DELETE RESTRICT,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (project_id, workspace_id) REFERENCES projects (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (asset_id, workspace_id) REFERENCES assets (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (workspace_id, number),
  UNIQUE (id, workspace_id),
  -- Only a human decision can verify, dismiss or close a finding.
  CHECK (validation_status IN ('hypothesis', 'unverified')
         OR (validated_by_user_id IS NOT NULL AND validated_at IS NOT NULL))
);
-- One finding per project/asset/check: re-observation updates it instead of duplicating.
CREATE UNIQUE INDEX findings_check_uq ON findings (project_id, asset_id, check_id) NULLS NOT DISTINCT
  WHERE check_id IS NOT NULL;
CREATE INDEX findings_filter_idx ON findings (workspace_id, severity, validation_status);
CREATE INDEX findings_recent_idx ON findings (workspace_id, last_observed_at DESC);
CREATE INDEX findings_asset_idx ON findings (asset_id);

-- Per-workspace finding numbers (NF-0001, NF-0002, ...), assigned under a lock.
CREATE FUNCTION nf_finding_number() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('findings:' || NEW.workspace_id::text));
  SELECT coalesce(max(number), 0) + 1 INTO NEW.number FROM findings
    WHERE workspace_id = NEW.workspace_id;
  RETURN NEW;
END $$;
CREATE TRIGGER findings_number BEFORE INSERT ON findings
  FOR EACH ROW EXECUTE FUNCTION nf_finding_number();
CREATE TRIGGER findings_updated_at BEFORE UPDATE ON findings
  FOR EACH ROW EXECUTE FUNCTION nf_set_updated_at();

CREATE TABLE finding_evidence (
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  finding_id    uuid NOT NULL,
  evidence_id   uuid NOT NULL,
  note          text NOT NULL DEFAULT '' CHECK (length(note) <= 1000),
  linked_by     text NOT NULL,  -- 'rule:<id>' or 'user:<uuid>'
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (finding_id, evidence_id),
  FOREIGN KEY (finding_id, workspace_id) REFERENCES findings (id, workspace_id) ON DELETE CASCADE,
  FOREIGN KEY (evidence_id, workspace_id) REFERENCES evidence (id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX finding_evidence_evidence_idx ON finding_evidence (evidence_id);

CREATE TABLE attack_paths (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id         uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  project_id           uuid NOT NULL,
  title                text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
  narrative            text NOT NULL DEFAULT '' CHECK (length(narrative) <= 20000),
  status               attack_path_status NOT NULL DEFAULT 'hypothesis',
  confidence           confidence_level NOT NULL DEFAULT 'low',
  created_by_user_id   uuid REFERENCES users(id) ON DELETE RESTRICT,
  reviewed_by_user_id  uuid REFERENCES users(id) ON DELETE RESTRICT,
  reviewed_at          timestamptz,
  review_note          text NOT NULL DEFAULT '' CHECK (length(review_note) <= 2000),
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (project_id, workspace_id) REFERENCES projects (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (id, workspace_id),
  CHECK (status = 'hypothesis' OR (reviewed_by_user_id IS NOT NULL AND reviewed_at IS NOT NULL))
);
CREATE TRIGGER attack_paths_updated_at BEFORE UPDATE ON attack_paths
  FOR EACH ROW EXECUTE FUNCTION nf_set_updated_at();

CREATE TABLE attack_path_steps (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id    uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  attack_path_id  uuid NOT NULL,
  ordinal         integer NOT NULL CHECK (ordinal BETWEEN 1 AND 50),
  asset_id        uuid,
  finding_id      uuid,
  description     text NOT NULL CHECK (length(description) BETWEEN 1 AND 2000),
  FOREIGN KEY (attack_path_id, workspace_id) REFERENCES attack_paths (id, workspace_id) ON DELETE CASCADE,
  FOREIGN KEY (asset_id, workspace_id) REFERENCES assets (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (finding_id, workspace_id) REFERENCES findings (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (attack_path_id, ordinal),
  CHECK (asset_id IS NOT NULL OR finding_id IS NOT NULL)
);

CREATE TABLE assessment_snapshots (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id      uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  project_id        uuid NOT NULL,
  taken_by_user_id  uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  taken_at          timestamptz NOT NULL DEFAULT now(),
  ruleset_version   text NOT NULL,
  content           jsonb NOT NULL,
  content_sha256    bytea NOT NULL CHECK (length(content_sha256) = 32),
  FOREIGN KEY (project_id, workspace_id) REFERENCES projects (id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX assessment_snapshots_project_idx ON assessment_snapshots (project_id, taken_at DESC);

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE attack_paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE attack_path_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE assessment_snapshots ENABLE ROW LEVEL SECURITY;
CREATE POLICY findings_tenant ON findings USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
CREATE POLICY finding_evidence_tenant ON finding_evidence USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
CREATE POLICY attack_paths_tenant ON attack_paths USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
CREATE POLICY attack_path_steps_tenant ON attack_path_steps USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
CREATE POLICY assessment_snapshots_tenant ON assessment_snapshots USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());

GRANT SELECT, INSERT, UPDATE ON findings TO nightfall_app;
GRANT SELECT, INSERT, DELETE ON finding_evidence TO nightfall_app;
GRANT SELECT, INSERT, UPDATE ON attack_paths TO nightfall_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON attack_path_steps TO nightfall_app;
GRANT SELECT, INSERT ON assessment_snapshots TO nightfall_app;
-- The worker records rule-based findings and links their evidence; it can't verify them
-- (the CHECK above requires a human for that) and can't touch attack paths or snapshots.
GRANT SELECT, INSERT, UPDATE ON findings TO nightfall_worker;
GRANT SELECT, INSERT ON finding_evidence TO nightfall_worker;
"""

DOWNGRADE = r"""
DROP TABLE IF EXISTS assessment_snapshots, attack_path_steps, attack_paths, finding_evidence,
  findings CASCADE;
DROP FUNCTION IF EXISTS nf_finding_number();
DROP TYPE IF EXISTS attack_path_status, finding_origin, validation_status, severity;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
