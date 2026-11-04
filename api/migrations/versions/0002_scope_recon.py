"""Phase 3: assets, versioned scopes, operations queue, evidence, asset relationships,
worker heartbeats.

Scope rules live in the database as well as the API: an authorized scope version is
immutable (triggers), only one version per project is active, and "high" risk
operations cannot be stored at all.

Revision ID: 0002
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TYPE asset_kind AS ENUM (
  'domain', 'hostname', 'ip_address', 'ip_range', 'application', 'api', 'cloud_resource', 'other');
CREATE TYPE asset_ownership AS ENUM ('organization', 'third_party', 'unknown');
CREATE TYPE scope_status AS ENUM ('draft', 'active', 'superseded');
CREATE TYPE scope_entry_kind AS ENUM ('host', 'domain_tree', 'ip', 'cidr');
CREATE TYPE risk_class AS ENUM ('passive', 'low', 'moderate', 'high');
CREATE TYPE operation_status AS ENUM ('queued', 'running', 'succeeded', 'failed', 'denied', 'cancelled');
CREATE TYPE evidence_kind AS ENUM ('observation', 'tool_output', 'document', 'screenshot', 'agent_note');
CREATE TYPE confidence_level AS ENUM ('low', 'medium', 'high');
CREATE TYPE relationship_type AS ENUM ('subdomain_of', 'resolves_to', 'cname_to');
CREATE TYPE relationship_status AS ENUM ('observed', 'hypothesis');

ALTER TABLE projects ADD CONSTRAINT projects_id_workspace_uq UNIQUE (id, workspace_id);

-- Assets -------------------------------------------------------------------

CREATE TABLE assets (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id     uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  organization_id  uuid NOT NULL,
  kind             asset_kind NOT NULL,
  value            text NOT NULL CHECK (length(value) BETWEEN 1 AND 500),
  ownership        asset_ownership NOT NULL DEFAULT 'unknown',
  source           text NOT NULL CHECK (length(source) BETWEEN 1 AND 100),
  notes            text NOT NULL DEFAULT '' CHECK (length(notes) <= 10000),
  first_seen_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at     timestamptz NOT NULL DEFAULT now(),
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, workspace_id) REFERENCES organizations (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (workspace_id, organization_id, kind, value),
  UNIQUE (id, workspace_id)
);
CREATE INDEX assets_org_idx ON assets (organization_id, kind);
CREATE INDEX assets_created_idx ON assets (workspace_id, created_at DESC);

-- Scopes (versioned per project) --------------------------------------------

CREATE TABLE scopes (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id             uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  project_id               uuid NOT NULL,
  version                  integer NOT NULL CHECK (version > 0),
  status                   scope_status NOT NULL DEFAULT 'draft',
  authorization_reference  text NOT NULL DEFAULT '' CHECK (length(authorization_reference) <= 500),
  valid_from               timestamptz,
  valid_until              timestamptz,
  created_by_user_id       uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  authorized_by_user_id    uuid REFERENCES users(id) ON DELETE RESTRICT,
  authorized_at            timestamptz,
  superseded_at            timestamptz,
  created_at               timestamptz NOT NULL DEFAULT now(),
  updated_at               timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (project_id, workspace_id) REFERENCES projects (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (project_id, version),
  UNIQUE (id, workspace_id),
  CHECK (status = 'draft' OR (authorized_by_user_id IS NOT NULL AND authorized_at IS NOT NULL
                              AND length(authorization_reference) > 0)),
  CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
);
CREATE UNIQUE INDEX scopes_one_active ON scopes (project_id) WHERE status = 'active';
CREATE UNIQUE INDEX scopes_one_draft ON scopes (project_id) WHERE status = 'draft';

CREATE TABLE scope_targets (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid NOT NULL,
  scope_id      uuid NOT NULL,
  kind          scope_entry_kind NOT NULL,
  value         text NOT NULL CHECK (length(value) BETWEEN 1 AND 300),
  note          text NOT NULL DEFAULT '' CHECK (length(note) <= 500),
  created_at    timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (scope_id, workspace_id) REFERENCES scopes (id, workspace_id) ON DELETE CASCADE,
  UNIQUE (scope_id, kind, value)
);

CREATE TABLE scope_exclusions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid NOT NULL,
  scope_id      uuid NOT NULL,
  kind          scope_entry_kind NOT NULL,
  value         text NOT NULL CHECK (length(value) BETWEEN 1 AND 300),
  reason        text NOT NULL DEFAULT '' CHECK (length(reason) <= 500),
  created_at    timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (scope_id, workspace_id) REFERENCES scopes (id, workspace_id) ON DELETE CASCADE,
  UNIQUE (scope_id, kind, value)
);

-- An authorized scope can only move to superseded; a superseded one never changes.
CREATE FUNCTION nf_scope_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.status <> 'draft' THEN
      RAISE EXCEPTION 'only draft scopes can be deleted' USING ERRCODE = 'check_violation';
    END IF;
    RETURN OLD;
  END IF;
  IF OLD.status = 'superseded' THEN
    RAISE EXCEPTION 'superseded scopes are immutable' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status = 'active' AND NOT (
       NEW.status = 'superseded'
       AND NEW.project_id = OLD.project_id AND NEW.version = OLD.version
       AND NEW.authorization_reference = OLD.authorization_reference
       AND NEW.valid_from IS NOT DISTINCT FROM OLD.valid_from
       AND NEW.valid_until IS NOT DISTINCT FROM OLD.valid_until
       AND NEW.authorized_by_user_id = OLD.authorized_by_user_id
       AND NEW.authorized_at = OLD.authorized_at) THEN
    RAISE EXCEPTION 'authorized scopes are immutable' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status = 'draft' AND NEW.status = 'superseded' THEN
    RAISE EXCEPTION 'a draft cannot be superseded' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER scopes_guard BEFORE UPDATE OR DELETE ON scopes
  FOR EACH ROW EXECUTE FUNCTION nf_scope_guard();

-- Entries of a non-draft scope can't be added, changed or removed. (Cascade deletes of
-- a draft scope's entries are allowed because the draft still exists at that point.)
CREATE FUNCTION nf_scope_entry_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE s scope_status;
BEGIN
  SELECT status INTO s FROM scopes WHERE id = COALESCE(NEW.scope_id, OLD.scope_id);
  IF s IS NOT NULL AND s <> 'draft' THEN
    RAISE EXCEPTION 'scope entries can only change while the scope is a draft'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN COALESCE(NEW, OLD);
END $$;
CREATE TRIGGER scope_targets_guard BEFORE INSERT OR UPDATE OR DELETE ON scope_targets
  FOR EACH ROW EXECUTE FUNCTION nf_scope_entry_guard();
CREATE TRIGGER scope_exclusions_guard BEFORE INSERT OR UPDATE OR DELETE ON scope_exclusions
  FOR EACH ROW EXECUTE FUNCTION nf_scope_entry_guard();

-- Operations (also the job queue) ---------------------------------------------

CREATE TABLE operations (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id          uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  project_id            uuid NOT NULL,
  scope_id              uuid NOT NULL,
  tool                  text NOT NULL CHECK (length(tool) BETWEEN 1 AND 50),
  risk_class            risk_class NOT NULL CHECK (risk_class <> 'high'),
  target_value          text NOT NULL CHECK (length(target_value) BETWEEN 1 AND 300),
  params                jsonb NOT NULL DEFAULT '{}'::jsonb,
  status                operation_status NOT NULL DEFAULT 'queued',
  requested_by_user_id  uuid REFERENCES users(id) ON DELETE RESTRICT,
  denial_reason         text,
  error                 text,
  result_summary        jsonb NOT NULL DEFAULT '{}'::jsonb,
  attempts              integer NOT NULL DEFAULT 0,
  queued_at             timestamptz NOT NULL DEFAULT now(),
  started_at            timestamptz,
  finished_at           timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (project_id, workspace_id) REFERENCES projects (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (scope_id, workspace_id) REFERENCES scopes (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (id, workspace_id)
);
-- One pending run per project/tool/target: re-submitting returns the pending one.
CREATE UNIQUE INDEX operations_one_pending ON operations (project_id, tool, target_value)
  WHERE status IN ('queued', 'running');
CREATE INDEX operations_queue_idx ON operations (queued_at) WHERE status IN ('queued', 'running');
CREATE INDEX operations_workspace_idx ON operations (workspace_id, created_at DESC);

-- Evidence (immutable; raw content lives in the content-addressed store) ------

CREATE TABLE evidence (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id       uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  project_id         uuid NOT NULL,
  asset_id           uuid,
  operation_id       uuid,
  kind               evidence_kind NOT NULL,
  source             text NOT NULL,
  collection_method  text NOT NULL,
  collected_at       timestamptz NOT NULL,
  confidence         confidence_level NOT NULL,
  tool_name          text NOT NULL,
  tool_version       text NOT NULL,
  input_params       jsonb NOT NULL DEFAULT '{}'::jsonb,
  content_sha256     bytea NOT NULL CHECK (length(content_sha256) = 32),
  content_type       text NOT NULL,
  size_bytes         bigint NOT NULL CHECK (size_bytes >= 0),
  summary            jsonb NOT NULL DEFAULT '{}'::jsonb,
  is_simulation      boolean NOT NULL DEFAULT false,
  created_at         timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (project_id, workspace_id) REFERENCES projects (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (asset_id, workspace_id) REFERENCES assets (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (operation_id, workspace_id) REFERENCES operations (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (operation_id, content_sha256),  -- a retried job never duplicates its evidence
  UNIQUE (id, workspace_id)
);
CREATE INDEX evidence_asset_idx ON evidence (asset_id, collected_at DESC);
CREATE INDEX evidence_operation_idx ON evidence (operation_id);

CREATE TABLE asset_relationships (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id   uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  from_asset_id  uuid NOT NULL,
  to_asset_id    uuid NOT NULL,
  rel_type       relationship_type NOT NULL,
  status         relationship_status NOT NULL DEFAULT 'observed',
  confidence     confidence_level NOT NULL,
  evidence_id    uuid,
  rule_id        text NOT NULL,
  first_seen_at  timestamptz NOT NULL DEFAULT now(),
  last_seen_at   timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (from_asset_id, workspace_id) REFERENCES assets (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (to_asset_id, workspace_id) REFERENCES assets (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (evidence_id, workspace_id) REFERENCES evidence (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (from_asset_id, to_asset_id, rel_type),
  CHECK (from_asset_id <> to_asset_id)
);
CREATE INDEX asset_relationships_to_idx ON asset_relationships (to_asset_id);

CREATE TABLE worker_heartbeats (
  worker_id     text PRIMARY KEY CHECK (length(worker_id) <= 200),
  version       text NOT NULL,
  last_seen_at  timestamptz NOT NULL DEFAULT now()
);

-- updated_at ----------------------------------------------------------------

CREATE TRIGGER assets_updated_at BEFORE UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION nf_set_updated_at();
CREATE TRIGGER scopes_updated_at BEFORE UPDATE ON scopes FOR EACH ROW EXECUTE FUNCTION nf_set_updated_at();
CREATE TRIGGER operations_updated_at BEFORE UPDATE ON operations FOR EACH ROW EXECUTE FUNCTION nf_set_updated_at();

-- Row-level security ------------------------------------------------------------

ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE scope_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE scope_exclusions ENABLE ROW LEVEL SECURITY;
ALTER TABLE operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_relationships ENABLE ROW LEVEL SECURITY;

CREATE POLICY assets_tenant ON assets USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
CREATE POLICY scopes_tenant ON scopes USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
CREATE POLICY scope_targets_tenant ON scope_targets USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
CREATE POLICY scope_exclusions_tenant ON scope_exclusions USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
CREATE POLICY operations_tenant ON operations USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
CREATE POLICY evidence_tenant ON evidence USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
CREATE POLICY asset_relationships_tenant ON asset_relationships USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
-- The worker must see the queue across workspaces to claim jobs; it then sets the job's
-- workspace context, so every other table stays tenant-limited for it too.
CREATE POLICY operations_worker_claim ON operations TO nightfall_worker USING (true) WITH CHECK (true);

-- Grants ----------------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE ON assets TO nightfall_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON scopes, scope_targets, scope_exclusions TO nightfall_app;
GRANT SELECT, INSERT, UPDATE ON operations TO nightfall_app;
GRANT SELECT ON evidence, asset_relationships, worker_heartbeats TO nightfall_app;

GRANT USAGE ON SCHEMA public TO nightfall_worker;
GRANT EXECUTE ON FUNCTION nf_current_workspace(), nf_current_user() TO nightfall_worker;
GRANT SELECT ON organizations, projects, scopes, scope_targets, scope_exclusions TO nightfall_worker;
GRANT SELECT, UPDATE ON operations TO nightfall_worker;
GRANT SELECT, INSERT, UPDATE ON assets, asset_relationships TO nightfall_worker;
GRANT SELECT, INSERT ON evidence TO nightfall_worker;
GRANT INSERT ON audit_events TO nightfall_worker;
GRANT SELECT, INSERT, UPDATE ON worker_heartbeats TO nightfall_worker;
"""

DOWNGRADE = r"""
DROP TABLE IF EXISTS worker_heartbeats, asset_relationships, evidence, operations,
  scope_exclusions, scope_targets, scopes, assets CASCADE;
DROP FUNCTION IF EXISTS nf_scope_entry_guard();
DROP FUNCTION IF EXISTS nf_scope_guard();
ALTER TABLE projects DROP CONSTRAINT IF EXISTS projects_id_workspace_uq;
DROP TYPE IF EXISTS relationship_status, relationship_type, confidence_level, evidence_kind,
  operation_status, risk_class, scope_entry_kind, scope_status, asset_ownership, asset_kind;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
