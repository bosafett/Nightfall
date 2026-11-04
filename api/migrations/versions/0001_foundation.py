"""Phase 1 foundation: identity, tenancy, target registry (orgs/projects), audit.

Tenant isolation is enforced twice: API queries are scoped by workspace, and
Postgres row-level security (keyed on transaction-local settings app.workspace_id
and app.user_id) makes a forgotten filter return nothing instead of another
tenant's rows. The API connects as nightfall_app, which is subject to RLS.

Revision ID: 0001
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE FUNCTION nf_current_workspace() RETURNS uuid
  LANGUAGE sql STABLE AS
  $$ SELECT nullif(current_setting('app.workspace_id', true), '')::uuid $$;

CREATE FUNCTION nf_current_user() RETURNS uuid
  LANGUAGE sql STABLE AS
  $$ SELECT nullif(current_setting('app.user_id', true), '')::uuid $$;

CREATE FUNCTION nf_set_updated_at() RETURNS trigger
  LANGUAGE plpgsql AS
  $$ BEGIN NEW.updated_at = now(); RETURN NEW; END $$;

CREATE TYPE workspace_role AS ENUM ('owner', 'admin', 'operator', 'analyst', 'viewer');
CREATE TYPE auth_token_purpose AS ENUM ('invite', 'password_reset');
CREATE TYPE actor_type AS ENUM ('user', 'agent', 'system');
CREATE TYPE assessment_type AS ENUM (
  'reconnaissance', 'security_assessment', 'ai_system_assessment', 'adversarial_simulation');
CREATE TYPE project_status AS ENUM ('planning', 'active', 'paused', 'completed', 'archived');

-- Identity ---------------------------------------------------------------

CREATE TABLE users (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email            text NOT NULL UNIQUE CHECK (email = lower(email) AND length(email) <= 320),
  display_name     text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
  password_hash    text NOT NULL,
  totp_secret_enc  bytea,
  mfa_enabled      boolean NOT NULL DEFAULT false,
  totp_last_step   bigint,
  is_disabled      boolean NOT NULL DEFAULT false,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CHECK (NOT mfa_enabled OR totp_secret_enc IS NOT NULL)
);

CREATE TABLE sessions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_sha256     bytea NOT NULL UNIQUE,
  created_at       timestamptz NOT NULL DEFAULT now(),
  last_seen_at     timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,
  revoked_at       timestamptz,
  mfa_verified_at  timestamptz,
  ip               text,
  user_agent       text
);
CREATE INDEX sessions_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;

-- Tenancy ----------------------------------------------------------------

CREATE TABLE workspaces (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE workspace_members (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  role          workspace_role NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, user_id)
);
CREATE INDEX workspace_members_user_idx ON workspace_members (user_id);

-- Single-use invite and password-reset links. Only the token's hash is stored.
CREATE TABLE auth_tokens (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  purpose             auth_token_purpose NOT NULL,
  token_sha256        bytea NOT NULL UNIQUE,
  workspace_id        uuid REFERENCES workspaces(id) ON DELETE RESTRICT,
  user_id             uuid REFERENCES users(id) ON DELETE CASCADE,
  email               text CHECK (email = lower(email)),
  role                workspace_role,
  created_by_user_id  uuid REFERENCES users(id) ON DELETE SET NULL,
  expires_at          timestamptz NOT NULL,
  used_at             timestamptz,
  revoked_at          timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  CHECK (purpose <> 'invite' OR (workspace_id IS NOT NULL AND email IS NOT NULL AND role IS NOT NULL)),
  CHECK (purpose <> 'password_reset' OR user_id IS NOT NULL)
);
CREATE INDEX auth_tokens_workspace_idx ON auth_tokens (workspace_id) WHERE used_at IS NULL AND revoked_at IS NULL;

-- Target registry --------------------------------------------------------

CREATE TABLE organizations (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  notes         text NOT NULL DEFAULT '' CHECK (length(notes) <= 10000),
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, workspace_id)
);
CREATE UNIQUE INDEX organizations_name_uq ON organizations (workspace_id, lower(name));

CREATE TABLE projects (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id     uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  organization_id  uuid NOT NULL,
  name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  description      text NOT NULL DEFAULT '' CHECK (length(description) <= 10000),
  assessment_type  assessment_type NOT NULL,
  status           project_status NOT NULL DEFAULT 'planning',
  started_at       timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  -- A project's organization must belong to the same workspace.
  FOREIGN KEY (organization_id, workspace_id)
    REFERENCES organizations (id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX projects_workspace_idx ON projects (workspace_id, status);
CREATE INDEX projects_org_idx ON projects (organization_id);

-- Audit (append-only for the app role) -----------------------------------

CREATE TABLE audit_events (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid REFERENCES workspaces(id) ON DELETE RESTRICT,
  actor_type    actor_type NOT NULL,
  actor_id      uuid,
  action        text NOT NULL,
  entity_type   text,
  entity_id     uuid,
  data          jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip            text,
  user_agent    text,
  occurred_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_workspace_idx ON audit_events (workspace_id, occurred_at DESC);
CREATE INDEX audit_events_actor_idx ON audit_events (actor_id, occurred_at DESC);

-- updated_at triggers ----------------------------------------------------

CREATE TRIGGER users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION nf_set_updated_at();
CREATE TRIGGER workspaces_updated_at BEFORE UPDATE ON workspaces
  FOR EACH ROW EXECUTE FUNCTION nf_set_updated_at();
CREATE TRIGGER workspace_members_updated_at BEFORE UPDATE ON workspace_members
  FOR EACH ROW EXECUTE FUNCTION nf_set_updated_at();
CREATE TRIGGER organizations_updated_at BEFORE UPDATE ON organizations
  FOR EACH ROW EXECUTE FUNCTION nf_set_updated_at();
CREATE TRIGGER projects_updated_at BEFORE UPDATE ON projects
  FOR EACH ROW EXECUTE FUNCTION nf_set_updated_at();

-- Number of workspaces a user belongs to, across tenants. SECURITY DEFINER so
-- the API can refuse cross-tenant password resets without seeing other tenants.
CREATE FUNCTION nf_user_workspace_count(target uuid) RETURNS integer
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT count(*)::int FROM workspace_members WHERE user_id = target $$;
REVOKE ALL ON FUNCTION nf_user_workspace_count(uuid) FROM PUBLIC;

-- Row-level security ------------------------------------------------------

ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspaces_select ON workspaces FOR SELECT
  USING (id = nf_current_workspace() OR EXISTS (
    SELECT 1 FROM workspace_members m
    WHERE m.workspace_id = workspaces.id AND m.user_id = nf_current_user()));
CREATE POLICY workspaces_update ON workspaces FOR UPDATE
  USING (id = nf_current_workspace()) WITH CHECK (id = nf_current_workspace());

ALTER TABLE workspace_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY members_select ON workspace_members FOR SELECT
  USING (workspace_id = nf_current_workspace() OR user_id = nf_current_user());
CREATE POLICY members_insert ON workspace_members FOR INSERT
  WITH CHECK (workspace_id = nf_current_workspace());
CREATE POLICY members_update ON workspace_members FOR UPDATE
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
CREATE POLICY members_delete ON workspace_members FOR DELETE
  USING (workspace_id = nf_current_workspace());

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY organizations_tenant ON organizations
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());

ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_tenant ON projects
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_select ON audit_events FOR SELECT
  USING (workspace_id = nf_current_workspace());
CREATE POLICY audit_insert ON audit_events FOR INSERT
  WITH CHECK (workspace_id IS NULL OR workspace_id = nf_current_workspace());

-- Grants for the API role ---------------------------------------------------

GRANT USAGE ON SCHEMA public TO nightfall_app;
GRANT EXECUTE ON FUNCTION nf_current_workspace(), nf_current_user(),
  nf_user_workspace_count(uuid) TO nightfall_app;
GRANT SELECT, INSERT, UPDATE ON users, sessions, auth_tokens TO nightfall_app;
GRANT SELECT, UPDATE ON workspaces TO nightfall_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON workspace_members TO nightfall_app;
GRANT SELECT, INSERT, UPDATE ON organizations, projects TO nightfall_app;
GRANT SELECT, INSERT ON audit_events TO nightfall_app;
"""

DOWNGRADE = r"""
DROP TABLE IF EXISTS audit_events, projects, organizations, auth_tokens,
  workspace_members, workspaces, sessions, users CASCADE;
DROP FUNCTION IF EXISTS nf_user_workspace_count(uuid);
DROP FUNCTION IF EXISTS nf_set_updated_at();
DROP FUNCTION IF EXISTS nf_current_user();
DROP FUNCTION IF EXISTS nf_current_workspace();
DROP TYPE IF EXISTS project_status, assessment_type, actor_type, auth_token_purpose, workspace_role;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
