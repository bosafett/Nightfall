"""BLACK OPS Profile B step 1: proof of control over a target (design G1, review F3).

  * ownership_claims: a hostname the owner says they control, with the method used to
    prove it (a DNS TXT record or a file on the web server) and the SHA-256 of a random
    token. The token itself is shown once and never stored. Only the owner creates or
    retires a claim (enforced by the API); the app role can change nothing but the
    retirement columns, and a retired claim can't be revived (trigger).
  * ownership_checks: one insert-only row per check of a claim against a scope version,
    with what was observed (DNS answers or the HTTP response) and its SHA-256. No role
    may update or delete a check.

Nothing here enables Profile B: the catalog still refuses it.

Revision ID: 0017
"""

from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TYPE ownership_method AS ENUM ('dns', 'file');

CREATE TABLE ownership_claims (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  name                text NOT NULL CHECK (length(name) BETWEEN 1 AND 253),
  method              ownership_method NOT NULL,
  token_sha256        bytea NOT NULL CHECK (length(token_sha256) = 32),
  created_by_user_id  uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at          timestamptz NOT NULL DEFAULT now(),
  retired_at          timestamptz,
  retired_by_user_id  uuid REFERENCES users(id) ON DELETE RESTRICT,
  CHECK ((retired_at IS NULL) = (retired_by_user_id IS NULL)),
  UNIQUE (id, workspace_id)
);
CREATE UNIQUE INDEX ownership_claims_active_uq
  ON ownership_claims (workspace_id, name, method) WHERE retired_at IS NULL;
ALTER TABLE ownership_claims ENABLE ROW LEVEL SECURITY;
CREATE POLICY ownership_claims_tenant ON ownership_claims
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON ownership_claims TO nightfall_app;
GRANT UPDATE (retired_at, retired_by_user_id) ON ownership_claims TO nightfall_app;
GRANT SELECT ON ownership_claims TO nightfall_worker;

CREATE FUNCTION nf_ownership_claim_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'a retired ownership claim cannot change'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER ownership_claims_guard BEFORE UPDATE ON ownership_claims
  FOR EACH ROW EXECUTE FUNCTION nf_ownership_claim_guard();

CREATE TABLE ownership_checks (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id         uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  claim_id             uuid NOT NULL,
  scope_id             uuid NOT NULL,
  ok                   boolean NOT NULL,
  detail               text NOT NULL CHECK (length(detail) <= 1000),
  observation          jsonb NOT NULL,
  observation_sha256   bytea NOT NULL CHECK (length(observation_sha256) = 32),
  checked_by_user_id   uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  checked_at           timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (claim_id, workspace_id) REFERENCES ownership_claims (id, workspace_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (scope_id, workspace_id) REFERENCES scopes (id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX ownership_checks_claim_idx ON ownership_checks (claim_id, scope_id, checked_at DESC);
ALTER TABLE ownership_checks ENABLE ROW LEVEL SECURITY;
CREATE POLICY ownership_checks_tenant ON ownership_checks
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON ownership_checks TO nightfall_app;
GRANT SELECT ON ownership_checks TO nightfall_worker;
"""

DOWNGRADE = r"""
DROP TABLE ownership_checks;
DROP TRIGGER ownership_claims_guard ON ownership_claims;
DROP FUNCTION nf_ownership_claim_guard();
DROP TABLE ownership_claims;
DROP TYPE ownership_method;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
