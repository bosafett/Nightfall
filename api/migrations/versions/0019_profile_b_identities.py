"""BLACK OPS Profile B step 2: designated test identities and run gates (design G2-G5).

  * test_identities: accounts that exist for testing, each bound to one target origin, with
    the owner's attestation. The credential is sealed to the self-hosted worker's public key
    by the API; only the worker holds the private key. The app role may write the sealed
    column but never read it (column-level grants); only the worker role can select it.
    An identity can only be retired, never edited or revived. Lockout testing is out of v1
    (owner decision 4), enforced by a CHECK.
  * playbook_runs: profile 'validation' (Profile B) is now a value the schema accepts, but
    only on a normal (non-lab) scope, with at least one passing proof-of-control check of
    that same scope version made in the last 24 hours, and only with active identities of
    the same workspace whose origin is the run's target (trigger). Nothing can launch such
    a run yet: the catalog has no Profile B playbook (step 3).

Revision ID: 0019
"""

from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TABLE test_identities (
  id                    uuid PRIMARY KEY,
  workspace_id          uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  origin                text NOT NULL CHECK (origin ~ '^https://[a-z0-9.-]{1,253}(:[0-9]{1,5})?$'),
  label                 text NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
  role_description      text NOT NULL DEFAULT '' CHECK (length(role_description) <= 500),
  login_method          text NOT NULL CHECK (login_method IN ('form', 'basic')),
  login_path            text NOT NULL DEFAULT '/'
                        CHECK (login_path ~ '^/[^\s]*$' AND length(login_path) <= 500),
  secret_sealed         bytea NOT NULL CHECK (length(secret_sealed) BETWEEN 60 AND 4096),
  attestation           text NOT NULL CHECK (length(attestation) BETWEEN 1 AND 1000),
  attested_by_user_id   uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  attested_at           timestamptz NOT NULL DEFAULT now(),
  lockout_test_allowed  boolean NOT NULL DEFAULT false CHECK (lockout_test_allowed = false),
  retired_at            timestamptz,
  retired_by_user_id    uuid REFERENCES users(id) ON DELETE RESTRICT,
  created_at            timestamptz NOT NULL DEFAULT now(),
  CHECK ((retired_at IS NULL) = (retired_by_user_id IS NULL)),
  UNIQUE (id, workspace_id)
);
CREATE UNIQUE INDEX test_identities_active_label_uq
  ON test_identities (workspace_id, origin, label) WHERE retired_at IS NULL;
ALTER TABLE test_identities ENABLE ROW LEVEL SECURITY;
CREATE POLICY test_identities_tenant ON test_identities
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
-- The API may write the sealed credential but never read it back.
GRANT SELECT (id, workspace_id, origin, label, role_description, login_method, login_path,
              attestation, attested_by_user_id, attested_at, lockout_test_allowed,
              retired_at, retired_by_user_id, created_at) ON test_identities TO nightfall_app;
GRANT INSERT ON test_identities TO nightfall_app;
GRANT UPDATE (retired_at, retired_by_user_id) ON test_identities TO nightfall_app;
GRANT SELECT ON test_identities TO nightfall_worker;

CREATE FUNCTION nf_test_identity_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'a retired test identity cannot change' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER test_identities_guard BEFORE UPDATE ON test_identities
  FOR EACH ROW EXECUTE FUNCTION nf_test_identity_guard();

-- The (non-lab) worker re-checks a Profile B run's gates before sending anything.
GRANT SELECT ON playbook_runs TO nightfall_worker;

ALTER TABLE playbook_runs ADD COLUMN identity_ids uuid[] NOT NULL DEFAULT '{}';
ALTER TABLE playbook_runs ADD COLUMN ownership_check_ids uuid[] NOT NULL DEFAULT '{}';
ALTER TABLE playbook_runs DROP CONSTRAINT playbook_runs_profile_check;
ALTER TABLE playbook_runs ADD CONSTRAINT playbook_runs_profile_check
  CHECK (profile IN ('live', 'lab', 'validation'));
ALTER TABLE playbook_runs ADD CONSTRAINT playbook_runs_validation_inputs CHECK (
  (profile = 'validation' AND cardinality(ownership_check_ids) >= 1
     AND cardinality(identity_ids) <= 5)
  OR (profile <> 'validation' AND cardinality(ownership_check_ids) = 0
     AND cardinality(identity_ids) = 0)
);

CREATE OR REPLACE FUNCTION nf_playbook_run_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE lab boolean; scope_project uuid; target_origin text;
BEGIN
  SELECT is_lab, project_id INTO lab, scope_project FROM scopes WHERE id = NEW.scope_id;
  IF scope_project IS DISTINCT FROM NEW.project_id THEN
    RAISE EXCEPTION 'playbook run scope belongs to another project' USING ERRCODE = 'check_violation';
  END IF;
  IF lab IS DISTINCT FROM (NEW.profile = 'lab') THEN
    RAISE EXCEPTION 'playbook run profile does not match its scope' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.profile = 'validation' THEN
    -- G1: every listed proof passed, for this scope version, in the last 24 hours.
    IF (SELECT count(*) FROM ownership_checks c
          WHERE c.id = ANY (NEW.ownership_check_ids) AND c.workspace_id = NEW.workspace_id
            AND c.scope_id = NEW.scope_id AND c.ok AND c.checked_at > now() - interval '24 hours')
       <> cardinality(NEW.ownership_check_ids) THEN
      RAISE EXCEPTION 'Profile B needs a fresh proof of control for this scope version'
        USING ERRCODE = 'check_violation';
    END IF;
    -- G2: only active identities of this workspace whose origin is the target.
    IF (SELECT count(*) FROM test_identities i
          WHERE i.id = ANY (NEW.identity_ids) AND i.workspace_id = NEW.workspace_id
            AND i.retired_at IS NULL
            AND split_part(substr(i.origin, 9), ':', 1) = NEW.target_value)
       <> cardinality(NEW.identity_ids) THEN
      RAISE EXCEPTION 'Profile B identities must be active and belong to the target'
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;
"""

DOWNGRADE = r"""
CREATE OR REPLACE FUNCTION nf_playbook_run_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE lab boolean; scope_project uuid;
BEGIN
  SELECT is_lab, project_id INTO lab, scope_project FROM scopes WHERE id = NEW.scope_id;
  IF scope_project IS DISTINCT FROM NEW.project_id THEN
    RAISE EXCEPTION 'playbook run scope belongs to another project' USING ERRCODE = 'check_violation';
  END IF;
  IF lab IS DISTINCT FROM (NEW.profile = 'lab') THEN
    RAISE EXCEPTION 'playbook run profile does not match its scope' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
ALTER TABLE playbook_runs DROP CONSTRAINT playbook_runs_validation_inputs;
ALTER TABLE playbook_runs DROP CONSTRAINT playbook_runs_profile_check;
-- NOT VALID: enforced for new rows; Profile B runs recorded before the downgrade stay.
ALTER TABLE playbook_runs ADD CONSTRAINT playbook_runs_profile_check
  CHECK (profile IN ('live', 'lab')) NOT VALID;
ALTER TABLE playbook_runs DROP COLUMN ownership_check_ids;
ALTER TABLE playbook_runs DROP COLUMN identity_ids;
REVOKE SELECT ON playbook_runs FROM nightfall_worker;
DROP TRIGGER test_identities_guard ON test_identities;
DROP FUNCTION nf_test_identity_guard();
DROP TABLE test_identities;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
