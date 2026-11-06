"""ATLAS v0: asset status and an insert-only asset history.

  * assets.status: unverified (default for everything a collector or a person registers),
    verified (a person confirmed it belongs to the organization) or retired (no longer in
    use). Only a signed-in person, through the app role, can change it; collectors and the
    lab and BLACKSITE roles cannot (trigger nf_asset_guard).
  * asset_history: one row per creation and per change of status, ownership or notes,
    written by trigger whatever role made the change. No role may update or delete it.
    Existing assets get a backfilled "created" row, marked recorded_by = 'migration'.

Revision ID: 0016
"""

from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TYPE asset_status AS ENUM ('unverified', 'verified', 'retired');
ALTER TABLE assets ADD COLUMN status asset_status NOT NULL DEFAULT 'unverified';

CREATE TABLE asset_history (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id   uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  asset_id       uuid NOT NULL,
  change         text NOT NULL CHECK (change IN ('created', 'status', 'ownership', 'notes')),
  old_value      text CHECK (length(old_value) <= 10000),
  new_value      text CHECK (length(new_value) <= 10000),
  actor_user_id  uuid REFERENCES users(id) ON DELETE RESTRICT,
  recorded_by    text NOT NULL CHECK (length(recorded_by) BETWEEN 1 AND 100),
  occurred_at    timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (asset_id, workspace_id) REFERENCES assets (id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX asset_history_asset_idx ON asset_history (asset_id, occurred_at DESC);
ALTER TABLE asset_history ENABLE ROW LEVEL SECURITY;
CREATE POLICY asset_history_tenant ON asset_history
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT ON asset_history TO nightfall_app;

-- Status is a human decision: only the app role, with a signed-in user on the transaction,
-- may set anything but the default. The schema owner (migrations, test fixtures) is exempt.
CREATE FUNCTION nf_asset_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  is_owner boolean := pg_has_role(current_user,
    (SELECT relowner FROM pg_class WHERE oid = 'assets'::regclass), 'MEMBER');
  person boolean := current_user = 'nightfall_app'
    AND coalesce(current_setting('app.user_id', true), '') <> '';
BEGIN
  IF (TG_OP = 'INSERT' AND NEW.status <> 'unverified')
     OR (TG_OP = 'UPDATE' AND NEW.status IS DISTINCT FROM OLD.status) THEN
    IF NOT (person OR is_owner) THEN
      RAISE EXCEPTION 'only a person can change an asset''s status'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER assets_guard BEFORE INSERT OR UPDATE ON assets
  FOR EACH ROW EXECUTE FUNCTION nf_asset_guard();

-- History is written by the database, so no writer can skip it; it runs as the owner
-- because no other role may insert into asset_history.
CREATE FUNCTION nf_asset_history() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  actor uuid := nullif(current_setting('app.user_id', true), '')::uuid;
  who text := session_user;
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO asset_history (workspace_id, asset_id, change, new_value, actor_user_id, recorded_by)
      VALUES (NEW.workspace_id, NEW.id, 'created', NEW.source, actor, who);
    RETURN NULL;
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    INSERT INTO asset_history (workspace_id, asset_id, change, old_value, new_value, actor_user_id, recorded_by)
      VALUES (NEW.workspace_id, NEW.id, 'status', OLD.status::text, NEW.status::text, actor, who);
  END IF;
  IF NEW.ownership IS DISTINCT FROM OLD.ownership THEN
    INSERT INTO asset_history (workspace_id, asset_id, change, old_value, new_value, actor_user_id, recorded_by)
      VALUES (NEW.workspace_id, NEW.id, 'ownership', OLD.ownership::text, NEW.ownership::text, actor, who);
  END IF;
  IF NEW.notes IS DISTINCT FROM OLD.notes THEN
    INSERT INTO asset_history (workspace_id, asset_id, change, old_value, new_value, actor_user_id, recorded_by)
      VALUES (NEW.workspace_id, NEW.id, 'notes', OLD.notes, NEW.notes, actor, who);
  END IF;
  RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION nf_asset_history() FROM PUBLIC;
CREATE TRIGGER assets_history AFTER INSERT OR UPDATE ON assets
  FOR EACH ROW EXECUTE FUNCTION nf_asset_history();

INSERT INTO asset_history (workspace_id, asset_id, change, new_value, recorded_by, occurred_at)
  SELECT workspace_id, id, 'created', source, 'migration', created_at FROM assets;
"""

DOWNGRADE = r"""
DROP TRIGGER assets_history ON assets;
DROP TRIGGER assets_guard ON assets;
DROP FUNCTION nf_asset_history();
DROP FUNCTION nf_asset_guard();
DROP TABLE asset_history;
ALTER TABLE assets DROP COLUMN status;
DROP TYPE asset_status;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
