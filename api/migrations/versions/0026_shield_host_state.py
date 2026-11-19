"""SHIELD v4 step 4a (docs/designs/2026-11-shield-v4-host-network-monitoring.md §5-6): host state
and its change log, from the osquery module of janus-sensor.

  * shield_host_state: per sensor and group (accounts, admins, ssh_keys, listeners, persistence,
    software, posture), the latest items the machine reported. Replaced by a full snapshot, and
    kept current between snapshots by the changes below. Items are untrusted data, size-capped,
    with only the columns the fixed query pack allows (the API drops anything else).
  * shield_host_changes: append-only log of what was added or removed, with the time the machine
    observed it kept apart from ingestion. Kept 90 days (owner decision 4): the app role can't
    delete, and nf_purge_host_changes removes only this sensor's rows older than 90 days.

Nothing here can instruct a machine: JANUS never sends queries (design §4).

Revision ID: 0026
"""

from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TABLE shield_host_state (
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  sensor_id     uuid NOT NULL,
  grp           text NOT NULL CHECK (grp IN ('accounts', 'admins', 'ssh_keys', 'listeners', 'persistence', 'software', 'posture')),
  items         jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(items) = 'array'),
  item_count    integer NOT NULL DEFAULT 0 CHECK (item_count BETWEEN 0 AND 5000),
  observed_at   timestamptz NOT NULL,
  ingested_at   timestamptz NOT NULL DEFAULT now(),
  snapshot_at   timestamptz,
  PRIMARY KEY (sensor_id, grp),
  FOREIGN KEY (sensor_id, workspace_id) REFERENCES shield_sensors (id, workspace_id) ON DELETE RESTRICT
);
ALTER TABLE shield_host_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY shield_host_state_tenant ON shield_host_state
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON shield_host_state TO nightfall_app;
GRANT UPDATE (items, item_count, observed_at, ingested_at, snapshot_at) ON shield_host_state TO nightfall_app;

CREATE TABLE shield_host_changes (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  sensor_id     uuid NOT NULL,
  grp           text NOT NULL CHECK (grp IN ('accounts', 'admins', 'ssh_keys', 'listeners', 'persistence', 'software', 'posture')),
  action        text NOT NULL CHECK (action IN ('added', 'removed')),
  item_key      text NOT NULL CHECK (length(item_key) BETWEEN 1 AND 500),
  item          jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(item) = 'object'),
  observed_at   timestamptz NOT NULL,
  ingested_at   timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (sensor_id, workspace_id) REFERENCES shield_sensors (id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX shield_host_changes_sensor_idx ON shield_host_changes (sensor_id, ingested_at DESC);
ALTER TABLE shield_host_changes ENABLE ROW LEVEL SECURITY;
CREATE POLICY shield_host_changes_tenant ON shield_host_changes
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON shield_host_changes TO nightfall_app;

-- Retention (90 days, fixed): the only way rows leave the log. Scoped to one sensor of the
-- caller's workspace; the interval can't be passed in.
CREATE FUNCTION nf_purge_host_changes(p_sensor uuid) RETURNS integer
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE n integer;
BEGIN
  DELETE FROM shield_host_changes
   WHERE sensor_id = p_sensor AND workspace_id = nf_current_workspace()
     AND ingested_at < now() - interval '90 days';
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;
REVOKE ALL ON FUNCTION nf_purge_host_changes(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nf_purge_host_changes(uuid) TO nightfall_app;
"""

DOWNGRADE = r"""
DROP FUNCTION nf_purge_host_changes(uuid);
DROP TABLE shield_host_changes;
DROP TABLE shield_host_state;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
