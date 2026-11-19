"""SHIELD v4 step 4b (docs/designs/2026-11-shield-v4-host-network-monitoring.md §5-7): host
alerts, file integrity and value changes.

  * shield_host_state / shield_host_changes: new group 'files' (sha256 of a fixed list of
    sensitive files), and a 'changed' action with the previous item, so a value change under the
    same key (a file's hash, a posture check going from OK to not OK) is recorded.
  * shield_host_alerts: one alert per security-relevant host change (new account, new
    administrator, new SSH key, new listening service, new persistence item, posture worse, a
    watched file changed). Kept apart from shield_intrusion_alerts, whose source address and
    dedup index GUARD relies on (design §6, as built). correlated_alert_id links an attack alert
    on the same machine shortly before: a hypothesis ("possible compromise, unconfirmed"), never
    a finding. Detection only: nothing here can block or change anything.

Revision ID: 0027
"""

from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None

UPGRADE = r"""
ALTER TABLE shield_host_state DROP CONSTRAINT shield_host_state_grp_check;
ALTER TABLE shield_host_state ADD CONSTRAINT shield_host_state_grp_check CHECK (grp IN
  ('accounts', 'admins', 'ssh_keys', 'listeners', 'persistence', 'software', 'posture', 'files'));
ALTER TABLE shield_host_changes DROP CONSTRAINT shield_host_changes_grp_check;
ALTER TABLE shield_host_changes ADD CONSTRAINT shield_host_changes_grp_check CHECK (grp IN
  ('accounts', 'admins', 'ssh_keys', 'listeners', 'persistence', 'software', 'posture', 'files'));
ALTER TABLE shield_host_changes DROP CONSTRAINT shield_host_changes_action_check;
ALTER TABLE shield_host_changes ADD CONSTRAINT shield_host_changes_action_check
  CHECK (action IN ('added', 'removed', 'changed'));
ALTER TABLE shield_host_changes ADD COLUMN previous jsonb
  CONSTRAINT shield_host_changes_previous_object
  CHECK (previous IS NULL OR jsonb_typeof(previous) = 'object');
ALTER TABLE shield_host_changes ADD CONSTRAINT shield_host_changes_previous_iff_changed
  CHECK ((action = 'changed') = (previous IS NOT NULL));
ALTER TABLE shield_host_changes ADD CONSTRAINT shield_host_changes_id_ws UNIQUE (id, workspace_id);

CREATE TABLE shield_host_alerts (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id         uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  sensor_id            uuid NOT NULL,
  category             text NOT NULL CHECK (category IN ('new_account', 'new_admin', 'new_ssh_key',
                         'new_listener', 'new_persistence', 'posture_degraded', 'file_changed')),
  severity             severity NOT NULL,
  title                text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
  change_id            uuid,
  correlated_alert_id  uuid,
  observed_at          timestamptz NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  state                text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'acknowledged', 'resolved')),
  acknowledged_at      timestamptz,
  CHECK ((state = 'open') OR (acknowledged_at IS NOT NULL)),
  FOREIGN KEY (sensor_id, workspace_id) REFERENCES shield_sensors (id, workspace_id) ON DELETE RESTRICT,
  -- The change log is kept 90 days; an alert outlives its change row.
  FOREIGN KEY (change_id, workspace_id) REFERENCES shield_host_changes (id, workspace_id) ON DELETE SET NULL (change_id),
  FOREIGN KEY (correlated_alert_id, workspace_id)
    REFERENCES shield_intrusion_alerts (id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX shield_host_alerts_sensor_idx ON shield_host_alerts (sensor_id, state, created_at DESC);
CREATE INDEX shield_host_alerts_ws_idx ON shield_host_alerts (workspace_id, state, created_at DESC);
ALTER TABLE shield_host_alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY shield_host_alerts_tenant ON shield_host_alerts
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON shield_host_alerts TO nightfall_app;
GRANT UPDATE (state, acknowledged_at) ON shield_host_alerts TO nightfall_app;
"""

DOWNGRADE = r"""
DROP TABLE shield_host_alerts;
ALTER TABLE shield_host_changes DROP CONSTRAINT shield_host_changes_id_ws;
ALTER TABLE shield_host_changes DROP CONSTRAINT shield_host_changes_previous_iff_changed;
ALTER TABLE shield_host_changes DROP COLUMN previous;
DELETE FROM shield_host_changes WHERE action = 'changed' OR grp = 'files';
DELETE FROM shield_host_state WHERE grp = 'files';
ALTER TABLE shield_host_changes DROP CONSTRAINT shield_host_changes_action_check;
ALTER TABLE shield_host_changes ADD CONSTRAINT shield_host_changes_action_check
  CHECK (action IN ('added', 'removed'));
ALTER TABLE shield_host_changes DROP CONSTRAINT shield_host_changes_grp_check;
ALTER TABLE shield_host_changes ADD CONSTRAINT shield_host_changes_grp_check CHECK (grp IN
  ('accounts', 'admins', 'ssh_keys', 'listeners', 'persistence', 'software', 'posture'));
ALTER TABLE shield_host_state DROP CONSTRAINT shield_host_state_grp_check;
ALTER TABLE shield_host_state ADD CONSTRAINT shield_host_state_grp_check CHECK (grp IN
  ('accounts', 'admins', 'ssh_keys', 'listeners', 'persistence', 'software', 'posture'));
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
