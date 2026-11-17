"""SHIELD v3 phase 2 (docs/designs/2026-11-shield-v3-intrusion-detection.md §3-4): sensors,
standing response authorization, and time-limited blocks.

  * shield_sensors: a CrowdSec sensor on a machine the owner runs. Authenticated by its own
    key (only the sha256 is stored; the key is shown once). Revocable; never deleted. The
    sensor connects outbound to JANUS; JANUS never connects to it and exposes nothing that
    runs anything there.
  * shield_response_authorizations: the owner's standing authorization for the automatic
    tier (which sensors, which actions, the longest block and the default, a per-hour cap,
    a 90-day expiry). Insert-only apart from ending it; at most one live row per workspace.
  * shield_response_settings: the kill switch. automatic_paused = true stops every automatic
    block at once; sensors fall back to alert-only.
  * shield_block_allowlist: addresses that must never be blocked (the owner's own, the lab,
    Neon, Vercel, GitHub, the sensor's route). A block that would cover one is refused by a
    database trigger and an alert is raised instead. Seeded empty; the owner fills it in.
  * shield_intrusion_alerts: alerts a sensor sends (a CrowdSec scenario on a source address).
    Event time is kept apart from ingestion time. raw is untrusted data, never instructions.
    One open alert per (sensor, source, category); a repeat raises its count.
  * shield_blocks: a time-limited block, automatic (under a live authorization) or approved
    (by a person). Every block expires, is liftable in one click, and records when the sensor
    applied and removed it. nf_shield_block_guard enforces the hard invariants: the allow list
    (both tiers), and for the automatic tier that a live authorization covers the sensor and
    action and the duration is within its limit. The cap and kill switch are policy enforced in
    the application (they fall back to alert-only); the allow list and duration are invariants
    enforced here so no violating block can exist even if the application is wrong.

Revision ID: 0025
"""

from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None

UPGRADE = r"""
-- Sensors ---------------------------------------------------------------------------------
CREATE TABLE shield_sensors (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  name                text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  key_prefix          text NOT NULL CHECK (length(key_prefix) BETWEEN 1 AND 16),
  key_sha256          bytea NOT NULL UNIQUE,
  created_by_user_id  uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at          timestamptz NOT NULL DEFAULT now(),
  last_seen_at        timestamptz,
  agent_version       text NOT NULL DEFAULT '' CHECK (length(agent_version) <= 40),
  revoked_at          timestamptz,
  revoked_by_user_id  uuid REFERENCES users(id) ON DELETE RESTRICT,
  revoked_reason      text NOT NULL DEFAULT '' CHECK (length(revoked_reason) <= 500),
  CHECK ((revoked_at IS NULL) = (revoked_by_user_id IS NULL)),
  CHECK (revoked_at IS NOT NULL OR revoked_reason = ''),
  UNIQUE (id, workspace_id)
);
CREATE INDEX shield_sensors_workspace_idx ON shield_sensors (workspace_id, created_at DESC);
ALTER TABLE shield_sensors ENABLE ROW LEVEL SECURITY;
CREATE POLICY shield_sensors_tenant ON shield_sensors
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON shield_sensors TO nightfall_app;
GRANT UPDATE (last_seen_at, agent_version, revoked_at, revoked_by_user_id, revoked_reason)
  ON shield_sensors TO nightfall_app;

-- A sensor authenticates by key before any workspace context exists, so the lookup runs in a
-- SECURITY DEFINER function that returns only a live (non-revoked) sensor's id and workspace.
CREATE FUNCTION nf_sensor_authenticate(key_hash bytea)
  RETURNS TABLE (sensor_id uuid, workspace_id uuid)
  LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT id, workspace_id FROM shield_sensors
  WHERE key_sha256 = key_hash AND revoked_at IS NULL
$$;
REVOKE ALL ON FUNCTION nf_sensor_authenticate(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nf_sensor_authenticate(bytea) TO nightfall_app;

-- Standing response authorization --------------------------------------------------------
CREATE TABLE shield_response_authorizations (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id           uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  sensor_ids             uuid[] NOT NULL CHECK (cardinality(sensor_ids) BETWEEN 1 AND 50),
  actions                text[] NOT NULL
                         CHECK (cardinality(actions) >= 1 AND actions <@ ARRAY['block_ip']),
  max_block_seconds      integer NOT NULL DEFAULT 3600 CHECK (max_block_seconds BETWEEN 60 AND 14400),
  default_block_seconds  integer NOT NULL DEFAULT 3600 CHECK (default_block_seconds BETWEEN 60 AND 14400),
  per_hour_cap           integer NOT NULL DEFAULT 50 CHECK (per_hour_cap BETWEEN 1 AND 1000),
  authorized_by_user_id  uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  authorized_at          timestamptz NOT NULL DEFAULT now(),
  expires_at             timestamptz NOT NULL,
  ended_at               timestamptz,
  ended_reason           text CHECK (ended_reason IN ('revoked', 'expired', 'renewed', 'superseded')),
  CHECK (default_block_seconds <= max_block_seconds),
  CHECK (expires_at > authorized_at),
  CHECK (expires_at <= authorized_at + interval '90 days'),
  CHECK ((ended_at IS NULL) = (ended_reason IS NULL)),
  UNIQUE (id, workspace_id)
);
CREATE UNIQUE INDEX shield_resp_auth_one_live
  ON shield_response_authorizations (workspace_id) WHERE ended_at IS NULL;
ALTER TABLE shield_response_authorizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY shield_resp_auth_tenant ON shield_response_authorizations
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON shield_response_authorizations TO nightfall_app;
GRANT UPDATE (ended_at, ended_reason) ON shield_response_authorizations TO nightfall_app;

-- Insert-only apart from ending it; an ended authorization is frozen.
CREATE FUNCTION nf_resp_auth_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.ended_at IS NOT NULL THEN
    RAISE EXCEPTION 'an ended response authorization cannot change' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.sensor_ids IS DISTINCT FROM OLD.sensor_ids
     OR NEW.actions IS DISTINCT FROM OLD.actions
     OR NEW.max_block_seconds IS DISTINCT FROM OLD.max_block_seconds
     OR NEW.default_block_seconds IS DISTINCT FROM OLD.default_block_seconds
     OR NEW.per_hour_cap IS DISTINCT FROM OLD.per_hour_cap
     OR NEW.authorized_by_user_id IS DISTINCT FROM OLD.authorized_by_user_id
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'a response authorization can only be ended, not edited'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER shield_resp_auth_guard BEFORE UPDATE ON shield_response_authorizations
  FOR EACH ROW EXECUTE FUNCTION nf_resp_auth_guard();

-- Kill switch ----------------------------------------------------------------------------
CREATE TABLE shield_response_settings (
  workspace_id       uuid PRIMARY KEY REFERENCES workspaces(id) ON DELETE RESTRICT,
  automatic_paused   boolean NOT NULL DEFAULT false,
  paused_by_user_id  uuid REFERENCES users(id) ON DELETE RESTRICT,
  paused_at          timestamptz,
  pause_reason       text NOT NULL DEFAULT '' CHECK (length(pause_reason) <= 500),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CHECK (automatic_paused = (paused_at IS NOT NULL)),
  CHECK (automatic_paused OR (paused_by_user_id IS NULL AND pause_reason = ''))
);
ALTER TABLE shield_response_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY shield_resp_settings_tenant ON shield_response_settings
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON shield_response_settings TO nightfall_app;
GRANT UPDATE (automatic_paused, paused_by_user_id, paused_at, pause_reason, updated_at)
  ON shield_response_settings TO nightfall_app;

-- Allow list -----------------------------------------------------------------------------
CREATE TABLE shield_block_allowlist (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  cidr                cidr NOT NULL,
  note                text NOT NULL DEFAULT '' CHECK (length(note) <= 500),
  added_by_user_id    uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  added_at            timestamptz NOT NULL DEFAULT now(),
  removed_at          timestamptz,
  removed_by_user_id  uuid REFERENCES users(id) ON DELETE RESTRICT,
  CHECK ((removed_at IS NULL) = (removed_by_user_id IS NULL)),
  UNIQUE (id, workspace_id)
);
CREATE INDEX shield_allowlist_live_idx
  ON shield_block_allowlist (workspace_id) WHERE removed_at IS NULL;
ALTER TABLE shield_block_allowlist ENABLE ROW LEVEL SECURITY;
CREATE POLICY shield_allowlist_tenant ON shield_block_allowlist
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON shield_block_allowlist TO nightfall_app;
GRANT UPDATE (removed_at, removed_by_user_id) ON shield_block_allowlist TO nightfall_app;

-- Intrusion alerts from sensors ----------------------------------------------------------
CREATE TABLE shield_intrusion_alerts (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id      uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  sensor_id         uuid NOT NULL,
  scenario          text NOT NULL CHECK (length(scenario) BETWEEN 1 AND 200),
  category          text NOT NULL DEFAULT 'other'
                    CHECK (category IN ('ssh_bruteforce', 'web_scan', 'exploit_attempt',
                                        'http_bruteforce', 'other')),
  severity          severity NOT NULL,
  source            inet NOT NULL,
  count             integer NOT NULL DEFAULT 1 CHECK (count >= 1),
  event_time        timestamptz NOT NULL,
  last_event_time   timestamptz NOT NULL,
  ingested_at       timestamptz NOT NULL DEFAULT now(),
  raw               jsonb NOT NULL DEFAULT '{}'::jsonb,
  state             text NOT NULL DEFAULT 'open'
                    CHECK (state IN ('open', 'acknowledged', 'resolved')),
  acknowledged_at   timestamptz,
  incident_id       uuid,
  CHECK (last_event_time >= event_time),
  CHECK ((state = 'open') OR (acknowledged_at IS NOT NULL)),
  FOREIGN KEY (sensor_id, workspace_id) REFERENCES shield_sensors (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (incident_id, workspace_id) REFERENCES incidents (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (id, workspace_id)
);
CREATE UNIQUE INDEX shield_intrusion_one_open
  ON shield_intrusion_alerts (sensor_id, source, category) WHERE state = 'open';
CREATE INDEX shield_intrusion_workspace_idx
  ON shield_intrusion_alerts (workspace_id, state, last_event_time DESC);
ALTER TABLE shield_intrusion_alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY shield_intrusion_tenant ON shield_intrusion_alerts
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON shield_intrusion_alerts TO nightfall_app;
GRANT UPDATE (count, last_event_time, severity, scenario, raw, state, acknowledged_at, incident_id)
  ON shield_intrusion_alerts TO nightfall_app;

-- Blocks ---------------------------------------------------------------------------------
CREATE TABLE shield_blocks (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  sensor_id           uuid NOT NULL,
  target              cidr NOT NULL,
  tier                text NOT NULL CHECK (tier IN ('automatic', 'approved')),
  action              text NOT NULL DEFAULT 'block_ip' CHECK (action = 'block_ip'),
  reason              text NOT NULL DEFAULT '' CHECK (length(reason) <= 1000),
  authorization_id    uuid,
  approved_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
  alert_id            uuid,
  incident_id         uuid,
  created_at          timestamptz NOT NULL DEFAULT now(),
  expires_at          timestamptz NOT NULL,
  applied_at          timestamptz,
  removed_at          timestamptz,
  lifted_at           timestamptz,
  lifted_by_user_id   uuid REFERENCES users(id) ON DELETE RESTRICT,
  lifted_reason       text NOT NULL DEFAULT '' CHECK (length(lifted_reason) <= 500),
  CHECK (expires_at > created_at),
  CHECK ((tier = 'automatic') = (authorization_id IS NOT NULL)),
  CHECK ((tier = 'approved') = (approved_by_user_id IS NOT NULL)),
  CHECK ((lifted_at IS NULL) = (lifted_by_user_id IS NULL)),
  CHECK (lifted_at IS NOT NULL OR lifted_reason = ''),
  FOREIGN KEY (sensor_id, workspace_id) REFERENCES shield_sensors (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (authorization_id, workspace_id)
    REFERENCES shield_response_authorizations (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (alert_id, workspace_id)
    REFERENCES shield_intrusion_alerts (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (incident_id, workspace_id) REFERENCES incidents (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (id, workspace_id)
);
CREATE INDEX shield_blocks_active_idx ON shield_blocks (workspace_id, sensor_id, expires_at)
  WHERE lifted_at IS NULL AND removed_at IS NULL;
ALTER TABLE shield_blocks ENABLE ROW LEVEL SECURITY;
CREATE POLICY shield_blocks_tenant ON shield_blocks
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON shield_blocks TO nightfall_app;
GRANT UPDATE (applied_at, removed_at, lifted_at, lifted_by_user_id, lifted_reason, incident_id)
  ON shield_blocks TO nightfall_app;

-- The hard safety invariants: the allow list (both tiers) and, for the automatic tier, a live
-- authorization that covers the sensor and action within its duration limit. A block that
-- breaks one cannot be inserted, whatever the application does.
CREATE FUNCTION nf_shield_block_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE auth shield_response_authorizations%ROWTYPE;
BEGIN
  IF EXISTS (SELECT 1 FROM shield_block_allowlist a
             WHERE a.workspace_id = NEW.workspace_id AND a.removed_at IS NULL
               AND a.cidr >>= NEW.target) THEN
    RAISE EXCEPTION 'target % is on the allow list and cannot be blocked', NEW.target
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.tier = 'automatic' THEN
    SELECT * INTO auth FROM shield_response_authorizations
      WHERE id = NEW.authorization_id AND workspace_id = NEW.workspace_id;
    IF auth.id IS NULL OR auth.ended_at IS NOT NULL OR auth.expires_at <= now() THEN
      RAISE EXCEPTION 'automatic block needs a live response authorization'
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.sensor_id <> ALL (auth.sensor_ids) THEN
      RAISE EXCEPTION 'the response authorization does not cover this sensor'
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.action <> ALL (auth.actions) THEN
      RAISE EXCEPTION 'the response authorization does not allow action %', NEW.action
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.expires_at - NEW.created_at > make_interval(secs => auth.max_block_seconds) THEN
      RAISE EXCEPTION 'block is longer than the authorization allows'
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER shield_blocks_guard BEFORE INSERT ON shield_blocks
  FOR EACH ROW EXECUTE FUNCTION nf_shield_block_guard();
"""

DOWNGRADE = r"""
DROP TABLE shield_blocks;
DROP FUNCTION nf_shield_block_guard();
DROP TABLE shield_intrusion_alerts;
DROP TABLE shield_block_allowlist;
DROP TABLE shield_response_settings;
DROP TABLE shield_response_authorizations;
DROP FUNCTION nf_resp_auth_guard();
DROP FUNCTION nf_sensor_authenticate(bytea);
DROP TABLE shield_sensors;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
