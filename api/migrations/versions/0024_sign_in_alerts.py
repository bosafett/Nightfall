"""SHIELD v3 phase 1 (docs/designs/2026-11-shield-v3-intrusion-detection.md §5): sign-in alerts.

  * sign_in_alerts: attacks on one account, noticed by the sign-in code. Kinds:
      signin.locked          the account was locked after repeated failed sign-ins;
      signin.password_known  the right password with a wrong two-factor code;
      signin.stepup_locked   a signed-in session failed the two-factor step-up repeatedly.
    One open alert per account and kind; a repeat raises its count, last time and addresses.
  * Written only through nf_record_sign_in_alert (SECURITY DEFINER), because the attempts
    come before anyone is signed in. The app role has no INSERT on the table, and the
    function fixes each kind's severity, so a caller can't choose it.
  * Visible to the account's own user, and to the owners and admins of a workspace the user
    belongs to (owner decision 5, 2026-11-17: no platform-wide view). Only the account's own
    user acknowledges.

Revision ID: 0024
"""

from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TABLE sign_in_alerts (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind             text NOT NULL
                   CHECK (kind IN ('signin.locked', 'signin.password_known', 'signin.stepup_locked')),
  severity         severity NOT NULL,
  count            integer NOT NULL DEFAULT 1 CHECK (count >= 1),
  addresses        text[] NOT NULL DEFAULT '{}' CHECK (cardinality(addresses) <= 10),
  first_seen_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at     timestamptz NOT NULL DEFAULT now(),
  state            text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'acknowledged')),
  acknowledged_at  timestamptz,
  CHECK ((state = 'acknowledged') = (acknowledged_at IS NOT NULL))
);
CREATE UNIQUE INDEX sign_in_alerts_one_open ON sign_in_alerts (user_id, kind) WHERE state = 'open';
CREATE INDEX sign_in_alerts_user_idx ON sign_in_alerts (user_id, last_seen_at DESC);

ALTER TABLE sign_in_alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY sign_in_alerts_select ON sign_in_alerts FOR SELECT USING (
  user_id = nf_current_user()
  OR (
    EXISTS (SELECT 1 FROM workspace_members me
            WHERE me.workspace_id = nf_current_workspace() AND me.user_id = nf_current_user()
              AND me.role IN ('owner', 'admin'))
    AND EXISTS (SELECT 1 FROM workspace_members m
                WHERE m.workspace_id = nf_current_workspace() AND m.user_id = sign_in_alerts.user_id)
  ));
CREATE POLICY sign_in_alerts_acknowledge ON sign_in_alerts FOR UPDATE
  USING (user_id = nf_current_user() AND state = 'open')
  WITH CHECK (user_id = nf_current_user() AND state = 'acknowledged');
GRANT SELECT ON sign_in_alerts TO nightfall_app;
GRANT UPDATE (state, acknowledged_at) ON sign_in_alerts TO nightfall_app;

CREATE FUNCTION nf_record_sign_in_alert(target uuid, k text, addr text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  sev severity := CASE k
    WHEN 'signin.locked' THEN 'medium'
    WHEN 'signin.password_known' THEN 'high'
    WHEN 'signin.stepup_locked' THEN 'medium'
  END;
  a text := left(coalesce(addr, ''), 64);
BEGIN
  IF sev IS NULL THEN
    RAISE EXCEPTION 'unknown sign-in alert kind %', k USING ERRCODE = 'check_violation';
  END IF;
  INSERT INTO sign_in_alerts AS s (user_id, kind, severity, addresses)
  VALUES (target, k, sev, CASE WHEN a = '' THEN '{}'::text[] ELSE ARRAY[a] END)
  ON CONFLICT (user_id, kind) WHERE state = 'open' DO UPDATE SET
    count = s.count + 1,
    last_seen_at = now(),
    addresses = CASE
      WHEN a = '' OR a = ANY (s.addresses) THEN s.addresses
      ELSE (s.addresses || a)[greatest(1, cardinality(s.addresses) - 8):]
    END;
END $$;
REVOKE ALL ON FUNCTION nf_record_sign_in_alert(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nf_record_sign_in_alert(uuid, text, text) TO nightfall_app;
"""

DOWNGRADE = r"""
DROP FUNCTION nf_record_sign_in_alert(uuid, text, text);
DROP TABLE sign_in_alerts;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
