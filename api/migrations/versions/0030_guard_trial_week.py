"""SHIELD v3 phase 2, safeguard 21 (design docs/designs/2026-11-shield-v3-intrusion-detection.md
§7, §10c): GUARD's trial week.

  * shield_response_authorizations.trial_days (0-7): for that many days after the owner
    authorizes automatic response, GUARD only records what it would have blocked. The API
    defaults it to 7; the owner may choose fewer when authorizing (already owner + fresh 2FA).
    Existing rows get 0: they were authorized before the trial existed.
  * Like the other limits, it can't be edited afterwards (nf_resp_auth_guard), and the database
    refuses an automatic block during the trial (nf_shield_block_guard), so a bug in the API
    can't skip it.

Revision ID: 0030
"""

from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None

_BLOCK_GUARD = r"""
CREATE OR REPLACE FUNCTION nf_shield_block_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
{trial}
  END IF;
  RETURN NEW;
END $$;
"""

_TRIAL_CHECK = r"""
    IF now() < auth.authorized_at + make_interval(days => auth.trial_days) THEN
      RAISE EXCEPTION 'automatic blocks start after the trial week'
        USING ERRCODE = 'check_violation';
    END IF;"""

_AUTH_GUARD = r"""
CREATE OR REPLACE FUNCTION nf_resp_auth_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at{trial} THEN
    RAISE EXCEPTION 'a response authorization can only be ended, not edited'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
"""

UPGRADE = (
    r"""
ALTER TABLE shield_response_authorizations
  ADD COLUMN trial_days smallint NOT NULL DEFAULT 0 CHECK (trial_days BETWEEN 0 AND 7);
"""
    + _AUTH_GUARD.replace("{trial}", "\n     OR NEW.trial_days IS DISTINCT FROM OLD.trial_days")
    + _BLOCK_GUARD.replace("{trial}", _TRIAL_CHECK)
)

DOWNGRADE = (
    _BLOCK_GUARD.replace("{trial}", "")
    + _AUTH_GUARD.replace("{trial}", "")
    + "ALTER TABLE shield_response_authorizations DROP COLUMN trial_days;\n"
)


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
