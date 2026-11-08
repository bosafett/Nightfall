"""SHIELD v1 (docs/designs/2026-11-shield-aegis.md): standing monitor authorizations and alerts.

  * monitor_authorizations: the owner's standing authorization for daily passive and
    low-risk checks (ct, dns, tls, headers) of up to 20 targets of one pinned scope version,
    for at most 30 days. Insert-only apart from ending it (revoke, expiry, renewal, scope
    change) and the scheduler's last-run time; an ended authorization can't change.
  * operations.monitor_authorization_id: set only at insert, and only when the operation
    matches a live authorization exactly (scope version, target, tool), isn't lab, a
    playbook step or an agent proposal. It's what lets a scheduled low-risk check run
    without a per-operation approval; nothing else does.
  * alerts: raised by the worker when a scheduled check finds a change or crosses a
    threshold; people only acknowledge and resolve them (state columns), and nobody deletes.

Revision ID: 0021
"""

from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TABLE monitor_authorizations (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id           uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  project_id             uuid NOT NULL,
  scope_id               uuid NOT NULL,
  targets                text[] NOT NULL CHECK (cardinality(targets) BETWEEN 1 AND 20),
  checks                 text[] NOT NULL
                         CHECK (cardinality(checks) >= 1 AND checks <@ ARRAY['ct', 'dns', 'tls', 'headers']),
  cadence                text NOT NULL DEFAULT 'daily' CHECK (cadence = 'daily'),
  authorized_by_user_id  uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  authorized_at          timestamptz NOT NULL DEFAULT now(),
  expires_at             timestamptz NOT NULL,
  renews_id              uuid,
  last_run_at            timestamptz,
  ended_at               timestamptz,
  ended_reason           text CHECK (ended_reason IN ('revoked', 'expired', 'renewed', 'scope_changed')),
  ended_by_user_id       uuid REFERENCES users(id) ON DELETE RESTRICT,
  end_note               text NOT NULL DEFAULT '' CHECK (length(end_note) <= 1000),
  CHECK (expires_at > authorized_at AND expires_at <= authorized_at + interval '30 days'),
  CHECK ((ended_at IS NULL) = (ended_reason IS NULL)),
  FOREIGN KEY (project_id, workspace_id) REFERENCES projects (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (scope_id, workspace_id) REFERENCES scopes (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (id, workspace_id)
);
CREATE INDEX monitor_authorizations_live_idx ON monitor_authorizations (expires_at) WHERE ended_at IS NULL;
ALTER TABLE monitor_authorizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY monitor_authorizations_tenant ON monitor_authorizations
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
-- The scheduler (worker) reads every workspace's authorizations once a day.
CREATE POLICY monitor_authorizations_worker ON monitor_authorizations TO nightfall_worker
  USING (true) WITH CHECK (true);
GRANT SELECT, INSERT ON monitor_authorizations TO nightfall_app;
GRANT UPDATE (ended_at, ended_reason, ended_by_user_id, end_note) ON monitor_authorizations TO nightfall_app;
GRANT SELECT ON monitor_authorizations TO nightfall_worker;
GRANT UPDATE (last_run_at, ended_at, ended_reason, end_note) ON monitor_authorizations TO nightfall_worker;

CREATE FUNCTION nf_monitor_authorization_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.ended_at IS NOT NULL THEN
    RAISE EXCEPTION 'an ended monitor authorization cannot change' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER monitor_authorizations_guard BEFORE UPDATE ON monitor_authorizations
  FOR EACH ROW EXECUTE FUNCTION nf_monitor_authorization_guard();

ALTER TABLE operations ADD COLUMN monitor_authorization_id uuid;
ALTER TABLE operations ADD FOREIGN KEY (monitor_authorization_id, workspace_id)
  REFERENCES monitor_authorizations (id, workspace_id) ON DELETE RESTRICT;
CREATE INDEX operations_monitor_idx ON operations (monitor_authorization_id)
  WHERE monitor_authorization_id IS NOT NULL;

CREATE FUNCTION nf_operation_monitor_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a monitor_authorizations%ROWTYPE;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.monitor_authorization_id IS DISTINCT FROM OLD.monitor_authorization_id THEN
      RAISE EXCEPTION 'an operation''s monitor authorization cannot change' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.monitor_authorization_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT * INTO a FROM monitor_authorizations WHERE id = NEW.monitor_authorization_id;
  IF a.id IS NULL OR a.workspace_id <> NEW.workspace_id OR a.ended_at IS NOT NULL
     OR a.expires_at <= now() OR a.scope_id <> NEW.scope_id
     OR NOT (NEW.target_value = ANY (a.targets)) OR NOT (NEW.tool = ANY (a.checks))
     OR NEW.risk_class NOT IN ('passive', 'low') OR NEW.is_lab
     OR NEW.playbook_run_id IS NOT NULL OR NEW.proposed_by_task_id IS NOT NULL THEN
    RAISE EXCEPTION 'operation does not match a live monitor authorization' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER operations_monitor_guard BEFORE INSERT OR UPDATE ON operations
  FOR EACH ROW EXECUTE FUNCTION nf_operation_monitor_guard();

CREATE TABLE alerts (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id             uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  project_id               uuid NOT NULL,
  authorization_id         uuid,
  kind                     text NOT NULL CHECK (kind IN (
    'cert.expiring', 'cert.changed', 'tls.weakened', 'headers.regressed', 'ct.new_names',
    'dns.changed', 'finding.reopened', 'monitor.failed', 'monitor.expiring', 'monitor.ended')),
  severity                 severity NOT NULL,
  title                    text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
  detail                   text NOT NULL DEFAULT '' CHECK (length(detail) <= 4000),
  target                   text NOT NULL DEFAULT '' CHECK (length(target) <= 300),
  dedupe_key               text NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 500),
  evidence_ids             uuid[] NOT NULL DEFAULT '{}',
  finding_id               uuid,
  rules                    text NOT NULL,
  first_seen_at            timestamptz NOT NULL DEFAULT now(),
  last_seen_at             timestamptz NOT NULL DEFAULT now(),
  state                    text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'acknowledged', 'resolved')),
  acknowledged_by_user_id  uuid REFERENCES users(id) ON DELETE RESTRICT,
  acknowledged_at          timestamptz,
  resolved_by_user_id      uuid REFERENCES users(id) ON DELETE RESTRICT,
  resolved_at              timestamptz,
  note                     text NOT NULL DEFAULT '' CHECK (length(note) <= 1000),
  FOREIGN KEY (project_id, workspace_id) REFERENCES projects (id, workspace_id) ON DELETE RESTRICT,
  FOREIGN KEY (authorization_id, workspace_id) REFERENCES monitor_authorizations (id, workspace_id)
    ON DELETE RESTRICT
);
CREATE UNIQUE INDEX alerts_open_dedupe_uq ON alerts (workspace_id, dedupe_key) WHERE state <> 'resolved';
CREATE INDEX alerts_workspace_idx ON alerts (workspace_id, state, last_seen_at DESC);
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY alerts_tenant ON alerts
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
CREATE POLICY alerts_worker ON alerts TO nightfall_worker USING (true) WITH CHECK (true);
GRANT SELECT ON alerts TO nightfall_app;
GRANT UPDATE (state, acknowledged_by_user_id, acknowledged_at, resolved_by_user_id, resolved_at, note)
  ON alerts TO nightfall_app;
GRANT SELECT, INSERT ON alerts TO nightfall_worker;
GRANT UPDATE (severity, title, detail, last_seen_at, evidence_ids, finding_id) ON alerts TO nightfall_worker;

-- open -> acknowledged -> resolved, or open -> resolved; resolved is final.
CREATE FUNCTION nf_alert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.state = 'resolved' THEN
    RAISE EXCEPTION 'a resolved alert cannot change' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'open' AND NEW.state IN ('acknowledged', 'resolved'))
    OR (OLD.state = 'acknowledged' AND NEW.state = 'resolved')) THEN
    RAISE EXCEPTION 'alert cannot go from % to %', OLD.state, NEW.state USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER alerts_guard BEFORE UPDATE ON alerts FOR EACH ROW EXECUTE FUNCTION nf_alert_guard();
"""

DOWNGRADE = r"""
DROP TRIGGER alerts_guard ON alerts;
DROP FUNCTION nf_alert_guard();
DROP TABLE alerts;
DROP TRIGGER operations_monitor_guard ON operations;
DROP FUNCTION nf_operation_monitor_guard();
ALTER TABLE operations DROP COLUMN monitor_authorization_id;
DROP TRIGGER monitor_authorizations_guard ON monitor_authorizations;
DROP FUNCTION nf_monitor_authorization_guard();
DROP TABLE monitor_authorizations;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
