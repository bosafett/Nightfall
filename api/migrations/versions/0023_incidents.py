"""SHIELD v2 (docs/designs/2026-11-shield-incident-response.md): incidents, with recovery and
verification.

  * incidents: a tracked incident on a project. The state only moves along the lifecycle
    (open -> contained -> recovering -> closed, or cancelled); a closed incident is frozen
    apart from being reopened; a cancelled one is final.
  * incident_items: the alerts, findings and assets linked to an incident. An item is added
    and may be removed once; an alert is in at most one incident that is still in progress.
  * incident_entries: the timeline (events, notes, recorded actions, checklist changes and
    verification results). Insert-only for every role. The worker may insert verification
    results only.
  * operations.incident_id: a verification run requested from an incident. Set only at
    insert, and only on an operation that runs under a monitor authorization (so every rule
    of migration 0021 applies to it) in the incident's own project while it is in progress.
  * alerts.data: the facts an alert was raised on (which protocols, which header checks), so
    a later check can say whether that condition is still present.

Revision ID: 0023
"""

from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TABLE incidents (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  project_id          uuid NOT NULL,
  title               text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
  summary             text NOT NULL DEFAULT '' CHECK (length(summary) <= 4000),
  severity            severity NOT NULL,
  severity_reason     text NOT NULL DEFAULT '' CHECK (length(severity_reason) <= 1000),
  lead_user_id        uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  state               text NOT NULL DEFAULT 'open'
                      CHECK (state IN ('open', 'contained', 'recovering', 'closed', 'cancelled')),
  opened_by_user_id   uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  opened_at           timestamptz NOT NULL DEFAULT now(),
  closed_by_user_id   uuid REFERENCES users(id) ON DELETE RESTRICT,
  closed_at           timestamptz,
  override_reason     text NOT NULL DEFAULT '' CHECK (length(override_reason) <= 2000),
  review              jsonb,
  cancel_reason       text NOT NULL DEFAULT '' CHECK (length(cancel_reason) <= 1000),
  CHECK ((state = 'closed') = (closed_at IS NOT NULL)),
  CHECK ((state = 'closed') = (review IS NOT NULL)),
  CHECK ((state = 'closed') = (closed_by_user_id IS NOT NULL)),
  CHECK (state = 'closed' OR override_reason = ''),
  CHECK ((state = 'cancelled') = (cancel_reason <> '')),
  FOREIGN KEY (project_id, workspace_id) REFERENCES projects (id, workspace_id) ON DELETE RESTRICT,
  UNIQUE (id, workspace_id)
);
CREATE INDEX incidents_workspace_idx ON incidents (workspace_id, state, opened_at DESC);
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
CREATE POLICY incidents_tenant ON incidents
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON incidents TO nightfall_app;
GRANT UPDATE (title, summary, severity, severity_reason, lead_user_id, state, closed_by_user_id,
              closed_at, override_reason, review, cancel_reason) ON incidents TO nightfall_app;
GRANT SELECT ON incidents TO nightfall_worker;

CREATE FUNCTION nf_incident_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE rank_old int; rank_new int;
BEGIN
  IF OLD.state = 'cancelled' THEN
    RAISE EXCEPTION 'a cancelled incident cannot change' USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.state = 'closed' THEN
    -- Frozen, apart from reopening, which clears the closing fields and nothing else.
    IF NEW.state <> 'open' OR NEW.title IS DISTINCT FROM OLD.title
       OR NEW.summary IS DISTINCT FROM OLD.summary OR NEW.severity IS DISTINCT FROM OLD.severity
       OR NEW.severity_reason IS DISTINCT FROM OLD.severity_reason
       OR NEW.lead_user_id IS DISTINCT FROM OLD.lead_user_id THEN
      RAISE EXCEPTION 'a closed incident can only be reopened' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NEW.state NOT IN ('closed', 'cancelled') THEN
    rank_old := array_position(ARRAY['open', 'contained', 'recovering'], OLD.state);
    rank_new := array_position(ARRAY['open', 'contained', 'recovering'], NEW.state);
    IF rank_new IS NULL OR rank_new <= rank_old THEN
      RAISE EXCEPTION 'incident cannot go from % to %', OLD.state, NEW.state USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER incidents_guard BEFORE UPDATE ON incidents
  FOR EACH ROW EXECUTE FUNCTION nf_incident_guard();

CREATE TABLE incident_items (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  incident_id         uuid NOT NULL,
  kind                text NOT NULL CHECK (kind IN ('alert', 'finding', 'asset')),
  item_id             uuid NOT NULL,
  added_by_user_id    uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  added_at            timestamptz NOT NULL DEFAULT now(),
  removed_by_user_id  uuid REFERENCES users(id) ON DELETE RESTRICT,
  removed_at          timestamptz,
  CHECK ((removed_at IS NULL) = (removed_by_user_id IS NULL)),
  FOREIGN KEY (incident_id, workspace_id) REFERENCES incidents (id, workspace_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX incident_items_live_uq ON incident_items (incident_id, kind, item_id)
  WHERE removed_at IS NULL;
CREATE INDEX incident_items_item_idx ON incident_items (kind, item_id) WHERE removed_at IS NULL;
ALTER TABLE incident_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY incident_items_tenant ON incident_items
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON incident_items TO nightfall_app;
GRANT UPDATE (removed_by_user_id, removed_at) ON incident_items TO nightfall_app;
GRANT SELECT ON incident_items TO nightfall_worker;

CREATE FUNCTION nf_incident_item_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE st text;
BEGIN
  SELECT state INTO st FROM incidents WHERE id = NEW.incident_id;
  IF st IS NULL OR st IN ('closed', 'cancelled') THEN
    RAISE EXCEPTION 'items of a closed or cancelled incident cannot change' USING ERRCODE = 'check_violation';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF OLD.removed_at IS NOT NULL THEN
      RAISE EXCEPTION 'a removed incident item cannot change' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.kind = 'alert' AND EXISTS (
       SELECT 1 FROM incident_items it JOIN incidents i ON i.id = it.incident_id
       WHERE it.kind = 'alert' AND it.item_id = NEW.item_id AND it.removed_at IS NULL
         AND it.incident_id <> NEW.incident_id AND i.state NOT IN ('closed', 'cancelled')) THEN
    RAISE EXCEPTION 'this alert is already in another incident in progress' USING ERRCODE = 'unique_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER incident_items_guard BEFORE INSERT OR UPDATE ON incident_items
  FOR EACH ROW EXECUTE FUNCTION nf_incident_item_guard();

CREATE TABLE incident_entries (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  seq             bigint GENERATED ALWAYS AS IDENTITY,  -- the order entries were written in
  workspace_id    uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  incident_id     uuid NOT NULL,
  kind            text NOT NULL CHECK (kind IN ('event', 'note', 'action', 'check', 'verification')),
  body            text NOT NULL DEFAULT '' CHECK (length(body) <= 4000),
  data            jsonb NOT NULL DEFAULT '{}',
  actor_user_id   uuid REFERENCES users(id) ON DELETE RESTRICT,
  created_at      timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (incident_id, workspace_id) REFERENCES incidents (id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX incident_entries_incident_idx ON incident_entries (incident_id, seq);
ALTER TABLE incident_entries ENABLE ROW LEVEL SECURITY;
CREATE POLICY incident_entries_tenant ON incident_entries
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
-- The timeline is a record: insert-only for every role (no UPDATE or DELETE grants).
GRANT SELECT, INSERT ON incident_entries TO nightfall_app;
GRANT SELECT, INSERT ON incident_entries TO nightfall_worker;
-- The worker writes verification results and nothing else; people's entries come from the API.
CREATE POLICY incident_entries_worker_verification ON incident_entries AS RESTRICTIVE FOR INSERT
  TO nightfall_worker WITH CHECK (kind = 'verification' AND actor_user_id IS NULL);
CREATE POLICY incident_entries_app_not_verification ON incident_entries AS RESTRICTIVE FOR INSERT
  TO nightfall_app WITH CHECK (kind <> 'verification');

ALTER TABLE operations ADD COLUMN incident_id uuid;
ALTER TABLE operations ADD FOREIGN KEY (incident_id, workspace_id)
  REFERENCES incidents (id, workspace_id) ON DELETE RESTRICT;
CREATE INDEX operations_incident_idx ON operations (incident_id) WHERE incident_id IS NOT NULL;

CREATE FUNCTION nf_operation_incident_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE i incidents%ROWTYPE;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.incident_id IS DISTINCT FROM OLD.incident_id THEN
      RAISE EXCEPTION 'an operation''s incident cannot change' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.incident_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT * INTO i FROM incidents WHERE id = NEW.incident_id;
  IF i.id IS NULL OR i.workspace_id <> NEW.workspace_id OR i.project_id <> NEW.project_id
     OR i.state IN ('closed', 'cancelled') OR NEW.monitor_authorization_id IS NULL THEN
    RAISE EXCEPTION 'a verification run needs an incident in progress in this project and a monitor authorization'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER operations_incident_guard BEFORE INSERT OR UPDATE ON operations
  FOR EACH ROW EXECUTE FUNCTION nf_operation_incident_guard();

ALTER TABLE alerts ADD COLUMN data jsonb NOT NULL DEFAULT '{}';
GRANT UPDATE (data) ON alerts TO nightfall_worker;
"""

DOWNGRADE = r"""
REVOKE UPDATE (data) ON alerts FROM nightfall_worker;
ALTER TABLE alerts DROP COLUMN data;
DROP TRIGGER operations_incident_guard ON operations;
DROP FUNCTION nf_operation_incident_guard();
ALTER TABLE operations DROP COLUMN incident_id;
DROP POLICY IF EXISTS incident_entries_app_not_verification ON incident_entries;
DROP POLICY IF EXISTS incident_entries_worker_verification ON incident_entries;
DROP TABLE incident_entries;
DROP TRIGGER incident_items_guard ON incident_items;
DROP FUNCTION nf_incident_item_guard();
DROP TABLE incident_items;
DROP TRIGGER incidents_guard ON incidents;
DROP FUNCTION nf_incident_guard();
DROP TABLE incidents;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
