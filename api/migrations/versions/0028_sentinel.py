"""SENTINEL step 3a (docs/designs/2026-11-sentinel-indicator-store.md §3-7): indicators,
sightings and assessments.

  * sentinel_indicators: one row per (workspace, type, normalized value). Counters and times are
    kept up to date by the application as detectors write; computed_confidence never exceeds
    medium (only a person's 'malicious' assessment makes it high, in the API). The assessment
    columns can't be written by the app role directly: only nf_sentinel_assess, which also writes
    the history row and takes the assessor from the session, not from the caller.
  * sentinel_assessments: append-only history of assessments (from, to, reason, who, when).
  * sentinel_sightings: append-only; each points at the source row (kind and id) instead of
    copying it. indicator_id is null for technique-only sightings (host alerts with no
    observable). Techniques are checked against WARPATH's pinned ATT&CK catalogue in the app.
  * Retention (owner decision 3, 1 year): nf_purge_sentinel removes this workspace's sightings
    older than a year and indicators unseen for a year, with their history. Fixed interval.

Analysis only: nothing here can block, open an incident, or change a machine.

Revision ID: 0028
"""

from alembic import op

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TABLE sentinel_indicators (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id         uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  type                 text NOT NULL CHECK (type IN ('ip', 'domain', 'url', 'sha256', 'cert_sha256', 'user_agent')),
  value                text NOT NULL CHECK (length(value) BETWEEN 1 AND 2048),
  first_seen           timestamptz NOT NULL,
  last_seen            timestamptz NOT NULL,
  sighting_count       integer NOT NULL DEFAULT 0 CHECK (sighting_count >= 0),
  computed_confidence  confidence_level NOT NULL DEFAULT 'low' CHECK (computed_confidence <> 'high'),
  assessment           text NOT NULL DEFAULT 'unreviewed'
                       CHECK (assessment IN ('unreviewed', 'malicious', 'benign', 'false_positive')),
  assessment_reason    text NOT NULL DEFAULT '' CHECK (length(assessment_reason) <= 1000),
  assessed_by_user_id  uuid REFERENCES users(id) ON DELETE RESTRICT,
  assessed_at          timestamptz,
  expires_at           timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now(),
  CHECK (last_seen >= first_seen),
  CHECK ((assessment = 'unreviewed') = (assessed_at IS NULL)),
  UNIQUE (workspace_id, type, value),
  UNIQUE (id, workspace_id)
);
CREATE INDEX sentinel_indicators_seen_idx ON sentinel_indicators (workspace_id, last_seen DESC);
ALTER TABLE sentinel_indicators ENABLE ROW LEVEL SECURITY;
CREATE POLICY sentinel_indicators_tenant ON sentinel_indicators
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT ON sentinel_indicators TO nightfall_app;
GRANT INSERT (id, workspace_id, type, value, first_seen, last_seen, sighting_count, computed_confidence,
              expires_at) ON sentinel_indicators TO nightfall_app;
GRANT UPDATE (first_seen, last_seen, sighting_count, computed_confidence, expires_at)
  ON sentinel_indicators TO nightfall_app;

CREATE TABLE sentinel_assessments (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id    uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  indicator_id    uuid NOT NULL,
  from_assessment text NOT NULL,
  to_assessment   text NOT NULL,
  reason          text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
  user_id         uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  at              timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (indicator_id, workspace_id) REFERENCES sentinel_indicators (id, workspace_id) ON DELETE CASCADE
);
CREATE INDEX sentinel_assessments_ind_idx ON sentinel_assessments (indicator_id, at DESC);
ALTER TABLE sentinel_assessments ENABLE ROW LEVEL SECURITY;
CREATE POLICY sentinel_assessments_tenant ON sentinel_assessments
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT ON sentinel_assessments TO nightfall_app;

CREATE TABLE sentinel_sightings (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  indicator_id  uuid,
  source_kind   text NOT NULL CHECK (source_kind IN ('intrusion_alert', 'block', 'host_alert', 'host_change')),
  source_id     uuid NOT NULL,
  sensor_id     uuid,
  techniques    text[] NOT NULL DEFAULT '{}' CHECK (cardinality(techniques) <= 10),
  event_time    timestamptz NOT NULL,
  ingested_at   timestamptz NOT NULL DEFAULT now(),
  CHECK (indicator_id IS NOT NULL OR cardinality(techniques) > 0),
  FOREIGN KEY (indicator_id, workspace_id) REFERENCES sentinel_indicators (id, workspace_id) ON DELETE CASCADE,
  FOREIGN KEY (sensor_id, workspace_id) REFERENCES shield_sensors (id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX sentinel_sightings_ind_idx ON sentinel_sightings (indicator_id, event_time DESC);
CREATE INDEX sentinel_sightings_src_idx ON sentinel_sightings (source_kind, source_id);
CREATE INDEX sentinel_sightings_ws_idx ON sentinel_sightings (workspace_id, ingested_at);
ALTER TABLE sentinel_sightings ENABLE ROW LEVEL SECURITY;
CREATE POLICY sentinel_sightings_tenant ON sentinel_sightings
  USING (workspace_id = nf_current_workspace()) WITH CHECK (workspace_id = nf_current_workspace());
GRANT SELECT, INSERT ON sentinel_sightings TO nightfall_app;

-- A person's assessment: the only way the assessment columns change. The assessor is the
-- session's user (nf_current_user), never a parameter; history is written in the same step.
CREATE FUNCTION nf_sentinel_assess(p_indicator uuid, p_to text, p_reason text) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE ind sentinel_indicators%ROWTYPE; who uuid := nf_current_user();
BEGIN
  IF who IS NULL THEN
    RAISE EXCEPTION 'an assessment needs a signed-in user' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_to NOT IN ('unreviewed', 'malicious', 'benign', 'false_positive') THEN
    RAISE EXCEPTION 'unknown assessment %', p_to USING ERRCODE = 'check_violation';
  END IF;
  IF p_reason IS NULL OR length(btrim(p_reason)) = 0 THEN
    RAISE EXCEPTION 'an assessment needs a reason' USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO ind FROM sentinel_indicators
   WHERE id = p_indicator AND workspace_id = nf_current_workspace() FOR UPDATE;
  IF ind.id IS NULL THEN
    RAISE EXCEPTION 'indicator not found' USING ERRCODE = 'no_data_found';
  END IF;
  INSERT INTO sentinel_assessments (workspace_id, indicator_id, from_assessment, to_assessment, reason, user_id)
    VALUES (ind.workspace_id, ind.id, ind.assessment, p_to, btrim(p_reason), who);
  UPDATE sentinel_indicators SET
    assessment = p_to,
    assessment_reason = CASE WHEN p_to = 'unreviewed' THEN '' ELSE btrim(p_reason) END,
    assessed_by_user_id = CASE WHEN p_to = 'unreviewed' THEN NULL ELSE who END,
    assessed_at = CASE WHEN p_to = 'unreviewed' THEN NULL ELSE now() END
   WHERE id = ind.id;
END $$;
REVOKE ALL ON FUNCTION nf_sentinel_assess(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nf_sentinel_assess(uuid, text, text) TO nightfall_app;

CREATE FUNCTION nf_purge_sentinel() RETURNS integer
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE n integer; m integer;
BEGIN
  DELETE FROM sentinel_sightings
   WHERE workspace_id = nf_current_workspace() AND ingested_at < now() - interval '1 year';
  GET DIAGNOSTICS n = ROW_COUNT;
  DELETE FROM sentinel_indicators
   WHERE workspace_id = nf_current_workspace() AND last_seen < now() - interval '1 year';
  GET DIAGNOSTICS m = ROW_COUNT;
  RETURN n + m;
END $$;
REVOKE ALL ON FUNCTION nf_purge_sentinel() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nf_purge_sentinel() TO nightfall_app;
"""

DOWNGRADE = r"""
DROP FUNCTION nf_purge_sentinel();
DROP FUNCTION nf_sentinel_assess(uuid, text, text);
DROP TABLE sentinel_sightings;
DROP TABLE sentinel_assessments;
DROP TABLE sentinel_indicators;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
