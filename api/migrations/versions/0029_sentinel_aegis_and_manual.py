"""SENTINEL step 3c (docs/designs/2026-11-sentinel-indicator-store.md §15): two more sources.

  * 'aegis_alert': AEGIS monitoring alerts. Certificate changes give the new certificate
    fingerprint; certificate-log and DNS changes give names outside the authorized scope. The
    worker raises these alerts, so it gets the same limited write access to indicators as the
    app, and may add a sighting only for an AEGIS alert in the same workspace.
  * 'incident_entry': an indicator a person entered on an incident; the sighting points at the
    timeline entry that records it.

No new tables. Analysis only: nothing here can block, open an incident, or change a machine.

Revision ID: 0029
"""

from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None

UPGRADE = r"""
ALTER TABLE sentinel_sightings DROP CONSTRAINT sentinel_sightings_source_kind_check;
ALTER TABLE sentinel_sightings ADD CONSTRAINT sentinel_sightings_source_kind_check
  CHECK (source_kind IN ('intrusion_alert', 'block', 'host_alert', 'host_change',
                         'aegis_alert', 'incident_entry'));

CREATE POLICY sentinel_indicators_worker ON sentinel_indicators TO nightfall_worker
  USING (true) WITH CHECK (true);
GRANT SELECT ON sentinel_indicators TO nightfall_worker;
GRANT INSERT (id, workspace_id, type, value, first_seen, last_seen, sighting_count, computed_confidence,
              expires_at) ON sentinel_indicators TO nightfall_worker;
GRANT UPDATE (first_seen, last_seen, sighting_count, computed_confidence, expires_at)
  ON sentinel_indicators TO nightfall_worker;

-- Insert only, and only for an AEGIS alert of the same workspace: the worker can't read
-- sightings or attach them to other sources.
CREATE POLICY sentinel_sightings_worker ON sentinel_sightings FOR INSERT TO nightfall_worker
  WITH CHECK (source_kind = 'aegis_alert' AND EXISTS (
    SELECT 1 FROM alerts a WHERE a.id = source_id AND a.workspace_id = sentinel_sightings.workspace_id));
GRANT INSERT ON sentinel_sightings TO nightfall_worker;
"""

DOWNGRADE = r"""
REVOKE INSERT ON sentinel_sightings FROM nightfall_worker;
DROP POLICY sentinel_sightings_worker ON sentinel_sightings;
REVOKE ALL ON sentinel_indicators FROM nightfall_worker;
DROP POLICY sentinel_indicators_worker ON sentinel_indicators;
DELETE FROM sentinel_sightings WHERE source_kind IN ('aegis_alert', 'incident_entry');
ALTER TABLE sentinel_sightings DROP CONSTRAINT sentinel_sightings_source_kind_check;
ALTER TABLE sentinel_sightings ADD CONSTRAINT sentinel_sightings_source_kind_check
  CHECK (source_kind IN ('intrusion_alert', 'block', 'host_alert', 'host_change'));
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
