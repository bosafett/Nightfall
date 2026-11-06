"""JANUS Phase 2: BLACKSITE probe deck (lab only).

  * scope_targets.allowed_ports / max_rps / daily_budget: per-target probe bounds, part of
    the authorized (immutable) scope version like the rest of the entry.
  * nightfall_blacksite may read registered lab assets (private IPv4 assets of organizations
    with a lab project) so probes can be addressed by asset id only.

Revision ID: 0014
"""

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

UPGRADE = r"""
ALTER TABLE scope_targets
  ADD COLUMN allowed_ports integer[] NOT NULL DEFAULT '{80,443}'
    CHECK (cardinality(allowed_ports) BETWEEN 1 AND 10
           AND 0 < ALL (allowed_ports) AND 65536 > ALL (allowed_ports)),
  ADD COLUMN max_rps smallint NOT NULL DEFAULT 1 CHECK (max_rps BETWEEN 1 AND 10),
  ADD COLUMN daily_budget integer NOT NULL DEFAULT 200 CHECK (daily_budget BETWEEN 1 AND 5000);

GRANT EXECUTE ON FUNCTION nf_is_private_ipv4(text) TO nightfall_blacksite;
GRANT SELECT ON assets TO nightfall_blacksite;
CREATE POLICY blacksite_assets ON assets AS RESTRICTIVE TO nightfall_blacksite
  USING (nf_is_private_ipv4(value) AND organization_id IN (SELECT organization_id FROM projects));
"""

DOWNGRADE = r"""
DROP POLICY IF EXISTS blacksite_assets ON assets;
REVOKE SELECT ON assets FROM nightfall_blacksite;
REVOKE EXECUTE ON FUNCTION nf_is_private_ipv4(text) FROM nightfall_blacksite;
ALTER TABLE scope_targets DROP COLUMN IF EXISTS daily_budget,
  DROP COLUMN IF EXISTS max_rps, DROP COLUMN IF EXISTS allowed_ports;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
