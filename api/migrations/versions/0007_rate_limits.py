"""Shared rate-limit counters (NIGHTFALL_RATE_LIMIT_BACKEND=postgres), for hosts that run
many API instances (serverless): in-process counters would give every instance its own
budget and make password-guessing limits meaningless.

Keys are stored as SHA-256 hashes (they include email addresses and client IPs).

Revision ID: 0007
"""

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TABLE rate_limit_hits (
  bucket    text NOT NULL CHECK (length(bucket) BETWEEN 1 AND 50),
  key_hash  bytea NOT NULL CHECK (length(key_hash) = 32),
  at        timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX rate_limit_hits_lookup ON rate_limit_hits (bucket, key_hash, at);
CREATE INDEX rate_limit_hits_age ON rate_limit_hits (at);
GRANT SELECT, INSERT, DELETE ON rate_limit_hits TO nightfall_app;
"""

DOWNGRADE = r"""
DROP TABLE IF EXISTS rate_limit_hits;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
