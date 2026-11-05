"""Evidence content in Postgres, for hosts without a persistent disk shared by the API and
the worker (NIGHTFALL_EVIDENCE_BACKEND=postgres). Content-addressed by SHA-256.

  * The worker may insert and read any blob: it stores content before the evidence row
    that refers to it exists.
  * The API may read a blob only if an evidence row in the current workspace refers to it.
    The policy's subquery runs under the evidence table's own row-level security, so a
    blob is invisible to every other workspace even if its hash is known.
  * Nobody can update or delete a blob.

Revision ID: 0006
"""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE TABLE evidence_blobs (
  sha256      bytea PRIMARY KEY CHECK (length(sha256) = 32),
  content     bytea NOT NULL,
  size_bytes  integer NOT NULL CHECK (size_bytes = length(content)),
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX evidence_content_idx ON evidence (content_sha256);

ALTER TABLE evidence_blobs ENABLE ROW LEVEL SECURITY;
CREATE POLICY evidence_blobs_worker_read ON evidence_blobs FOR SELECT TO nightfall_worker
  USING (true);
CREATE POLICY evidence_blobs_worker_insert ON evidence_blobs FOR INSERT TO nightfall_worker
  WITH CHECK (true);
CREATE POLICY evidence_blobs_app_read ON evidence_blobs FOR SELECT TO nightfall_app
  USING (EXISTS (SELECT 1 FROM evidence e WHERE e.content_sha256 = evidence_blobs.sha256));

GRANT SELECT ON evidence_blobs TO nightfall_app;
GRANT SELECT, INSERT ON evidence_blobs TO nightfall_worker;
"""

DOWNGRADE = r"""
DROP TABLE IF EXISTS evidence_blobs;
DROP INDEX IF EXISTS evidence_content_idx;
"""


def upgrade() -> None:
    op.execute(UPGRADE)


def downgrade() -> None:
    op.execute(DOWNGRADE)
