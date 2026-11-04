"""Phase 3b: operation states for the approval workflow.

New enum values must be committed before use, so they get their own migration.

Revision ID: 0003
"""

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TYPE operation_status ADD VALUE IF NOT EXISTS 'awaiting_approval' BEFORE 'queued'"
    )
    op.execute("ALTER TYPE operation_status ADD VALUE IF NOT EXISTS 'rejected' AFTER 'denied'")


def downgrade() -> None:
    # Postgres can't drop enum values; recreate the type without them.
    op.execute("""
        DROP INDEX IF EXISTS operations_one_pending;
        DROP INDEX IF EXISTS operations_queue_idx;
        UPDATE operations SET status = 'cancelled' WHERE status IN ('awaiting_approval', 'rejected');
        ALTER TABLE operations ALTER COLUMN status DROP DEFAULT;
        ALTER TYPE operation_status RENAME TO operation_status_old;
        CREATE TYPE operation_status AS ENUM ('queued', 'running', 'succeeded', 'failed', 'denied', 'cancelled');
        ALTER TABLE operations ALTER COLUMN status TYPE operation_status USING status::text::operation_status;
        ALTER TABLE operations ALTER COLUMN status SET DEFAULT 'queued';
        DROP TYPE operation_status_old;
        CREATE UNIQUE INDEX operations_one_pending ON operations (project_id, tool, target_value)
          WHERE status IN ('queued', 'running');
        CREATE INDEX operations_queue_idx ON operations (queued_at) WHERE status IN ('queued', 'running');
    """)
