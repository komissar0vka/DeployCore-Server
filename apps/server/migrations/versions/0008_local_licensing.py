"""Persist local license acceptance and device management state."""

from uuid import uuid4

import sqlalchemy as sa
from alembic import op

revision = "0008_local_licensing"
down_revision = "0007_detection"


def upgrade():
    op.add_column("devices", sa.Column("management_state", sa.String(12), nullable=False, server_default="managed"))
    op.execute("UPDATE devices SET management_state = 'retired' WHERE deleted_at IS NOT NULL")
    op.create_check_constraint("device_management_state", "devices", "management_state IN ('managed', 'retired')")
    op.create_index("device_management_state_index", "devices", ["management_state"])
    state = op.create_table(
        "license_state",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("instance_id", sa.Uuid, nullable=False, unique=True),
        sa.Column("grant", sa.LargeBinary),
        sa.Column("issue_number", sa.BigInteger),
        sa.Column("payload_sha256", sa.String(64)),
        sa.CheckConstraint("id = 1", name="license_singleton"),
    )
    op.bulk_insert(state, [{"id": 1, "instance_id": uuid4()}])


def downgrade():
    raise RuntimeError("Restore a pre-licensing backup to preserve management and license history")
