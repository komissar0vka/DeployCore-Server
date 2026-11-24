"""Store idempotency for multi-program deployment submissions."""
import sqlalchemy as sa
from alembic import op


revision = "0012_deployment_batches"
down_revision = "0011_device_groups"


def upgrade():
    op.create_table(
        "deployment_batches",
        sa.Column("created_by", sa.Uuid, sa.ForeignKey("users.id"), primary_key=True),
        sa.Column("request_id", sa.Uuid, primary_key=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
    )


def downgrade():
    op.drop_table("deployment_batches")
