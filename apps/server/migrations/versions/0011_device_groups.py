"""Store operator-managed device groups."""
import sqlalchemy as sa
from alembic import op


revision = "0011_device_groups"
down_revision = "0010_deployment_schedule"


def upgrade():
    op.create_table(
        "device_groups",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.UniqueConstraint("name", name="device_group_name"),
    )
    op.create_table(
        "device_group_members",
        sa.Column("group_id", sa.Uuid, sa.ForeignKey("device_groups.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("device_id", sa.Uuid, sa.ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True),
    )


def downgrade():
    op.drop_table("device_group_members")
    op.drop_table("device_groups")
