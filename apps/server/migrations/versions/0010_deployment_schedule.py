"""Add a start time to locally queued deployments."""
import sqlalchemy as sa
from alembic import op


revision = "0010_deployment_schedule"
down_revision = "0009_package_intake"


def upgrade():
    op.add_column("deployment_jobs", sa.Column("not_before", sa.DateTime(timezone=True)))


def downgrade():
    op.drop_column("deployment_jobs", "not_before")
