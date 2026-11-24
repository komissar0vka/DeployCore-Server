"""Stage catalog uploads before creating package records."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "0009_package_intake"
down_revision = "0008_local_licensing"


def upgrade():
    op.add_column("software_versions", sa.Column("revision", sa.Integer, nullable=False, server_default="1"))
    op.drop_constraint("package_version_identity", "software_versions", type_="unique")
    op.create_unique_constraint("package_version_identity", "software_versions",
                                ["package_id", "version", "architecture", "revision"])
    op.add_column("software_packages", sa.Column("category", sa.String(160), nullable=False, server_default=""))
    op.add_column("package_artifacts", sa.Column("storage_key", sa.Uuid()))
    op.create_table(
        "package_intakes",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("owner_id", sa.Uuid, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", JSONB, nullable=False),
    )
    op.create_index("ix_package_intakes_owner_id", "package_intakes", ["owner_id"])
    op.create_index("ix_package_intakes_expires_at", "package_intakes", ["expires_at"])


def downgrade():
    op.drop_column("package_artifacts", "storage_key")
    op.drop_table("package_intakes")
    op.drop_column("software_packages", "category")
    op.drop_constraint("package_version_identity", "software_versions", type_="unique")
    op.create_unique_constraint("package_version_identity", "software_versions", ["package_id", "version", "architecture"])
    op.drop_column("software_versions", "revision")
