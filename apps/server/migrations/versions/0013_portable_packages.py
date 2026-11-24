"""Add managed Portable EXE placement."""
import sqlalchemy as sa
from alembic import op

revision = "0013_portable_packages"
down_revision = "0012_deployment_batches"

def upgrade():
    op.drop_constraint("package_installer", "software_versions", type_="check")
    op.alter_column("software_versions", "installer", type_=sa.String(8))
    op.create_check_constraint("package_installer", "software_versions", "installer IN ('msi','exe','portable')")
    op.drop_constraint("package_detection_kind", "package_detection_rules", type_="check")
    op.create_check_constraint("package_detection_kind", "package_detection_rules",
        "kind IN ('msi_product','registry_software','file_exists','file_version','all','any','portable_file')")

def downgrade():
    raise RuntimeError("Restore a pre-Portable backup to preserve package history")
