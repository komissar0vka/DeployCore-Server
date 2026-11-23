"""Bind catalog approvals and jobs to an artifact digest."""

import sqlalchemy as sa
from alembic import op

revision = "0006_manual_approval"
down_revision = "0005_execution"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("software_versions", sa.Column("approval_kind", sa.String(12)))
    op.add_column("software_versions", sa.Column("approved_sha256", sa.String(64)))
    op.add_column("deployment_jobs", sa.Column("artifact_sha256", sa.String(64)))
    op.execute("""
        UPDATE software_versions AS version
        SET approval_kind = 'authenticode', approved_sha256 = artifact.sha256
        FROM package_artifacts AS artifact
        WHERE artifact.version_id = version.id AND artifact.signature = 'verified'
          AND version.approved_at IS NOT NULL AND version.approved_by IS NOT NULL
    """)
    op.execute("""
        UPDATE software_versions SET approved_at = NULL, approved_by = NULL
        WHERE approval_kind IS NULL
    """)
    op.execute("""
        UPDATE deployment_jobs AS job SET artifact_sha256 = version.approved_sha256
        FROM software_versions AS version WHERE job.version_id = version.id
    """)
    op.create_check_constraint(
        "package_approval", "software_versions",
        "(approved_at IS NULL AND approved_by IS NULL AND approval_kind IS NULL AND approved_sha256 IS NULL) OR "
        "(approved_at IS NOT NULL AND approved_by IS NOT NULL AND approval_kind IS NOT NULL "
        "AND approval_kind IN ('authenticode', 'manual') AND approved_sha256 IS NOT NULL "
        "AND approved_sha256 ~ '^[a-f0-9]{64}$')",
    )
    op.execute("""
        CREATE FUNCTION invalidate_package_approval() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            UPDATE software_versions
            SET approved_at = NULL, approved_by = NULL, approval_kind = NULL, approved_sha256 = NULL
            WHERE id = OLD.version_id AND approved_at IS NOT NULL;
            RETURN NULL;
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER invalidate_package_approval_on_update
        AFTER UPDATE ON package_artifacts FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW)
        EXECUTE FUNCTION invalidate_package_approval()
    """)
    op.execute("""
        CREATE TRIGGER invalidate_package_approval_on_delete
        AFTER DELETE ON package_artifacts FOR EACH ROW
        EXECUTE FUNCTION invalidate_package_approval()
    """)


def downgrade():
    op.execute("DROP TRIGGER invalidate_package_approval_on_delete ON package_artifacts")
    op.execute("DROP TRIGGER invalidate_package_approval_on_update ON package_artifacts")
    op.execute("DROP FUNCTION invalidate_package_approval()")
    op.drop_constraint("package_approval", "software_versions", type_="check")
    op.execute("UPDATE software_versions SET approved_at = NULL, approved_by = NULL WHERE approval_kind = 'manual'")
    op.drop_column("deployment_jobs", "artifact_sha256")
    op.drop_column("software_versions", "approved_sha256")
    op.drop_column("software_versions", "approval_kind")
