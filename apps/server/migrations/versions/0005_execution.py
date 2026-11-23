"""Execution protocol and result metadata."""
from alembic import op
import sqlalchemy as sa

revision = "0005_execution"
down_revision = "0004_deployment_queue"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column("deployment_targets", "state", existing_type=sa.String(16), type_=sa.String(32))
    op.alter_column("deployment_attempts", "outcome", existing_type=sa.String(16), type_=sa.String(32))
    op.add_column("deployment_jobs", sa.Column("mode", sa.String(16), nullable=False, server_default="transport_only"))
    op.create_check_constraint("deployment_mode", "deployment_jobs", "mode IN ('transport_only', 'execute_v1')")
    for column, kind in (
        ("started_at", sa.DateTime(timezone=True)), ("stage", sa.String(16)),
        ("exit_code", sa.BigInteger()), ("diagnostic", sa.String(32)), ("output_bytes", sa.BigInteger()),
    ):
        op.add_column("deployment_attempts", sa.Column(column, kind))
    op.drop_constraint("deployment_target_state", "deployment_targets", type_="check")
    op.create_check_constraint("deployment_target_state", "deployment_targets",
                               "state IN ('queued','leased','running','not_executed','cancelled','failed','succeeded','already_installed','already_absent','reboot_required','unknown')")
    op.drop_index("deployment_one_active_target", table_name="deployment_targets")
    op.create_index("deployment_one_active_target", "deployment_targets", ["device_id"], unique=True,
                    postgresql_where=sa.text("state IN ('leased', 'running', 'unknown')"))
    op.drop_constraint("deployment_attempt_outcome", "deployment_attempts", type_="check")
    op.create_check_constraint("deployment_attempt_outcome", "deployment_attempts",
                               "outcome IS NULL OR outcome IN ('expired','not_executed','cancelled','failed','succeeded','already_installed','already_absent','reboot_required','unknown')")
    op.drop_constraint("package_detection_kind", "package_detection_rules", type_="check")
    op.create_check_constraint("package_detection_kind", "package_detection_rules",
                               "kind IN ('msi_product','registry_software','file_exists','file_version')")


def downgrade():
    raise RuntimeError("Restore the pre-execution backup to downgrade without losing deployment history")
