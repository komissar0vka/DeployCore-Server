"""Add detection previews and installation observations."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0007_detection"
down_revision = "0006_manual_approval"

DETECTION_KINDS = "kind IN ('msi_product','registry_software','file_exists','file_version'"


def target_states(*, extended):
    states = "'queued','leased','running','not_executed','cancelled','failed','succeeded','already_installed','already_absent','reboot_required','unknown'"
    active = "'leased','running','unknown'"
    if extended:
        states += ",'awaiting_reboot'"
        active += ",'awaiting_reboot'"
    op.drop_constraint("deployment_target_state", "deployment_targets", type_="check")
    op.create_check_constraint("deployment_target_state", "deployment_targets", f"state IN ({states})")
    op.drop_index("deployment_one_active_target", table_name="deployment_targets")
    op.create_index("deployment_one_active_target", "deployment_targets", ["device_id"], unique=True,
                    postgresql_where=sa.text(f"state IN ({active})"))


def upgrade():
    target_states(extended=True)
    op.drop_constraint("package_detection_kind", "package_detection_rules", type_="check")
    op.create_check_constraint("package_detection_kind", "package_detection_rules", DETECTION_KINDS + ",'all','any')")
    op.add_column("deployment_attempts", sa.Column("process_started", sa.Boolean()))
    op.add_column("deployment_attempts", sa.Column("detection", sa.String(16)))
    op.add_column("deployment_attempts", sa.Column("reboot_deadline", sa.DateTime(timezone=True)))
    op.add_column("deployment_attempts", sa.Column("reboot_detection", sa.String(16)))
    op.add_column("deployment_attempts", sa.Column("reboot_finished_at", sa.DateTime(timezone=True)))
    op.create_table(
        "detection_previews",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("device_id", sa.Uuid(), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("version_id", sa.Uuid(), sa.ForeignKey("software_versions.id"), nullable=False),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rule", JSONB(), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("observation", sa.String(16)),
    )
    op.create_index("detection_preview_device_created", "detection_previews", ["device_id", "created_at"])


def downgrade():
    op.execute("UPDATE deployment_targets SET state='unknown' WHERE state='awaiting_reboot'")
    target_states(extended=False)
    op.create_check_constraint("package_detection_legacy_only", "package_detection_rules", DETECTION_KINDS + ")")
    op.drop_constraint("package_detection_kind", "package_detection_rules", type_="check")
    op.execute("ALTER TABLE package_detection_rules RENAME CONSTRAINT package_detection_legacy_only TO package_detection_kind")
    op.drop_table("detection_previews")
    for column in ("reboot_finished_at", "reboot_detection", "reboot_deadline", "detection", "process_started"):
        op.drop_column("deployment_attempts", column)
