from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Index, String, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class DeploymentJob(Base):
    __tablename__ = "deployment_jobs"
    __table_args__ = (
        UniqueConstraint("created_by", "request_id", name="deployment_request_identity"),
        CheckConstraint("operation IN ('install', 'uninstall')", name="deployment_operation"),
        CheckConstraint("mode IN ('transport_only', 'execute_v1')", name="deployment_mode"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    version_id: Mapped[UUID] = mapped_column(ForeignKey("software_versions.id"))
    artifact_sha256: Mapped[str | None] = mapped_column(String(64))
    mode: Mapped[str] = mapped_column(String(16), server_default="transport_only")
    operation: Mapped[str] = mapped_column(String(12))
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    request_id: Mapped[UUID]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class DeploymentTarget(Base):
    __tablename__ = "deployment_targets"
    __table_args__ = (
        UniqueConstraint("job_id", "device_id", name="deployment_device_identity"),
        CheckConstraint("state IN ('queued', 'leased', 'running', 'not_executed', 'cancelled','failed','succeeded','already_installed','already_absent','reboot_required','awaiting_reboot','unknown')",
                        name="deployment_target_state"),
        Index("deployment_one_active_target", "device_id", unique=True,
              postgresql_where=text("state IN ('leased', 'running', 'awaiting_reboot', 'unknown')")),
        Index("deployment_target_device_state", "device_id", "state"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(ForeignKey("deployment_jobs.id"))
    device_id: Mapped[UUID] = mapped_column(ForeignKey("devices.id"))
    state: Mapped[str] = mapped_column(String(32), default="queued")
    cancel_requested: Mapped[bool] = mapped_column(default=False)


class DeploymentAttempt(Base):
    __tablename__ = "deployment_attempts"
    __table_args__ = (
        UniqueConstraint("target_id", "number", name="deployment_attempt_number"),
        CheckConstraint("number BETWEEN 1 AND 5", name="deployment_attempt_range"),
        CheckConstraint("outcome IS NULL OR outcome IN ('expired','not_executed','cancelled','failed','succeeded','already_installed','already_absent','reboot_required','unknown')",
                        name="deployment_attempt_outcome"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    target_id: Mapped[UUID] = mapped_column(ForeignKey("deployment_targets.id"))
    number: Mapped[int]
    leased_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stage: Mapped[str | None] = mapped_column(String(16))
    exit_code: Mapped[int | None] = mapped_column(BigInteger)
    diagnostic: Mapped[str | None] = mapped_column(String(32))
    output_bytes: Mapped[int | None] = mapped_column(BigInteger)
    process_started: Mapped[bool | None]
    detection: Mapped[str | None] = mapped_column(String(16))
    reboot_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reboot_detection: Mapped[str | None] = mapped_column(String(16))
    reboot_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    outcome: Mapped[str | None] = mapped_column(String(32))


class DeploymentEvent(Base):
    __tablename__ = "deployment_events"
    __table_args__ = (Index("deployment_events_job_cursor", "job_id", "id"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    job_id: Mapped[UUID] = mapped_column(ForeignKey("deployment_jobs.id"))
    target_id: Mapped[UUID | None] = mapped_column(ForeignKey("deployment_targets.id"))
    attempt_id: Mapped[UUID | None] = mapped_column(ForeignKey("deployment_attempts.id"))
    action: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
