from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Index, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint("management_state IN ('managed', 'retired')", name="device_management_state"),
        Index("device_management_state_index", "management_state"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(253))
    fqdn: Mapped[str] = mapped_column(String(253))
    network_name: Mapped[str] = mapped_column(String(253))
    domain_joined: Mapped[bool]
    ips: Mapped[list[str]] = mapped_column(JSONB)
    os_version: Mapped[str] = mapped_column(String(200))
    agent_version: Mapped[str] = mapped_column(String(64))
    uptime_seconds: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    management_state: Mapped[str] = mapped_column(String(12), server_default="managed")
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    __table_args__ = (
        CheckConstraint("max_uses BETWEEN 1 AND 100 AND uses BETWEEN 0 AND max_uses", name="enrollment_usage"),
        CheckConstraint("device_id IS NULL OR max_uses = 1", name="enrollment_recovery_single_use"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    label: Mapped[str] = mapped_column(String(120))
    max_uses: Mapped[int]
    uses: Mapped[int]
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    device_id: Mapped[UUID | None] = mapped_column(ForeignKey("devices.id"), index=True)


class Agent(Base):
    __tablename__ = "agents"

    device_id: Mapped[UUID] = mapped_column(ForeignKey("devices.id"), primary_key=True)
    credential_hash: Mapped[str] = mapped_column(String(64), unique=True)
    enrollment_id: Mapped[UUID] = mapped_column(ForeignKey("enrollment_tokens.id"))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DeviceInventory(Base):
    __tablename__ = "device_inventory"

    device_id: Mapped[UUID] = mapped_column(ForeignKey("devices.id"), primary_key=True)
    hardware: Mapped[dict] = mapped_column(JSONB)
    fingerprint: Mapped[str] = mapped_column(String(64))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class InstalledSoftware(Base):
    __tablename__ = "installed_software"
    __table_args__ = (UniqueConstraint("device_id", "name", "version", "publisher", name="software_identity"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    device_id: Mapped[UUID] = mapped_column(ForeignKey("devices.id"), index=True)
    name: Mapped[str] = mapped_column(String(240))
    version: Mapped[str] = mapped_column(String(120))
    publisher: Mapped[str] = mapped_column(String(200))


class DeviceEvent(Base):
    __tablename__ = "device_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    device_id: Mapped[UUID] = mapped_column(ForeignKey("devices.id"), index=True)
    actor_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
