from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class SoftwarePackage(Base):
    __tablename__ = "software_packages"
    __table_args__ = (UniqueConstraint("publisher", "name", name="package_identity"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(160))
    publisher: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SoftwareVersion(Base):
    __tablename__ = "software_versions"
    __table_args__ = (
        UniqueConstraint("package_id", "version", "architecture", name="package_version_identity"),
        CheckConstraint("architecture IN ('x64', 'x86')", name="package_architecture"),
        CheckConstraint("installer IN ('msi', 'exe')", name="package_installer"),
        CheckConstraint("timeout_seconds BETWEEN 1 AND 86400", name="package_timeout"),
        CheckConstraint("min_windows_build IS NULL OR min_windows_build > 0", name="package_os_build"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    package_id: Mapped[UUID] = mapped_column(ForeignKey("software_packages.id"))
    version: Mapped[str] = mapped_column(String(80))
    architecture: Mapped[str] = mapped_column(String(3))
    installer: Mapped[str] = mapped_column(String(3))
    min_windows_build: Mapped[int | None]
    install_args: Mapped[list[str]] = mapped_column(JSONB)
    uninstall_args: Mapped[list[str] | None] = mapped_column(JSONB(none_as_null=True))
    timeout_seconds: Mapped[int]
    success_codes: Mapped[list[int]] = mapped_column(JSONB)
    reboot_required: Mapped[bool]
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))


class PackageDetectionRule(Base):
    __tablename__ = "package_detection_rules"
    __table_args__ = (
        CheckConstraint("kind IN ('msi_product','registry_software','file_exists','file_version')", name="package_detection_kind"),
    )

    version_id: Mapped[UUID] = mapped_column(ForeignKey("software_versions.id"), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    data: Mapped[dict] = mapped_column(JSONB)


class PackageArtifact(Base):
    __tablename__ = "package_artifacts"
    __table_args__ = (
        CheckConstraint("signature IN ('verified', 'unverified')", name="package_signature_status"),
        CheckConstraint("size_bytes > 0", name="package_artifact_size"),
        CheckConstraint("sha256 ~ '^[a-f0-9]{64}$'", name="package_sha256"),
    )

    version_id: Mapped[UUID] = mapped_column(ForeignKey("software_versions.id"), primary_key=True)
    filename: Mapped[str] = mapped_column(String(180))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(12))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
