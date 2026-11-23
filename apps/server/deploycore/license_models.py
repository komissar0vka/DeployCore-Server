from uuid import UUID

from sqlalchemy import BigInteger, CheckConstraint, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class LicenseState(Base):
    __tablename__ = "license_state"
    __table_args__ = (CheckConstraint("id = 1", name="license_singleton"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    instance_id: Mapped[UUID] = mapped_column(unique=True)
    grant: Mapped[bytes | None] = mapped_column(LargeBinary)
    issue_number: Mapped[int | None] = mapped_column(BigInteger)
    payload_sha256: Mapped[str | None] = mapped_column(String(64))
