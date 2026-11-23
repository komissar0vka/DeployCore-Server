from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class DetectionPreview(Base):
    __tablename__ = "detection_previews"
    __table_args__ = (Index("detection_preview_device_created", "device_id", "created_at"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    device_id: Mapped[UUID] = mapped_column(ForeignKey("devices.id"))
    version_id: Mapped[UUID] = mapped_column(ForeignKey("software_versions.id"))
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    rule: Mapped[dict] = mapped_column(JSONB)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observation: Mapped[str | None] = mapped_column(String(16))
