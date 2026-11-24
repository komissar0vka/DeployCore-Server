from uuid import UUID, uuid4

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class DeviceGroup(Base):
    __tablename__ = "device_groups"
    __table_args__ = (UniqueConstraint("name", name="device_group_name"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(160))


class GroupMember(Base):
    __tablename__ = "device_group_members"

    group_id: Mapped[UUID] = mapped_column(ForeignKey("device_groups.id", ondelete="CASCADE"), primary_key=True)
    device_id: Mapped[UUID] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
