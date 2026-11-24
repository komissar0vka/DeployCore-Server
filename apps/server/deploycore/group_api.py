from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import Field, field_validator
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError

from .device_models import Agent, Device
from .device_schemas import Wire
from .group_models import DeviceGroup, GroupMember
from .models import User
from .package_schemas import Title
from .security import Db, Permission, audit, require

router = APIRouter(prefix="/api/v1/device-groups", tags=["Device groups"])
Reader = Annotated[User, Depends(require(Permission.READ))]
Operator = Annotated[User, Depends(require(Permission.MANAGE_OPERATIONS))]


class GroupInput(Wire):
    name: Title
    device_ids: Annotated[list[UUID], Field(max_length=100)]

    @field_validator("device_ids")
    @classmethod
    def distinct_devices(cls, values):
        if len(set(values)) != len(values):
            raise ValueError("device IDs must be unique")
        return values


class MemberView(Wire):
    id: UUID
    hostname: str
    agent_version: str


class GroupView(Wire):
    id: UUID
    name: str
    devices: list[MemberView]


def available_devices():
    return (
        select(Device.id, Device.hostname, Device.agent_version)
        .join(Agent, Agent.device_id == Device.id)
        .where(Device.deleted_at.is_(None), Device.management_state == "managed", Agent.revoked_at.is_(None))
        .order_by(Device.hostname, Device.id)
    )


@router.get("")
def list_groups(db: Db, actor: Reader) -> list[GroupView]:
    groups = {group.id: GroupView(id=group.id, name=group.name, devices=[])
              for group in db.scalars(select(DeviceGroup).order_by(DeviceGroup.name, DeviceGroup.id))}
    for id_, hostname, version, group_id in db.execute(
        available_devices().join(GroupMember, GroupMember.device_id == Device.id).add_columns(GroupMember.group_id)
    ):
        if group_id in groups:
            groups[group_id].devices.append(MemberView(id=id_, hostname=hostname, agent_version=version))
    db.commit()
    return list(groups.values())


def group_for_update(db: Db, group_id: UUID) -> DeviceGroup:
    group = db.get(DeviceGroup, group_id, with_for_update=True)
    if group is None:
        raise HTTPException(404, "device_group_not_found")
    return group


def save(group: DeviceGroup, data: GroupInput, request: Request, db: Db, actor: Operator, event: str) -> GroupView:
    group.name = data.name
    try:
        db.flush()
    except IntegrityError as exc:
        if getattr(exc.orig.diag, "constraint_name", None) == "device_group_name":
            raise HTTPException(409, "device_group_duplicate") from exc
        raise
    members = db.execute(available_devices().where(Device.id.in_(data.device_ids))).all()
    if len(members) != len(data.device_ids):
        raise HTTPException(422, "deployment_devices_unavailable")
    db.execute(delete(GroupMember).where(GroupMember.group_id == group.id))
    db.add_all(GroupMember(group_id=group.id, device_id=device_id) for device_id, _, _ in members)
    audit(db, request, event, actor=actor, details={"group_id": str(group.id), "device_count": str(len(members))})
    db.commit()
    return GroupView(id=group.id, name=group.name, devices=[
        MemberView(id=device_id, hostname=hostname, agent_version=version) for device_id, hostname, version in members
    ])


@router.post("", status_code=201)
def create_group(data: GroupInput, request: Request, db: Db, actor: Operator) -> GroupView:
    db.execute(select(func.pg_advisory_xact_lock(194403)))
    if db.scalar(select(func.count()).select_from(DeviceGroup)) >= 100:
        raise HTTPException(409, "device_group_limit")
    group = DeviceGroup(name=data.name)
    db.add(group)
    return save(group, data, request, db, actor, "device_group_created")


@router.put("/{group_id}")
def update_group(group_id: UUID, data: GroupInput, request: Request, db: Db, actor: Operator) -> GroupView:
    return save(group_for_update(db, group_id), data, request, db, actor, "device_group_changed")


@router.delete("/{group_id}", status_code=204, response_class=Response)
def delete_group(group_id: UUID, request: Request, db: Db, actor: Operator):
    db.delete(group_for_update(db, group_id))
    audit(db, request, "device_group_deleted", actor=actor, details={"group_id": str(group_id)})
    db.commit()
