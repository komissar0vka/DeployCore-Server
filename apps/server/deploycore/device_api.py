import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import Text, cast, delete, func, insert, or_, select, text, update
from sqlalchemy.exc import IntegrityError

from . import device_schemas as wire
from .device_models import Agent, Device, DeviceEvent, DeviceInventory, EnrollmentToken, InstalledSoftware
from .models import AuditEvent, Installation, User
from .security import Db, Permission, audit, digest, require

router = APIRouter(prefix="/api/v1")
Reader = Annotated[User, Depends(require(Permission.READ))]
Operator = Annotated[User, Depends(require(Permission.MANAGE_OPERATIONS))]
agent_bearer = HTTPBearer(auto_error=False, scheme_name="DeployCoreAgent")
Bearer = Annotated[HTTPAuthorizationCredentials | None, Security(agent_bearer)]


def clock() -> datetime:
    return datetime.now(UTC)


def heartbeat_interval(db: Db) -> int:
    return db.get_one(Installation, 1).heartbeat_seconds


def cutoff(db: Db, now: datetime) -> datetime:
    return now - timedelta(seconds=max(180, heartbeat_interval(db) * 3))


def live_device(db: Db, device_id: UUID, *, lock: bool = False) -> Device:
    device = db.get(Device, device_id, with_for_update=lock)
    if device is None or device.deleted_at is not None:
        raise HTTPException(404, "device_not_found")
    return device


def record_event(db: Db, device: Device, action: str, actor: User | None = None) -> None:
    db.add(DeviceEvent(device_id=device.id, action=action, actor_id=actor.id if actor else None))


def connection(db: Db, device: Device) -> wire.Connection:
    return wire.Connection(device_id=device.id, heartbeat_seconds=heartbeat_interval(db), last_seen_at=device.last_seen_at)


def enroll_commit(db: Db) -> None:
    try:
        db.commit()
    except IntegrityError as error:
        db.rollback()
        if getattr(error.orig, "sqlstate", None) != "23505":
            raise
        raise HTTPException(409, "registration_conflict") from None


def require_agent(device_id: UUID, db: Db, bearer: Bearer) -> Device:
    if bearer is None or len(bearer.credentials) != 43:
        raise HTTPException(401, "agent_unauthorized")
    device = db.get(Device, device_id, with_for_update=True)
    agent = db.get(Agent, device_id)
    if (device is None or device.deleted_at is not None or agent is None or agent.revoked_at is not None
            or not secrets.compare_digest(agent.credential_hash, digest(bearer.credentials))):
        raise HTTPException(401, "agent_unauthorized")
    return device


AgentDevice = Annotated[Device, Depends(require_agent)]


@router.post("/agent/enroll", tags=["Agent"])
def enroll(data: wire.Enroll, db: Db) -> wire.Connection:
    token_hash = digest(data.enrollment_token)
    credential_hash = digest(data.credential)
    candidate = db.execute(select(EnrollmentToken.id, EnrollmentToken.device_id)
                           .where(EnrollmentToken.token_hash == token_hash)).one_or_none()
    if candidate is None:
        raise HTTPException(403, "enrollment_invalid")
    token_id, target_id = candidate
    if target_id is not None and target_id != data.installation_id:
        raise HTTPException(409, "registration_conflict")
    device_id = data.installation_id
    if target_id is None:
        db.execute(text("SELECT pg_advisory_xact_lock(492403, hashtext(:device))"), {"device": str(device_id)})
    device = db.get(Device, device_id, with_for_update=True)
    token = db.get_one(EnrollmentToken, token_id, with_for_update=True)
    now = clock()
    if token.revoked_at is not None or token.expires_at <= now:
        raise HTTPException(403, "enrollment_invalid")
    prior = db.get(Agent, device_id)
    if device is not None and device.deleted_at is not None:
        raise HTTPException(409, "registration_conflict")
    if prior is not None and prior.enrollment_id == token.id and prior.revoked_at is None:
        if secrets.compare_digest(prior.credential_hash, credential_hash):
            result = connection(db, device)
            db.commit()
            return result
        # A targeted token may only bind to the first credential it issued.
        raise HTTPException(409, "registration_conflict")
    if token.uses >= token.max_uses:
        raise HTTPException(403, "enrollment_invalid")
    metadata = data.heartbeat.model_dump(mode="json")
    if target_id is None:
        if device is not None:
            raise HTTPException(409, "registration_conflict")
        device = Device(id=device_id, last_seen_at=now, **metadata)
        db.add(device)
        db.flush()
        db.add(Agent(device_id=device_id, credential_hash=credential_hash, enrollment_id=token.id, issued_at=now))
        record_event(db, device, "registered")
    else:
        if device is None or prior is None or prior.credential_hash == credential_hash:
            raise HTTPException(409, "registration_conflict")
        for key, value in metadata.items():
            setattr(device, key, value)
        device.last_seen_at = now
        prior.credential_hash = credential_hash
        prior.enrollment_id = token.id
        prior.issued_at = now
        prior.revoked_at = None
        record_event(db, device, "agent_recovered")
    token.uses += 1
    result = connection(db, device)
    enroll_commit(db)
    return result


@router.post("/agent/{device_id}/heartbeat", tags=["Agent"])
def heartbeat(data: wire.Heartbeat, db: Db, device: AgentDevice) -> wire.Connection:
    now = clock()
    if device.last_seen_at < cutoff(db, now):
        record_event(db, device, "reconnected")
    if device.hostname != data.hostname or device.fqdn != data.fqdn:
        record_event(db, device, "name_changed")
    for key, value in data.model_dump(mode="json").items():
        setattr(device, key, value)
    device.last_seen_at = now
    result = connection(db, device)
    db.commit()
    return result


@router.put("/agent/{device_id}/inventory", tags=["Agent"], status_code=204, response_class=Response)
def upload_inventory(data: wire.Inventory, db: Db, device: AgentDevice) -> None:
    hardware = data.hardware.model_dump(mode="json")
    software = sorted({(item.name, item.version, item.publisher) for item in data.software})
    fingerprint = digest(json.dumps([hardware, software], sort_keys=True, ensure_ascii=False))
    current = db.get(DeviceInventory, device.id)
    now = clock()
    if current is None:
        db.add(DeviceInventory(device_id=device.id, hardware=hardware, fingerprint=fingerprint, collected_at=now))
    else:
        current.collected_at = now
    if current is None or current.fingerprint != fingerprint:
        if current is not None:
            current.hardware, current.fingerprint = hardware, fingerprint
        db.execute(delete(InstalledSoftware).where(InstalledSoftware.device_id == device.id))
        if software:
            db.execute(insert(InstalledSoftware), [
                {"device_id": device.id, "name": name, "version": version, "publisher": publisher}
                for name, version, publisher in software
            ])
        record_event(db, device, "inventory_updated")
    db.commit()


@router.post("/agent/{device_id}/issues", tags=["Agent"], status_code=204, response_class=Response)
def report_agent_issue(data: wire.AgentIssue, db: Db, device: AgentDevice) -> None:
    recent = db.scalar(select(DeviceEvent.id).where(
        DeviceEvent.device_id == device.id, DeviceEvent.action == data.action,
        DeviceEvent.created_at >= clock() - timedelta(hours=1),
    ).limit(1))
    if recent is None:
        record_event(db, device, data.action)
    db.commit()


def present(device: Device, agent: Agent, since: datetime) -> wire.DeviceView:
    return wire.DeviceView(
        **wire.Heartbeat.model_validate(device).model_dump(), id=device.id, last_seen_at=device.last_seen_at,
        online=agent.revoked_at is None and device.last_seen_at >= since, agent_revoked=agent.revoked_at is not None,
    )


@router.get("/devices", tags=["Devices"])
def devices(
    db: Db, actor: Reader, q: Annotated[str, Query(max_length=120)] = "",
    status: Literal["all", "online", "offline", "revoked"] = "all",
    offset: Annotated[int, Query(ge=0, le=100000)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    sort: Literal["hostname", "status", "os", "agent", "last_seen"] = "hostname",
    direction: Literal["asc", "desc"] = "asc",
    agent_version: Annotated[str, Query(min_length=1, max_length=64)] | None = None,
) -> wire.DevicePage:
    since = cutoff(db, clock())
    online = (Agent.revoked_at.is_(None)) & (Device.last_seen_at >= since)
    query = select(Device, Agent).join(Agent, Agent.device_id == Device.id).where(Device.deleted_at.is_(None))
    if (term := q.strip()):
        query = query.where(or_(
            Device.hostname.icontains(term, autoescape=True),
            Device.fqdn.icontains(term, autoescape=True),
            cast(Device.ips, Text).icontains(term, autoescape=True),
        ))
    if status == "revoked":
        query = query.where(Agent.revoked_at.is_not(None))
    elif status != "all":
        query = query.where(online if status == "online" else ~online)
    if agent_version is not None:
        query = query.where(Device.agent_version == agent_version)
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    order_column = {
        "hostname": Device.hostname, "status": online, "os": Device.os_version,
        "agent": Device.agent_version, "last_seen": Device.last_seen_at,
    }[sort]
    ordering = order_column.asc() if direction == "asc" else order_column.desc()
    rows = db.execute(query.order_by(ordering, Device.id).offset(offset).limit(limit)).all()
    result = wire.DevicePage(items=[present(device, agent, since) for device, agent in rows], total=total)
    db.commit()
    return result


@router.get("/devices/summary", tags=["Devices"])
def fleet_summary(db: Db, actor: Reader) -> wire.FleetSummary:
    since = cutoff(db, clock())
    online = Agent.revoked_at.is_(None) & (Device.last_seen_at >= since)
    counts = db.execute(
        select(Device.agent_version, func.count(), func.count().filter(online))
        .join(Agent, Agent.device_id == Device.id)
        .where(Device.deleted_at.is_(None)).group_by(Device.agent_version).order_by(Device.agent_version)
    ).all()
    recent = select(DeviceEvent, Device.hostname).join(Device, Device.id == DeviceEvent.device_id)
    recent = recent.order_by(DeviceEvent.id.desc()).limit(10)
    events = [wire.FleetEvent(id=entry.id, action=entry.action, hostname=hostname, created_at=entry.created_at)
              for entry, hostname in db.execute(recent)]
    warnings = recent.where(DeviceEvent.action.in_(("agent_revoked", "inventory_failed")))
    errors = [wire.FleetError(action=entry.action, hostname=hostname, created_at=entry.created_at)
              for entry, hostname in db.execute(warnings)]
    if actor.role == "super_admin":
        failures = db.scalars(select(AuditEvent).where(AuditEvent.action == "login_failed")
                              .order_by(AuditEvent.created_at.desc()).limit(10))
        errors.extend(wire.FleetError(action=entry.action, created_at=entry.created_at) for entry in failures)
    total = sum(count for _, count, _ in counts)
    active = sum(count for _, _, count in counts)
    result = wire.FleetSummary(
        total=total, online=active, offline=total - active,
        versions={version: count for version, count, _ in counts},
        events=events, errors=sorted(errors, key=lambda entry: entry.created_at, reverse=True)[:10],
    )
    db.commit()
    return result


@router.get("/devices/{device_id}", tags=["Devices"])
def device_detail(device_id: UUID, db: Db, actor: Reader) -> wire.DeviceDetail:
    device = live_device(db, device_id)
    inventory = db.get(DeviceInventory, device_id)
    software = db.scalars(select(InstalledSoftware).where(InstalledSoftware.device_id == device_id)
                          .order_by(InstalledSoftware.name, InstalledSoftware.id)).all()
    events = db.scalars(select(DeviceEvent).where(DeviceEvent.device_id == device_id)
                        .order_by(DeviceEvent.id.desc()).limit(100)).all()
    result = wire.DeviceDetail(
        device=present(device, db.get_one(Agent, device_id), cutoff(db, clock())),
        inventory=inventory, software=software, events=events,
    )
    db.commit()
    return result


@router.get("/enrollment-tokens", tags=["Enrollment"])
def list_tokens(db: Db, actor: Operator, offset: Annotated[int, Query(ge=0, le=100000)] = 0) -> list[wire.TokenView]:
    tokens = db.scalars(select(EnrollmentToken)
                        .order_by(EnrollmentToken.created_at.desc(), EnrollmentToken.id)
                        .offset(offset).limit(100)).all()
    db.commit()
    return tokens


@router.post("/enrollment-tokens", tags=["Enrollment"], status_code=201)
def create_token(data: wire.TokenInput, request: Request, db: Db, actor: Operator) -> wire.IssuedToken:
    if data.device_id is not None:
        device = live_device(db, data.device_id, lock=True)
        revoke_recovery_tokens(db, device.id, clock())
        record_event(db, device, "recovery_issued", actor)
    raw = secrets.token_urlsafe(32)
    token = EnrollmentToken(
        token_hash=digest(raw), label=data.label, expires_at=clock() + timedelta(minutes=data.ttl_minutes),
        max_uses=data.max_uses, uses=0, created_by=actor.id, device_id=data.device_id,
    )
    db.add(token)
    db.flush()
    details = {"token_id": str(token.id)}
    if data.device_id:
        details["device_id"] = str(data.device_id)
    audit(db, request, "enrollment_created", actor=actor, details=details)
    db.commit()
    return wire.IssuedToken(token=raw, enrollment=wire.TokenView.model_validate(token))


@router.delete("/enrollment-tokens/{token_id}", tags=["Enrollment"], status_code=204, response_class=Response)
def revoke_token(token_id: UUID, request: Request, db: Db, actor: Operator) -> None:
    token = db.get(EnrollmentToken, token_id, with_for_update=True)
    if token is None:
        raise HTTPException(404, "token_not_found")
    if token.revoked_at is None:
        token.revoked_at = clock()
        audit(db, request, "enrollment_revoked", actor=actor, details={"token_id": str(token.id)})
    db.commit()


def revoke_recovery_tokens(db: Db, device_id: UUID, now: datetime) -> None:
    db.execute(update(EnrollmentToken).where(
        EnrollmentToken.device_id == device_id, EnrollmentToken.revoked_at.is_(None),
    ).values(revoked_at=now))


@router.delete("/devices/{device_id}/agent", tags=["Devices"], status_code=204, response_class=Response)
def revoke_agent(device_id: UUID, request: Request, db: Db, actor: Operator) -> None:
    device = live_device(db, device_id, lock=True)
    agent = db.get_one(Agent, device.id)
    now = clock()
    revoke_recovery_tokens(db, device.id, now)
    if agent.revoked_at is None:
        agent.revoked_at = now
        record_event(db, device, "agent_revoked", actor)
        audit(db, request, "agent_revoked", actor=actor, details={"device_id": str(device.id)})
    db.commit()


@router.delete("/devices/{device_id}", tags=["Devices"], status_code=204, response_class=Response)
def delete_device(device_id: UUID, request: Request, db: Db, actor: Operator) -> None:
    device = live_device(db, device_id, lock=True)
    agent = db.get_one(Agent, device.id)
    now = clock()
    from .job_api import cancel_deleted_device_targets

    cancel_deleted_device_targets(db, device.id)
    device.deleted_at = now
    agent.revoked_at = agent.revoked_at or now
    revoke_recovery_tokens(db, device.id, now)
    db.execute(delete(InstalledSoftware).where(InstalledSoftware.device_id == device.id))
    db.execute(delete(DeviceInventory).where(DeviceInventory.device_id == device.id))
    device.ips = []
    record_event(db, device, "device_deleted", actor)
    audit(db, request, "device_deleted", actor=actor, details={"device_id": str(device.id)})
    db.commit()
