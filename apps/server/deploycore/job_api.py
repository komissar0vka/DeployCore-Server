import os
import re
from datetime import datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select, text

from . import job_schemas as wire
from .device_api import AgentDevice
from .device_models import Agent, Device
from .job_models import DeploymentAttempt as Attempt, DeploymentEvent as Event, DeploymentJob as Job, DeploymentTarget as Target
from .models import User
from .package_models import PackageArtifact, PackageDetectionRule, SoftwarePackage, SoftwareVersion, artifact_approved
from .package_schemas import DetectionState
from .package_storage import artifact_path
from .security import PERMISSIONS, Db, Permission, Role, audit, require

router = APIRouter(prefix="/api/v1")
Reader = Annotated[User, Depends(require(Permission.READ))]
Operator = Annotated[User, Depends(require(Permission.MANAGE_OPERATIONS))]
LEASE = timedelta(seconds=120)
ACTIVE = ("leased", "running", "awaiting_reboot", "unknown")
REBOOT_WINDOW = timedelta(hours=24)
GROUP_KINDS = ("all", "any")
MAX_ATTEMPTS = 5


def execution_enabled() -> bool:
    return os.getenv("DEPLOYCORE_ENABLE_EXECUTION") == "1"


def supports_execution(version: str, minimum: tuple[int, int, int] = (0, 3, 4)) -> bool:
    return bool(re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}", version)) and tuple(map(int, version.split("."))) >= minimum


def agent_capabilities(request: Request) -> set[str]:
    return {item.strip() for item in request.headers.get("x-deploycore-capabilities", "").split(",")}


def detection_capable(request: Request, device: Device) -> bool:
    return supports_execution(device.agent_version, (0, 3, 5)) and "detection_v1" in agent_capabilities(request)


def validate_execution(version, detection, operation):
    args = version.uninstall_args if operation == "uninstall" else version.install_args
    if sum(len(arg.encode()) for arg in args or []) > 8192:
        raise HTTPException(422, "deployment_manifest_invalid")
    if version.installer != "msi":
        if operation == "uninstall" and not version.uninstall_args:
            raise HTTPException(422, "deployment_manifest_invalid")
        return
    if operation == "uninstall" and detection.kind != "msi_product":
        if detection.kind not in GROUP_KINDS or sum(
            leaf["kind"] == "msi_product" for leaf in detection.data["rules"]
        ) != 1:
            raise HTTPException(422, "deployment_manifest_invalid")
    flags = 0
    for arg in args or []:
        if arg.lower() in {"/qn", "/qb"}:
            flags += 1
        elif arg.lower() != "/norestart" and (
            not re.fullmatch(r"[A-Z][A-Z0-9_]{0,71}=.*", arg)
            or arg.partition("=")[0] in {"TRANSFORMS", "PATCH", "REBOOT", "REBOOTPROMPT", "ACTION", "SOURCELIST"}
        ):
            raise HTTPException(422, "deployment_manifest_invalid")
    if flags > 1:
        raise HTTPException(422, "deployment_manifest_invalid")


def clock(db: Db):
    return db.scalar(select(func.clock_timestamp()))


def job_row(db: Db, job_id: UUID):
    row = db.execute(
        select(Job, SoftwareVersion.version, SoftwarePackage.name)
        .join(SoftwareVersion, SoftwareVersion.id == Job.version_id)
        .join(SoftwarePackage, SoftwarePackage.id == SoftwareVersion.package_id)
        .where(Job.id == job_id)
    ).one_or_none()
    if row is None:
        raise HTTPException(404, "deployment_not_found")
    return row


def counts_for(db: Db, ids: list[UUID]) -> dict:
    counts: dict = {job_id: {} for job_id in ids}
    for job_id, state, count in db.execute(
        select(Target.job_id, Target.state, func.count()).where(Target.job_id.in_(ids))
        .group_by(Target.job_id, Target.state)
    ):
        counts[job_id][state] = count
    return counts


def view(job: Job, version: str, name: str, counts: dict) -> wire.JobView:
    return wire.JobView(id=job.id, version_id=job.version_id, package_name=name, version=version,
                        operation=job.operation, mode=job.mode, created_at=job.created_at, counts=counts)


def get_view(db: Db, job_id: UUID) -> wire.JobView:
    return view(*job_row(db, job_id), counts_for(db, [job_id])[job_id])


def event(db: Db, job_id: UUID, action: str, target: Target | None = None, attempt: Attempt | None = None):
    db.add(Event(job_id=job_id, action=action, target_id=target.id if target else None,
                 attempt_id=attempt.id if attempt else None))


def last_attempt(db: Db, target_id: UUID) -> Attempt | None:
    return db.scalar(select(Attempt).where(Attempt.target_id == target_id).order_by(Attempt.number.desc()).limit(1))


@router.post("/deployments", tags=["Deployments"], status_code=201)
def create_job(data: wire.JobInput, request: Request, db: Db, actor: Operator) -> wire.JobView:
    if data.mode == "execute_v1" and data.operation == "uninstall" and Permission.MANAGE_REMOVALS not in PERMISSIONS[Role(actor.role)]:
        raise HTTPException(403, "permission_denied")
    db.execute(text("SELECT pg_advisory_xact_lock(4, hashtext(:key))"),
               {"key": f"{actor.id}:{data.request_id}"})
    existing = db.scalar(select(Job).where(Job.created_by == actor.id, Job.request_id == data.request_id))
    if existing is not None:
        device_ids = set(db.scalars(select(Target.device_id).where(Target.job_id == existing.id)))
        if existing.version_id != data.version_id or existing.operation != data.operation or existing.mode != data.mode or device_ids != set(data.device_ids):
            raise HTTPException(409, "deployment_request_conflict")
        result = get_view(db, existing.id)
        db.commit()
        return result

    # Device operations and agent requests acquire the device lock before target/package locks.
    devices = list(db.execute(
        select(Device.id, Device.agent_version).join(Agent, Agent.device_id == Device.id)
        .where(Device.id.in_(data.device_ids), Device.deleted_at.is_(None), Device.management_state == "managed", Agent.revoked_at.is_(None))
        .order_by(Device.id).with_for_update(of=Device)
    ))
    revoked = db.scalar(select(Agent.device_id).where(
        Agent.device_id.in_(data.device_ids), Agent.revoked_at.is_not(None),
    ).limit(1))
    if len(devices) != len(data.device_ids) or revoked is not None:
        raise HTTPException(422, "deployment_devices_unavailable")

    package = db.scalar(
        select(SoftwarePackage).join(SoftwareVersion, SoftwareVersion.package_id == SoftwarePackage.id)
        .where(SoftwareVersion.id == data.version_id).with_for_update(of=SoftwarePackage)
    )
    if package is None or package.archived_at is not None:
        raise HTTPException(409, "deployment_version_unavailable")
    version = db.get_one(SoftwareVersion, data.version_id, with_for_update={"read": True}, populate_existing=True)
    artifact = db.get(PackageArtifact, data.version_id)
    if not artifact_approved(version, artifact):
        raise HTTPException(409, "deployment_version_unavailable")
    if not artifact_path(data.version_id).is_file():
        raise HTTPException(503, "package_storage_unavailable")
    if data.operation == "uninstall" and version.uninstall_args is None:
        raise HTTPException(409, "deployment_uninstall_unavailable")
    minimum_agent = (0, 3, 4)
    if data.mode == "execute_v1":
        if not execution_enabled():
            raise HTTPException(409, "deployment_execution_disabled")
        rule = db.get_one(PackageDetectionRule, data.version_id)
        validate_execution(version, rule, data.operation)
        if rule.kind in GROUP_KINDS:
            minimum_agent = (0, 3, 5)
    if data.mode == "execute_v1" and not all(supports_execution(agent_version, minimum_agent) for _, agent_version in devices):
        raise HTTPException(422, "deployment_agent_incompatible")

    job = Job(version_id=data.version_id, artifact_sha256=artifact.sha256, operation=data.operation,
              created_by=actor.id, request_id=data.request_id, mode=data.mode)
    db.add(job)
    db.flush()
    db.add_all(Target(job_id=job.id, device_id=device_id) for device_id, _ in devices)
    event(db, job.id, "created")
    audit(db, request, "deployment_created", actor=actor,
          details={"job_id": str(job.id), "version_id": str(job.version_id), "operation": job.operation,
                   "target_count": str(len(devices)), "mode": data.mode})
    result = view(job, version.version, package.name, {"queued": len(devices)})
    db.commit()
    return result


def job_matches_scope(scope: wire.JobScope, now: datetime):
    if scope == "active":
        return select(Target.id).where(Target.job_id == Job.id, Target.state.in_(("queued", *ACTIVE))).exists()
    expired = select(Attempt.id).where(Attempt.target_id == Target.id, or_(
        (Target.state == "running") & Attempt.finished_at.is_(None) & (Attempt.lease_expires_at <= now),
        (Target.state == "awaiting_reboot") & Attempt.reboot_finished_at.is_(None) & (Attempt.reboot_deadline <= now),
    )).exists()
    return select(Target.id).where(Target.job_id == Job.id, or_(Target.state.in_(("failed", "unknown")), expired)).exists()


@router.get("/deployments", tags=["Deployments"])
def list_jobs(db: Db, actor: Reader, offset: Annotated[int, Query(ge=0, le=100000)] = 0,
              limit: Annotated[int, Query(ge=1, le=100)] = 25,
              q: Annotated[str, Query(max_length=160)] = "", scope: wire.JobScope = "all",
              operation: wire.Operation | None = None, device_id: UUID | None = None,
              direction: Literal["asc", "desc"] = "desc") -> wire.JobPage:
    now = clock(db)
    active, problem = job_matches_scope("active", now), job_matches_scope("problem", now)
    query = (select(Job, SoftwareVersion.version, SoftwarePackage.name)
             .join(SoftwareVersion, SoftwareVersion.id == Job.version_id)
             .join(SoftwarePackage, SoftwarePackage.id == SoftwareVersion.package_id))
    if term := q.strip():
        query = query.where(or_(SoftwarePackage.name.icontains(term, autoescape=True),
                                SoftwareVersion.version.icontains(term, autoescape=True)))
    if operation is not None:
        query = query.where(Job.operation == operation)
    if device_id is not None:
        query = query.where(select(Target.id).where(Target.job_id == Job.id, Target.device_id == device_id).exists())
    if scope != "all":
        query = query.where(active if scope == "active" else problem)
    order = Job.created_at.asc() if direction == "asc" else Job.created_at.desc()
    rows = db.execute(query.order_by(order, Job.id).offset(offset).limit(limit)).all()
    counts = counts_for(db, [row[0].id for row in rows])
    active_count, problem_count = db.execute(select(
        func.count().filter(active), func.count().filter(problem),
    ).select_from(Job)).one()
    result = wire.JobPage(items=[view(*row, counts[row[0].id]) for row in rows],
                          total=db.scalar(select(func.count()).select_from(query.subquery())),
                          active=active_count, problem=problem_count)
    db.commit()
    return result


def retry_requires_admin(attempt_outcome, reboot_deadline, reboot_observation) -> bool:
    return attempt_outcome == "unknown" or (reboot_deadline is not None and reboot_observation in (None, "unknown"))


@router.get("/deployments/{job_id}", tags=["Deployments"])
def job_detail(job_id: UUID, db: Db, actor: Reader) -> wire.JobDetail:
    summary = get_view(db, job_id)
    now = clock(db)
    latest = (select(Attempt).where(Attempt.target_id == Target.id).order_by(Attempt.number.desc())
              .limit(1).correlate(Target).lateral())
    rows = db.execute(
        select(Target, Device.hostname, latest.c.number, latest.c.lease_expires_at,
               latest.c.stage, latest.c.exit_code, latest.c.diagnostic, latest.c.output_bytes,
               latest.c.started_at, latest.c.process_started, latest.c.detection, latest.c.reboot_deadline, latest.c.reboot_detection,
               latest.c.reboot_finished_at, latest.c.outcome).select_from(Target)
        .join(Device, Device.id == Target.device_id).outerjoin(latest, text("true"))
        .where(Target.job_id == job_id).order_by(Device.hostname, Device.id)
    )
    targets = [wire.TargetView(
        id=target.id, device_id=target.device_id, hostname=name, state=target.state,
        cancel_requested=target.cancel_requested, attempt=number, lease_expires_at=expires if target.state in ("leased", "running", "unknown") else None,
        recovery_required=target.state == "unknown" or (target.state == "running" and expires is not None and expires <= now)
        or (target.state == "awaiting_reboot" and deadline is not None and deadline <= now),
        stage=stage, exit_code=code, diagnostic=diagnostic, output_bytes=output,
        started_at=started, process_started=launched, detection=observation, reboot_deadline=deadline, reboot_detection=reboot_observation,
        reboot_finished_at=reboot_finished,
        retry_requires_admin=retry_requires_admin(outcome, deadline, reboot_observation),
        reboot_diagnostic=reboot_diagnostic(target.state, reboot_observation, reboot_finished),
    ) for target, name, number, expires, stage, code, diagnostic, output, started, launched, observation, deadline,
          reboot_observation, reboot_finished, outcome in rows]
    db.commit()
    return wire.JobDetail(**summary.model_dump(), targets=targets)


@router.get("/deployments/{job_id}/events", tags=["Deployments"])
def job_events(job_id: UUID, db: Db, actor: Reader, before: Annotated[int, Query(ge=1)] | None = None,
               target_id: UUID | None = None) -> list[wire.EventView]:
    job_row(db, job_id)
    query = (select(Event, Attempt.number).outerjoin(Attempt, Attempt.id == Event.attempt_id)
             .where(Event.job_id == job_id))
    if before is not None:
        query = query.where(Event.id < before)
    if target_id is not None:
        query = query.where(Event.target_id == target_id)
    result = [wire.EventView(id=entry.id, target_id=entry.target_id, attempt_id=entry.attempt_id,
                             attempt_number=number, action=entry.action, created_at=entry.created_at)
              for entry, number in db.execute(query.order_by(Event.id.desc()).limit(50))]
    db.commit()
    return result


@router.post("/deployments/{job_id}/cancel", tags=["Deployments"])
def cancel_job(job_id: UUID, request: Request, db: Db, actor: Operator) -> wire.JobView:
    if db.get(Job, job_id) is None:
        raise HTTPException(404, "deployment_not_found")
    targets = list(db.scalars(select(Target).where(Target.job_id == job_id).order_by(Target.id).with_for_update()))
    now = clock(db)
    immediate = requested = 0
    for target in targets:
        if target.state in ("queued", "leased"):
            attempt = last_attempt(db, target.id) if target.state == "leased" else None
            if attempt is not None:
                attempt.finished_at, attempt.outcome = now, "cancelled"
            target.state = "cancelled"
            event(db, job_id, "cancelled", target, attempt)
            immediate += 1
        elif target.state == "running" and not target.cancel_requested:
            target.cancel_requested = True
            event(db, job_id, "cancel_requested", target, last_attempt(db, target.id))
            requested += 1
    if immediate or requested:
        audit(db, request, "deployment_cancelled", actor=actor,
              details={"job_id": str(job_id), "cancelled": str(immediate), "requested": str(requested)})
    result = get_view(db, job_id)
    db.commit()
    return result


def assignment(db: Db, target: Target, attempt: Attempt) -> wire.PollReply:
    job = db.get_one(Job, target.job_id)
    return wire.PollReply(assignment=wire.Assignment(
        target_id=target.id, attempt_id=attempt.id, version_id=job.version_id,
        operation=job.operation, mode=job.mode, lease_expires_at=attempt.lease_expires_at,
    ))


@router.post("/agent/{device_id}/jobs/poll", tags=["Agent Jobs"])
def poll(request: Request, db: Db, device: AgentDevice) -> wire.PollReply:
    execute = execution_enabled() and supports_execution(device.agent_version) and "execute_v1" in agent_capabilities(request)
    extended = detection_capable(request, device)
    # require_agent serializes requests for this device. The unique partial index is a second line of defense.
    active = db.scalar(select(Target).where(Target.device_id == device.id, Target.state.in_(ACTIVE)).with_for_update())
    if active is not None:
        attempt = last_attempt(db, active.id)
        if active.state == "awaiting_reboot":
            now = clock(db)
            if attempt.reboot_deadline <= now:
                finish_reboot(db, active, attempt, None, now)
            db.commit()
            return wire.PollReply(recovery_required=True)
        if active.state in ("running", "unknown"):
            db.commit()
            return wire.PollReply(recovery_required=True)
        now = clock(db)
        if attempt.lease_expires_at > now:
            job = db.get_one(Job, active.job_id)
            if job.mode == "execute_v1" and (
                not execute or (not extended and db.get_one(PackageDetectionRule, job.version_id).kind in GROUP_KINDS)
            ):
                db.commit()
                return wire.PollReply()
            reply = assignment(db, active, attempt)
            db.commit()
            return reply
        attempt.finished_at, attempt.outcome = now, "expired"
        active.state = "failed" if attempt.number == MAX_ATTEMPTS else "queued"
        event(db, active.job_id, "delivery_failed" if active.state == "failed" else "lease_expired", active, attempt)
        db.flush()
    target = db.scalar(
        select(Target).join(Job, Job.id == Target.job_id)
        .where(Target.device_id == device.id, Target.state == "queued", Job.mode.in_(("transport_only", "execute_v1") if execute else ("transport_only",)))
        .join(PackageDetectionRule, PackageDetectionRule.version_id == Job.version_id)
        .where(or_(Job.mode == "transport_only", PackageDetectionRule.kind.not_in(GROUP_KINDS)) if not extended else True)
        .order_by(Job.created_at, Job.id).limit(1).with_for_update(of=Target)
    )
    if target is None:
        db.commit()
        return wire.PollReply()
    previous = last_attempt(db, target.id)
    now = clock(db)
    attempt = Attempt(target_id=target.id, number=previous.number + 1 if previous else 1,
                      leased_at=now, lease_expires_at=now + LEASE)
    db.add(attempt)
    target.state = "leased"
    db.flush()
    event(db, target.job_id, "leased", target, attempt)
    reply = assignment(db, target, attempt)
    db.commit()
    return reply


def attempt_for(db: Db, device: Device, target_id: UUID, attempt_id: UUID) -> tuple[Target, Attempt]:
    target = db.scalar(select(Target).where(Target.id == target_id, Target.device_id == device.id).with_for_update())
    if target is None:
        raise HTTPException(404, "deployment_target_not_found")
    attempt = db.get(Attempt, attempt_id)
    if attempt is None or attempt.target_id != target.id:
        raise HTTPException(409, "deployment_lease_conflict")
    return target, attempt


def renew(db: Db, target: Target, attempt: Attempt, *, ack: bool, stage: wire.Stage | None = None) -> wire.LeaseReply:
    now = clock(db)
    if attempt.finished_at is not None or target.state not in ACTIVE:
        raise HTTPException(409, "deployment_lease_conflict")
    if attempt.acknowledged_at is None:
        if not ack or target.state != "leased" or attempt.lease_expires_at <= now:
            raise HTTPException(409, "deployment_lease_conflict")
        attempt.acknowledged_at = now
        target.state = "running"
        event(db, target.job_id, "acknowledged", target, attempt)
    elif target.state != "running":
        raise HTTPException(409, "deployment_lease_conflict")
    elif attempt.lease_expires_at <= now:
        event(db, target.job_id, "recovered", target, attempt)
    if stage is not None:
        if db.get_one(Job, target.job_id).mode != "execute_v1":
            raise HTTPException(409, "deployment_mode_conflict")
        if (attempt.started_at is None and stage not in ("checking", "downloading")) or (
            attempt.started_at is not None and stage not in ("executing", "verifying")
        ):
            raise HTTPException(409, "deployment_stage_conflict")
        if attempt.stage != stage:
            attempt.stage = stage
            event(db, target.job_id, stage, target, attempt)
    attempt.lease_expires_at = now + LEASE
    result = wire.LeaseReply(lease_expires_at=attempt.lease_expires_at, cancel_requested=target.cancel_requested)
    db.commit()
    return result


@router.post("/agent/{device_id}/jobs/{target_id}/ack", tags=["Agent Jobs"])
def acknowledge(target_id: UUID, data: wire.Lease, db: Db, device: AgentDevice) -> wire.LeaseReply:
    return renew(db, *attempt_for(db, device, target_id, data.attempt_id), ack=True)


@router.post("/agent/{device_id}/jobs/{target_id}/heartbeat", tags=["Agent Jobs"])
def heartbeat(target_id: UUID, data: wire.Heartbeat, db: Db, device: AgentDevice) -> wire.LeaseReply:
    return renew(db, *attempt_for(db, device, target_id, data.attempt_id), ack=False, stage=data.stage)


@router.post("/agent/{device_id}/jobs/{target_id}/result", tags=["Agent Jobs"], response_model_exclude_none=True)
def submit_result(target_id: UUID, data: wire.Result, request: Request, db: Db, device: AgentDevice) -> wire.Result:
    target, attempt = attempt_for(db, device, target_id, data.attempt_id)
    mode = db.get_one(Job, target.job_id).mode
    extended = data.detection is not None or data.reboot_pending or data.process_started is not None
    if extended and not detection_capable(request, device):
        raise HTTPException(409, "deployment_agent_incompatible")
    if data.reboot_pending and (data.outcome != "reboot_required" or data.process_started is not True):
        raise HTTPException(422, "deployment_result_conflict")
    execution_details = (data.exit_code, data.diagnostic, data.output_bytes, data.detection, data.process_started)
    invalid_transport = mode == "transport_only" and (
        data.outcome not in ("not_executed", "cancelled") or extended or any(x is not None for x in execution_details)
    )
    if invalid_transport or (mode == "execute_v1" and data.outcome == "not_executed"):
        raise HTTPException(422, "deployment_mode_conflict")
    if attempt.finished_at is not None:
        if attempt.diagnostic == "operator_resolved" and "closed_result_v1" in agent_capabilities(request):
            raise HTTPException(410, "deployment_attempt_closed")
        stored = (attempt.exit_code, attempt.diagnostic, attempt.output_bytes, attempt.detection, attempt.process_started)
        same_result = (data.outcome == attempt.outcome and execution_details == stored
                       and bool(data.reboot_pending) == (attempt.reboot_deadline is not None))
        if attempt.diagnostic != "operator_resolved" and (attempt.acknowledged_at is None or not same_result):
            raise HTTPException(409, "deployment_result_conflict")
    else:
        if attempt.acknowledged_at is None or target.state != "running":
            raise HTTPException(409, "deployment_lease_conflict")
        if data.outcome == "cancelled" and not target.cancel_requested:
            raise HTTPException(409, "deployment_cancel_not_requested")
        if data.process_started is not None and attempt.started_at is None:
            raise HTTPException(409, "deployment_start_required")
        if data.process_started is False and data.exit_code is not None:
            raise HTTPException(422, "deployment_result_conflict")
        if data.outcome in ("succeeded", "reboot_required") and (attempt.started_at is None or data.exit_code is None):
            raise HTTPException(409, "deployment_start_required")
        if data.outcome in ("already_installed", "already_absent") and attempt.started_at is not None:
            raise HTTPException(409, "deployment_already_started")
        attempt.outcome = data.outcome
        (attempt.exit_code, attempt.diagnostic, attempt.output_bytes,
         attempt.detection, attempt.process_started) = execution_details
        if data.detection is not None and attempt.started_at is not None and attempt.stage != "verifying":
            attempt.stage = "verifying"
            event(db, target.job_id, "verifying", target, attempt)
        attempt.finished_at = clock(db)
        target.state = data.outcome
        if data.reboot_pending:
            attempt.reboot_deadline = attempt.finished_at + REBOOT_WINDOW
            target.state = "awaiting_reboot"
        event(db, target.job_id, target.state, target, attempt)
    db.commit()
    return data


def reboot_diagnostic(state: str, observation: DetectionState | None,
                      finished: datetime | None) -> wire.Diagnostic | None:
    if finished is None:
        return None
    if observation is None:
        return "reboot_timeout"
    if observation == "unknown":
        return "detection_failed"
    return "detection_mismatch" if state == "failed" else None


def finish_reboot(db: Db, target: Target, attempt: Attempt, observation: DetectionState | None, now: datetime):
    attempt.reboot_detection = observation
    attempt.reboot_finished_at = now
    job = db.get_one(Job, target.job_id)
    desired = "installed" if job.operation == "install" else "not_installed"
    if observation in (None, "unknown"):
        target.state = "unknown"
    else:
        target.state = "succeeded" if observation == desired else "failed"
    event(db, target.job_id, reboot_diagnostic(target.state, observation, now) or "reboot_verified", target, attempt)


@router.post("/agent/{device_id}/jobs/{target_id}/reboot-result", tags=["Agent Jobs"], status_code=204)
def submit_reboot_result(target_id: UUID, data: wire.RebootResult, request: Request, db: Db, device: AgentDevice):
    if not detection_capable(request, device):
        raise HTTPException(409, "deployment_agent_incompatible")
    target, attempt = attempt_for(db, device, target_id, data.attempt_id)
    if attempt.reboot_deadline is None:
        if attempt.diagnostic == "operator_resolved" and "closed_result_v1" in agent_capabilities(request):
            raise HTTPException(410, "deployment_attempt_closed")
        raise HTTPException(409, "deployment_result_conflict")
    if attempt.reboot_finished_at is not None:
        if attempt.reboot_detection is not None and attempt.reboot_detection != data.detection:
            raise HTTPException(409, "deployment_result_conflict")
    elif target.state == "awaiting_reboot":
        now = clock(db)
        finish_reboot(db, target, attempt, data.detection if now < attempt.reboot_deadline else None, now)
    else:
        raise HTTPException(409, "deployment_result_conflict")
    expired_observation = data.detection is not None and attempt.reboot_detection is None
    db.commit()
    if expired_observation and "closed_result_v1" in agent_capabilities(request):
        raise HTTPException(410, "deployment_attempt_closed")


def cancel_deleted_device_targets(db: Db, device_id: UUID, *, diagnostic: wire.Diagnostic = "device_removed") -> None:
    """Close work that can no longer be delivered to the device."""
    targets = db.scalars(select(Target).where(
        Target.device_id == device_id, Target.state.in_(("queued", "leased", "running")),
    ).order_by(Target.id).with_for_update())
    now = clock(db)
    for target in targets:
        attempt = last_attempt(db, target.id)
        if attempt is not None and attempt.started_at is not None:
            target.state = "unknown"
            attempt.finished_at, attempt.outcome, attempt.diagnostic = now, "unknown", diagnostic
        else:
            target.state = "cancelled"
            if attempt is not None and attempt.finished_at is None:
                attempt.finished_at, attempt.outcome, attempt.diagnostic = now, "cancelled", diagnostic
        event(db, target.job_id, diagnostic, target, attempt)
