from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse

from . import job_schemas as wire
from . import package_schemas as catalog
from .device_api import AgentDevice
from .job_api import ACTIVE, GROUP_KINDS, LEASE, attempt_for, clock, detection_capable, event, execution_enabled, get_view, last_attempt, portable_capable, retry_requires_admin
from .job_models import DeploymentJob as Job, DeploymentTarget as Target
from .models import User
from .package_models import PackageArtifact, PackageDetectionRule, SoftwarePackage, SoftwareVersion, artifact_approved
from .package_storage import artifact_path
from .security import Db, Permission, audit, require

router = APIRouter(prefix="/api/v1")
SystemAdmin = Annotated[User, Depends(require(Permission.MANAGE_SYSTEM))]


class Manifest(wire.Wire):
    installer: str
    architecture: str
    size_bytes: int
    sha256: str
    args: list[str]
    detection: catalog.Detection
    timeout_seconds: int
    success_codes: list[int]
    min_windows_build: int | None
    reboot_required: bool
    package_id: UUID | None = None


def permitted(db, device, target_id, attempt_id, request):
    target, attempt = attempt_for(db, device, target_id, attempt_id)
    job = db.get_one(Job, target.job_id)
    now = clock(db)
    if (not execution_enabled() or job.mode != "execute_v1" or target.state != "running"
            or target.cancel_requested or attempt.acknowledged_at is None or attempt.finished_at is not None
            or attempt.lease_expires_at <= now or attempt.started_at is not None):
        raise HTTPException(409, "deployment_execution_not_permitted")
    version = db.get_one(SoftwareVersion, job.version_id)
    package = db.get_one(SoftwarePackage, version.package_id, with_for_update={"read": True})
    version = db.get_one(SoftwareVersion, version.id, with_for_update={"read": True}, populate_existing=True)
    artifact = db.get(PackageArtifact, version.id)
    if (package.archived_at is not None or not artifact_approved(version, artifact)
            or job.artifact_sha256 != artifact.sha256):
        raise HTTPException(409, "deployment_version_unavailable")
    rule = db.get_one(PackageDetectionRule, version.id)
    if version.installer == "portable" and not portable_capable(request, device):
        raise HTTPException(409, "deployment_agent_incompatible")
    if rule.kind in GROUP_KINDS and not detection_capable(request, device):
        raise HTTPException(409, "deployment_agent_incompatible")
    return target, attempt, job, version, artifact, rule, now


@router.get("/agent/{device_id}/jobs/{target_id}/manifest", tags=["Agent Execution"])
def manifest(target_id: UUID, attempt_id: UUID, request: Request, db: Db, device: AgentDevice) -> Manifest:
    _, _, job, version, artifact, rule, _ = permitted(db, device, target_id, attempt_id, request)
    result = Manifest(installer=version.installer, architecture=version.architecture, size_bytes=artifact.size_bytes,
                      sha256=artifact.sha256, args=version.uninstall_args if job.operation == "uninstall" else version.install_args,
                      detection={"kind": rule.kind, **rule.data}, timeout_seconds=version.timeout_seconds,
                      success_codes=version.success_codes, min_windows_build=version.min_windows_build,
                      reboot_required=version.reboot_required, package_id=version.package_id if version.installer == "portable" else None)
    db.commit()
    return result


@router.get("/agent/{device_id}/jobs/{target_id}/artifact", tags=["Agent Execution"], response_class=FileResponse)
def download(target_id: UUID, attempt_id: UUID, request: Request, db: Db, device: AgentDevice):
    _, _, _, version, artifact, _, _ = permitted(db, device, target_id, attempt_id, request)
    path = artifact_path(version.id, artifact.storage_key)
    try:
        if not path.is_file() or path.stat().st_size != artifact.size_bytes:
            raise HTTPException(503, "package_storage_unavailable")
    except OSError as exc:
        raise HTTPException(503, "package_storage_unavailable") from exc
    db.commit()
    return FileResponse(path, media_type="application/octet-stream", headers={"X-DeployCore-SHA256": artifact.sha256})


@router.post("/agent/{device_id}/jobs/{target_id}/start", tags=["Agent Execution"])
def start(target_id: UUID, data: wire.Lease, request: Request, db: Db, device: AgentDevice) -> wire.LeaseReply:
    target, attempt, _, _, _, _, now = permitted(db, device, target_id, data.attempt_id, request)
    attempt.started_at = now
    attempt.stage = "executing"
    attempt.lease_expires_at = now + LEASE
    event(db, target.job_id, "executing", target, attempt)
    result = wire.LeaseReply(lease_expires_at=attempt.lease_expires_at, cancel_requested=False)
    db.commit()
    return result


@router.post("/deployments/{job_id}/targets/{target_id}/resolve", tags=["Deployments"])
def resolve(job_id: UUID, target_id: UUID, data: wire.Resolve, request: Request, db: Db, actor: SystemAdmin) -> wire.JobView:
    target = db.get(Target, target_id, with_for_update=True)
    if target is None or target.job_id != job_id:
        raise HTTPException(404, "deployment_target_not_found")
    attempt = last_attempt(db, target.id)
    now = clock(db)
    if target.state not in ACTIVE or attempt is None or (
        target.state != "unknown" and not (
            (target.state == "running" and attempt.lease_expires_at <= now)
            or (target.state == "awaiting_reboot" and attempt.reboot_deadline <= now)
        )
    ):
        raise HTTPException(409, "deployment_resolution_unavailable")
    if attempt.finished_at is None:
        attempt.finished_at = now
        attempt.outcome = "unknown"
        attempt.diagnostic = "operator_resolved"
    if target.state in ("unknown", "awaiting_reboot"):
        if attempt.reboot_deadline is not None and attempt.reboot_finished_at is None:
            attempt.reboot_finished_at = now
    target.state = "failed"
    event(db, target.job_id, "operator_resolved", target, attempt)
    audit(db, request, "deployment_resolved", actor=actor,
          details={"job_id": str(job_id), "target_id": str(target_id)})
    result = get_view(db, job_id)
    db.commit()
    return result


class Retry(wire.Wire):
    request_id: UUID


Operator = Annotated[User, Depends(require(Permission.MANAGE_OPERATIONS))]


@router.post("/deployments/{job_id}/targets/{target_id}/retry", tags=["Deployments"], status_code=201)
def retry(job_id: UUID, target_id: UUID, data: Retry, request: Request, db: Db, actor: Operator) -> wire.JobView:
    from .job_api import create_job

    target = db.get(Target, target_id)
    if target is None or target.job_id != job_id:
        raise HTTPException(404, "deployment_target_not_found")
    if target.state != "failed":
        raise HTTPException(409, "deployment_retry_unavailable")
    attempt = last_attempt(db, target.id)
    if attempt is not None and retry_requires_admin(attempt.outcome, attempt.reboot_deadline, attempt.reboot_detection) and actor.role != "super_admin":
        raise HTTPException(403, "permission_denied")
    job = db.get_one(Job, job_id)
    return create_job(wire.JobInput(version_id=job.version_id, mode=job.mode, operation=job.operation,
                                    request_id=data.request_id, device_ids=[target.device_id]), request, db, actor)
