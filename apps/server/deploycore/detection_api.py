from datetime import datetime, timedelta
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import func, select, text

from .device_api import AgentDevice
from .device_models import Agent, Device
from .detection_models import DetectionPreview
from .job_api import Operator, clock, detection_capable, supports_execution
from .package_models import PackageDetectionRule, SoftwarePackage, SoftwareVersion
from .package_schemas import Detection, DetectionState, Wire
from .security import Db, audit

router = APIRouter(prefix="/api/v1", tags=["Detection Preview"])
WINDOW = timedelta(minutes=2)


class PreviewInput(Wire):
    device_id: UUID
    version_id: UUID


class PreviewView(Wire):
    id: UUID
    expires_at: datetime
    status: Literal["queued", "checking", "completed", "expired"]
    observation: DetectionState | None


class PreviewTask(Wire):
    id: UUID
    rule: Detection


class PreviewPoll(Wire):
    task: PreviewTask | None = None


class PreviewResult(Wire):
    observation: DetectionState


def preview_view(row: DetectionPreview, now: datetime) -> PreviewView:
    if row.observation is not None:
        status = "completed"
    elif row.expires_at <= now:
        status = "expired"
    else:
        status = "checking" if row.delivered_at is not None else "queued"
    return PreviewView(id=row.id, expires_at=row.expires_at, status=status, observation=row.observation)


@router.post("/detection-previews", status_code=201)
def create_preview(data: PreviewInput, request: Request, db: Db, actor: Operator) -> PreviewView:
    db.execute(text("SELECT pg_advisory_xact_lock(7, hashtext(:key))"), {"key": str(actor.id)})
    device = db.get(Device, data.device_id, with_for_update=True)
    agent = db.get(Agent, data.device_id)
    if device is None or device.deleted_at is not None or agent is None or agent.revoked_at is not None:
        raise HTTPException(404, "device_not_found")
    if not supports_execution(device.agent_version, (0, 3, 5)):
        raise HTTPException(409, "deployment_agent_incompatible")
    rule = db.scalar(
        select(PackageDetectionRule).join(SoftwareVersion, SoftwareVersion.id == PackageDetectionRule.version_id)
        .join(SoftwarePackage, SoftwarePackage.id == SoftwareVersion.package_id)
        .where(PackageDetectionRule.version_id == data.version_id, SoftwarePackage.archived_at.is_(None))
    )
    if rule is None:
        raise HTTPException(404, "package_version_not_found")
    now = clock(db)
    recent = select(DetectionPreview).where(DetectionPreview.created_at > now - WINDOW)
    if db.scalar(recent.where(DetectionPreview.device_id == device.id).limit(1)) is not None or db.scalar(
        select(func.count()).select_from(recent.where(DetectionPreview.created_by == actor.id).subquery())
    ) >= 5:
        raise HTTPException(429, "detection_preview_rate_limit")
    preview = DetectionPreview(
        device_id=device.id, version_id=data.version_id, created_by=actor.id, created_at=now,
        expires_at=now + WINDOW, rule={"kind": rule.kind, **rule.data},
    )
    db.add(preview)
    db.flush()
    audit(db, request, "detection_preview_requested", actor=actor,
          details={"preview_id": str(preview.id), "device_id": str(device.id), "version_id": str(data.version_id)})
    result = preview_view(preview, now)
    db.commit()
    return result


@router.get("/detection-previews/{preview_id}")
def get_preview(preview_id: UUID, db: Db, actor: Operator) -> PreviewView:
    preview = db.get(DetectionPreview, preview_id)
    if preview is None or (preview.created_by != actor.id and actor.role != "super_admin"):
        raise HTTPException(404, "detection_preview_not_found")
    result = preview_view(preview, clock(db))
    db.commit()
    return result


@router.post("/agent/{device_id}/detection-previews/poll")
def poll_preview(request: Request, db: Db, device: AgentDevice) -> PreviewPoll:
    if not detection_capable(request, device):
        raise HTTPException(409, "deployment_agent_incompatible")
    now = clock(db)
    preview = db.scalar(select(DetectionPreview).where(
        DetectionPreview.device_id == device.id, DetectionPreview.expires_at > now,
        DetectionPreview.delivered_at.is_(None),
    ).order_by(DetectionPreview.created_at).limit(1))
    if preview is None:
        db.commit()
        return PreviewPoll()
    preview.delivered_at = now
    result = PreviewPoll(task=PreviewTask(id=preview.id, rule=preview.rule))
    db.commit()
    return result


@router.post("/agent/{device_id}/detection-previews/{preview_id}/result", status_code=204)
def report_preview(preview_id: UUID, data: PreviewResult, request: Request, db: Db, device: AgentDevice):
    if not detection_capable(request, device):
        raise HTTPException(409, "deployment_agent_incompatible")
    preview = db.get(DetectionPreview, preview_id)
    if preview is None or preview.device_id != device.id:
        raise HTTPException(404, "detection_preview_not_found")
    if preview.observation == data.observation:
        db.commit()
        return
    if preview.delivered_at is None or preview.expires_at <= clock(db) or preview.observation is not None:
        raise HTTPException(409, "detection_preview_unavailable")
    preview.observation = data.observation
    audit(db, request, "detection_preview_completed", details={
        "preview_id": str(preview.id), "device_id": str(device.id), "observation": data.observation,
    })
    db.commit()
