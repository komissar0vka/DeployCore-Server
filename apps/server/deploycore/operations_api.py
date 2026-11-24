"""Restricted mailbox for the host backup and update service."""
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import Field, StringConstraints

from .device_schemas import Wire
from .models import User
from .security import Db, Permission, audit, require

router = APIRouter(prefix="/api/v1/operations", tags=["Host operations"])
Administrator = Annotated[User, Depends(require(Permission.MANAGE_SYSTEM))]
ROOT = Path("/run/deploycore-ops")
VERSION = Annotated[str, StringConstraints(pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-beta\.[1-9][0-9]*)?$", max_length=40)]


class BackupRequest(Wire):
    action: Literal["backup"]


class UpdateRequest(Wire):
    action: Literal["update"]
    channel: Literal["stable", "beta"]
    version: VERSION


class Status(Wire):
    id: UUID
    action: Literal["backup", "update"]
    stage: Literal["queued", "running", "checking", "downloading", "backing_up", "applying",
                   "rolling_back", "completed", "failed", "interrupted"]


class Backup(Wire):
    id: UUID
    bytes: int
    created_at: datetime


class OperationsView(Wire):
    available: bool
    status: Status | None
    backups: list[Backup]


def view() -> OperationsView:
    inbox, outbox = ROOT / "inbox", ROOT / "outbox"
    available = inbox.is_dir() and outbox.is_dir()
    if not available:
        return OperationsView(available=False, status=None, backups=[])
    status = None
    for stage_file, queued in [(inbox / "request.json", True), (outbox / "status.json", False)]:
        try:
            data = json.loads(stage_file.read_text())
            if queued:
                data = {key: data[key] for key in ("id", "action")} | {"stage": "queued"}
            status = Status.model_validate(data)
            break
        except (OSError, ValueError, KeyError, TypeError):
            pass
    backups = []
    for path in outbox.glob("*.tar.gz"):
        try:
            id = UUID(path.name.removesuffix(".tar.gz"))
            metadata = path.stat()
        except (OSError, ValueError):
            continue
        backups.append(Backup(id=id, bytes=metadata.st_size, created_at=datetime.fromtimestamp(metadata.st_mtime, UTC)))
    return OperationsView(available=True, status=status, backups=sorted(backups, key=lambda item: item.created_at, reverse=True))


@router.get("")
def state(db: Db, actor: Administrator) -> OperationsView:
    result = view()
    db.commit()
    return result


@router.post("", status_code=202)
def submit(data: Annotated[BackupRequest | UpdateRequest, Field(discriminator="action")],
           request: Request, db: Db, actor: Administrator) -> Status:
    current = view()
    if not current.available:
        raise HTTPException(503, "host_operations_unavailable")
    if current.status and current.status.stage not in {"completed", "failed", "interrupted"}:
        raise HTTPException(409, "host_operation_in_progress")
    id = uuid4()
    inbox = ROOT / "inbox"
    try:
        with NamedTemporaryFile(mode="w", dir=inbox, delete=False) as temporary:
            path = Path(temporary.name)
            json.dump({"id": str(id), **data.model_dump()}, temporary)
        try:
            os.link(path, inbox / "request.json")
        finally:
            path.unlink(missing_ok=True)
    except FileExistsError as exc:
        raise HTTPException(409, "host_operation_in_progress") from exc
    except OSError as exc:
        raise HTTPException(503, "host_operations_unavailable") from exc
    audit(db, request, "host_operation_requested", actor=actor, details={"id": str(id), "action": data.action})
    db.commit()
    return Status(id=id, action=data.action, stage="queued")


@router.get("/backups/{id}", response_class=FileResponse)
def download(id: UUID, db: Db, actor: Administrator):
    path = ROOT / "outbox" / f"{id}.tar.gz"
    if not path.is_file():
        raise HTTPException(404, "host_backup_not_found")
    db.commit()
    return FileResponse(path, filename=f"deploycore-backup-{id}.tar.gz", media_type="application/gzip")
