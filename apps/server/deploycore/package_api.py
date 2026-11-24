import hashlib
import os
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from sqlalchemy import String, cast, delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from starlette.concurrency import run_in_threadpool

from . import package_metadata as metadata
from . import package_schemas as wire
from . import package_storage as storage
from .detection_models import DetectionPreview
from .job_models import DeploymentJob
from .models import AuditEvent, User
from .package_models import PackageArtifact, PackageDetectionRule, PackageIntake, SoftwarePackage, SoftwareVersion, artifact_approved
from .security import COOKIE, Db, Permission, active_session, audit, require

router = APIRouter(prefix="/api/v1/packages", tags=["Packages"])
Reader = Annotated[User, Depends(require(Permission.READ))]
manage = require(Permission.MANAGE_OPERATIONS)
Operator = Annotated[User, Depends(manage)]
SystemAdmin = Annotated[User, Depends(require(Permission.MANAGE_SYSTEM))]


def find_package(db: Db, package_id: UUID, *, lock: bool = False) -> SoftwarePackage:
    package = db.get(SoftwarePackage, package_id, with_for_update=lock, populate_existing=lock)
    if package is None or package.archived_at is not None:
        raise HTTPException(404, "package_not_found")
    return package


def find_version(db: Db, package_id: UUID, version_id: UUID, *, lock: bool = False) -> SoftwareVersion:
    version = db.get(SoftwareVersion, version_id, with_for_update=lock, populate_existing=lock)
    if version is None or version.package_id != package_id:
        raise HTTPException(404, "package_version_not_found")
    return version


def version_view(version, rule, artifact, editable: bool = True) -> wire.VersionView:
    approved = artifact_approved(version, artifact)
    return wire.VersionView.model_validate({
        **{key: getattr(version, key) for key in wire.VersionInput.model_fields if key != "detection"},
        "id": version.id, "editable": editable, "revision": version.revision,
        "approved_at": version.approved_at if approved else None,
        "approved_by": version.approved_by if approved else None,
        "approval_kind": version.approval_kind if approved else None,
        "approved_sha256": version.approved_sha256 if approved else None,
        "detection": {"kind": rule.kind, **rule.data}, "artifact": artifact,
    })


def commit(db: Db):
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if getattr(exc.orig.diag, "constraint_name", None) in {"package_identity", "package_version_identity"}:
            raise HTTPException(409, "package_duplicate") from exc
        raise


@router.get("")
def list_packages(db: Db, actor: Reader, q: Annotated[str, Query(max_length=160)] = "",
                  offset: Annotated[int, Query(ge=0, le=100000)] = 0,
                  limit: Annotated[int, Query(ge=1, le=100)] = 25,
                  sort: Literal["name", "publisher"] = "name",
                  direction: Literal["asc", "desc"] = "asc") -> wire.PackagePage:
    query = select(SoftwarePackage).where(SoftwarePackage.archived_at.is_(None))
    if term := q.strip():
        query = query.where(or_(SoftwarePackage.name.icontains(term, autoescape=True),
                                SoftwarePackage.publisher.icontains(term, autoescape=True),
                                SoftwarePackage.category.icontains(term, autoescape=True)))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    field = SoftwarePackage.name if sort == "name" else SoftwarePackage.publisher
    order = field.asc() if direction == "asc" else field.desc()
    can_deploy = select(SoftwareVersion.id).join(PackageArtifact, PackageArtifact.version_id == SoftwareVersion.id).where(
        SoftwareVersion.package_id == SoftwarePackage.id,
        SoftwareVersion.approved_at.is_not(None),
        SoftwareVersion.approved_sha256 == PackageArtifact.sha256,
        or_((SoftwareVersion.approval_kind == "manual") & (PackageArtifact.signature == "unverified"),
            (SoftwareVersion.approval_kind == "authenticode") & (PackageArtifact.signature == "verified")),
    ).exists()
    rows = db.execute(query.add_columns(can_deploy).order_by(order, SoftwarePackage.id).offset(offset).limit(limit))
    result = wire.PackagePage(
        items=[wire.PackageListItem(**wire.PackageView.model_validate(row).model_dump(), can_deploy=approved)
               for row, approved in rows], total=total,
    )
    db.commit()
    return result


@router.post("", status_code=201)
def create_package(data: wire.PackageInput, request: Request, db: Db, actor: Operator) -> wire.PackageView:
    package = SoftwarePackage(id=uuid4(), **data.model_dump())
    db.add(package)
    audit(db, request, "package_created", actor=actor, details={"package_id": str(package.id)})
    commit(db)
    return wire.PackageView.model_validate(package)


UploadFilename = Annotated[str, Query(min_length=5, max_length=180, pattern=r"^[^/\\\x00-\x1f\x7f]+$")]
BINARY_BODY = {
    "requestBody": {"required": True, "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}},
}


def check_binary_body(request: Request):
    if request.headers.get("content-type", "").split(";")[0].strip() != "application/octet-stream":
        raise HTTPException(415, "package_upload_content_type")


def intake_path(id: UUID):
    return storage.storage_root() / f".intake-{id}"


def register_intake(path, upload: storage.Upload, filename: str, installer: str, actor_id: UUID, request: Request, db: Db):
    architecture = storage.installer_architecture(path, installer)
    signature = storage.authenticity(path)
    hints = metadata.suggest(path, installer)
    now = datetime.now(UTC)
    current_actor = manage(active_session(request, db, request.cookies.get(COOKIE)))
    if current_actor.id != actor_id:
        raise HTTPException(403, "permission_denied")
    expired = db.scalars(delete(PackageIntake).where(PackageIntake.expires_at <= now).returning(PackageIntake.id)).all()
    id = uuid4()
    target = intake_path(id)
    preview = wire.IntakeView(id=id, filename=filename, size_bytes=upload.size, sha256=upload.hash.hexdigest(),
                              signature=signature, installer=installer, architecture=architecture, **hints)
    db.add(PackageIntake(id=id, owner_id=actor_id, expires_at=now + timedelta(hours=1),
                         metadata_json=preview.model_dump(mode="json")))
    os.replace(path, target)
    try:
        storage.sync_directory()
        db.commit()
    except Exception:
        target.unlink(missing_ok=True)
        raise
    for expired_id in expired:
        intake_path(expired_id).unlink(missing_ok=True)
    return preview


@router.post("/intakes", status_code=201, openapi_extra=BINARY_BODY)
async def inspect_upload(filename: UploadFilename, request: Request, db: Db, actor: Operator) -> wire.IntakeView:
    check_binary_body(request)
    installer = filename.rpartition(".")[2].lower()
    if installer not in {"msi", "exe"}:
        raise HTTPException(422, "package_invalid_format")
    actor_id = actor.id
    await run_in_threadpool(db.commit)
    with storage.temporary_upload(request) as upload:
        path = await storage.receive(request, upload)
        return await run_in_threadpool(register_intake, path, upload, filename, installer, actor_id, request, db)


@router.post("/intakes/{intake_id}/save", status_code=201)
def save_intake(intake_id: UUID, data: wire.IntakeSave, request: Request, db: Db, actor: Operator) -> wire.IntakeSaved:
    intake = db.get(PackageIntake, intake_id, with_for_update=True)
    if intake is None or intake.owner_id != actor.id or intake.expires_at <= datetime.now(UTC):
        raise HTTPException(404, "package_intake_expired")
    preview = wire.IntakeView.model_validate(intake.metadata_json)
    expected = "exe" if data.version.installer == "portable" else data.version.installer
    if expected != preview.installer or data.version.architecture != preview.architecture:
        raise HTTPException(422, "package_architecture_mismatch")
    package = SoftwarePackage(id=uuid4(), **data.package.model_dump())
    db.add(package)
    try:
        db.flush()
    except IntegrityError as exc:
        if getattr(exc.orig.diag, "constraint_name", None) == "package_identity":
            raise HTTPException(409, "package_duplicate") from exc
        raise
    version = SoftwareVersion(id=uuid4(), package_id=package.id, **data.version.model_dump(exclude={"detection"}))
    db.add(version)
    db.flush()
    rule = PackageDetectionRule(version_id=version.id, kind=data.version.detection.kind,
                                data=data.version.detection.model_dump(mode="json", exclude={"kind"}))
    artifact = PackageArtifact(version_id=version.id, filename=preview.filename, size_bytes=preview.size_bytes,
                               sha256=preview.sha256, signature=preview.signature)
    db.add_all([rule, artifact])
    db.delete(intake)
    audit(db, request, "package_created", actor=actor,
          details={"package_id": str(package.id), "version_id": str(version.id), "sha256": artifact.sha256})
    original = intake_path(intake_id)
    target = storage.artifact_path(version.id)
    linked = False
    try:
        os.link(original, target)
        linked = True
        storage.sync_directory()
        commit(db)
    except OSError as exc:
        if linked:
            target.unlink(missing_ok=True)
        raise storage.storage_error(exc) from exc
    except Exception:
        if linked:
            target.unlink(missing_ok=True)
        raise
    original.unlink(missing_ok=True)
    return wire.IntakeSaved(package=wire.PackageView.model_validate(package), version=version_view(version, rule, artifact))


@router.get("/{package_id}")
def package_detail(package_id: UUID, db: Db, actor: Reader) -> wire.PackageDetail:
    package = find_package(db, package_id)
    rows = db.execute(
        select(SoftwareVersion, PackageDetectionRule, PackageArtifact,
               ~select(DeploymentJob.id).where(DeploymentJob.version_id == SoftwareVersion.id).exists())
        .join(PackageDetectionRule, PackageDetectionRule.version_id == SoftwareVersion.id)
        .outerjoin(PackageArtifact, PackageArtifact.version_id == SoftwareVersion.id)
        .where(SoftwareVersion.package_id == package_id)
        .order_by(SoftwareVersion.version.desc(), SoftwareVersion.architecture, SoftwareVersion.revision.desc())
    )
    result = wire.PackageDetail(**wire.PackageView.model_validate(package).model_dump(),
                                versions=[version_view(*row) for row in rows])
    db.commit()
    return result


@router.patch("/{package_id}")
def edit_package(package_id: UUID, data: wire.PackagePatch, request: Request, db: Db, actor: Operator) -> wire.PackageView:
    package = find_package(db, package_id, lock=True)
    changes = data.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(package, key, value)
    if changes:
        audit(db, request, "package_changed", actor=actor, details={"package_id": str(package.id)})
    commit(db)
    return wire.PackageView.model_validate(package)


@router.delete("/{package_id}", status_code=204, response_class=Response)
def archive_package(package_id: UUID, request: Request, db: Db, actor: Operator):
    package = find_package(db, package_id, lock=True)
    package.archived_at = datetime.now(UTC)
    audit(db, request, "package_archived", actor=actor, details={"package_id": str(package.id)})
    db.commit()


@router.post("/{package_id}/versions", status_code=201)
def create_version(package_id: UUID, data: wire.VersionInput, request: Request, db: Db, actor: Operator) -> wire.VersionView:
    find_package(db, package_id, lock=True)
    version = SoftwareVersion(package_id=package_id, **data.model_dump(exclude={"detection"}))
    db.add(version)
    try:
        db.flush()
    except IntegrityError as exc:
        if getattr(exc.orig.diag, "constraint_name", None) == "package_version_identity":
            raise HTTPException(409, "package_duplicate") from exc
        raise
    rule = PackageDetectionRule(version_id=version.id, kind=data.detection.kind,
                                data=data.detection.model_dump(mode="json", exclude={"kind"}))
    db.add(rule)
    audit(db, request, "package_version_created", actor=actor, details={"version_id": str(version.id)})
    db.commit()
    return version_view(version, rule, None)


@router.post("/{package_id}/duplicate", status_code=201)
def duplicate_package(package_id: UUID, data: wire.PackageInput,
                      request: Request, db: Db, actor: Operator) -> wire.PackageView:
    find_package(db, package_id, lock=True)
    package = SoftwarePackage(id=uuid4(), **data.model_dump())
    db.add(package)
    try:
        db.flush()
    except IntegrityError as exc:
        if getattr(exc.orig.diag, "constraint_name", None) == "package_identity":
            raise HTTPException(409, "package_duplicate") from exc
        raise
    sources = db.execute(
        select(SoftwareVersion, PackageDetectionRule, PackageArtifact)
        .join(PackageDetectionRule, PackageDetectionRule.version_id == SoftwareVersion.id)
        .outerjoin(PackageArtifact, PackageArtifact.version_id == SoftwareVersion.id)
        .where(SoftwareVersion.package_id == package_id)
    ).all()
    paths = []
    try:
        for old, rule, artifact in sources:
            new = SoftwareVersion(id=uuid4(), package_id=package.id, revision=old.revision,
                                  **{key: getattr(old, key) for key in wire.VersionInput.model_fields if key != "detection"})
            db.add(new)
            db.flush()
            db.add(PackageDetectionRule(version_id=new.id, kind=rule.kind, data=rule.data))
            if artifact is not None:
                path = storage.artifact_path(new.id)
                os.link(storage.artifact_path(old.id, artifact.storage_key), path)
                paths.append(path)
                db.add(PackageArtifact(version_id=new.id, filename=artifact.filename, size_bytes=artifact.size_bytes,
                                       sha256=artifact.sha256, signature=artifact.signature))
        if paths:
            storage.sync_directory()
        audit(db, request, "package_duplicated", actor=actor,
              details={"package_id": str(package.id), "source_package_id": str(package_id)})
        commit(db)
    except Exception as exc:
        for path in paths:
            path.unlink(missing_ok=True)
        if isinstance(exc, OSError):
            raise storage.storage_error(exc) from exc
        raise
    return wire.PackageView.model_validate(package)


def remove_versions(db: Db, versions: list[UUID]):
    if not versions:
        return []
    used_by_job = select(DeploymentJob.id).where(DeploymentJob.version_id.in_(versions)).exists()
    used_by_preview = select(DetectionPreview.id).where(DetectionPreview.version_id.in_(versions)).exists()
    if db.scalar(select(used_by_job | used_by_preview)):
        raise HTTPException(409, "package_version_in_use")
    paths = [storage.artifact_path(version_id, key) for version_id, key in db.execute(
        delete(PackageArtifact).where(PackageArtifact.version_id.in_(versions))
        .returning(PackageArtifact.version_id, PackageArtifact.storage_key))]
    db.execute(delete(PackageDetectionRule).where(PackageDetectionRule.version_id.in_(versions)))
    db.execute(delete(SoftwareVersion).where(SoftwareVersion.id.in_(versions)))
    return paths


@router.delete("/{package_id}/versions/{version_id}", status_code=204, response_class=Response)
def delete_version(package_id: UUID, version_id: UUID, request: Request, db: Db, actor: Operator):
    find_package(db, package_id, lock=True)
    find_version(db, package_id, version_id, lock=True)
    paths = remove_versions(db, [version_id])
    audit(db, request, "package_version_deleted", actor=actor,
          details={"package_id": str(package_id), "version_id": str(version_id)})
    commit(db)
    for path in paths:
        path.unlink(missing_ok=True)


@router.delete("/{package_id}/purge", status_code=204, response_class=Response)
def delete_package(package_id: UUID, request: Request, db: Db, actor: Operator):
    package = db.get(SoftwarePackage, package_id, with_for_update=True)
    if package is None:
        raise HTTPException(404, "package_not_found")
    versions = list(db.scalars(select(SoftwareVersion.id).where(SoftwareVersion.package_id == package_id).with_for_update()))
    paths = remove_versions(db, versions)
    db.delete(package)
    audit(db, request, "package_deleted", actor=actor, details={"package_id": str(package_id)})
    commit(db)
    for path in paths:
        path.unlink(missing_ok=True)


@router.get("/{package_id}/history")
def package_history(package_id: UUID, db: Db, actor: Reader) -> list[wire.PackageHistoryEvent]:
    find_package(db, package_id)
    version_ids = select(cast(SoftwareVersion.id, String)).where(SoftwareVersion.package_id == package_id)
    rows = db.execute(select(AuditEvent.action, AuditEvent.created_at, User.username)
        .outerjoin(User, User.id == AuditEvent.actor_id)
        .where(AuditEvent.action.startswith("package_", autoescape=True),
               or_(AuditEvent.details["package_id"].astext == str(package_id),
                   AuditEvent.details["version_id"].astext.in_(version_ids)))
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(100))
    result = [wire.PackageHistoryEvent(action=event, created_at=created, actor=username)
              for event, created, username in rows]
    db.commit()
    return result


def check_unused(db: Db, version_id: UUID):
    if db.scalar(select(select(DeploymentJob.id).where(DeploymentJob.version_id == version_id).exists())):
        raise HTTPException(409, "package_version_in_use")


def clear_approval(version: SoftwareVersion):
    version.approved_at = version.approved_by = version.approval_kind = version.approved_sha256 = None


@router.put("/{package_id}/versions/{version_id}")
def edit_version(package_id: UUID, version_id: UUID, data: wire.VersionInput,
                 request: Request, db: Db, actor: Operator) -> wire.VersionView:
    find_package(db, package_id, lock=True)
    version = find_version(db, package_id, version_id, lock=True)
    check_unused(db, version_id)
    artifact = db.get(PackageArtifact, version_id)
    if artifact and (version.installer != data.installer or version.architecture != data.architecture):
        raise HTTPException(422, "package_architecture_mismatch")
    for key, value in data.model_dump(exclude={"detection"}).items():
        setattr(version, key, value)
    rule = db.get_one(PackageDetectionRule, version_id)
    rule.kind = data.detection.kind
    rule.data = data.detection.model_dump(mode="json", exclude={"kind"})
    clear_approval(version)
    audit(db, request, "package_version_changed", actor=actor, details={"version_id": str(version_id)})
    commit(db)
    return version_view(version, rule, artifact)


@router.post("/{package_id}/versions/{version_id}/revisions", status_code=201)
def create_revision(package_id: UUID, version_id: UUID, data: wire.VersionInput,
                    request: Request, db: Db, actor: Operator) -> wire.VersionView:
    find_package(db, package_id, lock=True)
    previous = find_version(db, package_id, version_id, lock=True)
    source = db.get(PackageArtifact, version_id)
    if source and (previous.installer != data.installer or previous.architecture != data.architecture):
        raise HTTPException(422, "package_architecture_mismatch")
    revision = db.scalar(select(func.max(SoftwareVersion.revision)).where(
        SoftwareVersion.package_id == package_id, SoftwareVersion.version == data.version,
        SoftwareVersion.architecture == data.architecture,
    )) or 0
    version = SoftwareVersion(id=uuid4(), package_id=package_id, revision=revision + 1,
                              **data.model_dump(exclude={"detection"}))
    rule = PackageDetectionRule(version_id=version.id, kind=data.detection.kind,
                                data=data.detection.model_dump(mode="json", exclude={"kind"}))
    db.add(version)
    db.flush()
    db.add(rule)
    artifact = None
    target = None
    if source:
        verify_stored_digest(version_id, source.sha256, source.storage_key)
        artifact = PackageArtifact(version_id=version.id, filename=source.filename, size_bytes=source.size_bytes,
                                   sha256=source.sha256, signature=source.signature)
        db.add(artifact)
    audit(db, request, "package_version_revised", actor=actor,
          details={"version_id": str(version.id), "source_version_id": str(version_id)})
    try:
        if source:
            path = storage.artifact_path(version.id)
            os.link(storage.artifact_path(version_id, source.storage_key), path)
            target = path
            storage.sync_directory()
        commit(db)
    except OSError as exc:
        if target is not None:
            target.unlink(missing_ok=True)
        raise storage.storage_error(exc) from exc
    except Exception:
        if target is not None:
            target.unlink(missing_ok=True)
        raise
    return version_view(version, rule, artifact)


def finalize_upload(package_id: UUID, version_id: UUID, filename: str, path, upload: storage.Upload, signature: str, request: Request, db: Db, replace: bool, validated_format: tuple[str, str]) -> wire.ArtifactView:
    actor = manage(active_session(request, db, request.cookies.get(COOKIE)))
    find_package(db, package_id, lock=True)
    version = find_version(db, package_id, version_id, lock=True)
    if (version.installer, version.architecture) != validated_format:
        raise HTTPException(422, "package_architecture_mismatch")
    artifact = db.get(PackageArtifact, version.id, populate_existing=True)
    if artifact is not None and not replace:
        raise HTTPException(409, "package_artifact_immutable")
    if artifact is None and replace:
        raise HTTPException(404, "package_artifact_not_found")
    values = {"filename": filename, "size_bytes": upload.size, "sha256": upload.hash.hexdigest(), "signature": signature}
    old_path = None
    if artifact is not None:
        check_unused(db, version.id)
        old_path = storage.artifact_path(version.id, artifact.storage_key)
        artifact.storage_key = uuid4()
        artifact.uploaded_at = datetime.now(UTC)
        for key, value in values.items():
            setattr(artifact, key, value)
        clear_approval(version)
    else:
        artifact = PackageArtifact(version_id=version.id, **values)
        db.add(artifact)
    target = storage.artifact_path(version.id, artifact.storage_key)
    os.replace(path, target)
    try:
        storage.sync_directory()
        audit(db, request, "package_artifact_replaced" if replace else "package_artifact_uploaded", actor=actor,
              details={"version_id": str(version.id), "sha256": artifact.sha256, "signature": signature})
        db.commit()
    except Exception:
        target.unlink(missing_ok=True)
        raise
    if old_path is not None:
        old_path.unlink(missing_ok=True)
    return wire.ArtifactView.model_validate(artifact)


def validate_upload(db: Db, package_id: UUID, version_id: UUID, filename: str, replace: bool) -> tuple[str, str]:
    find_package(db, package_id)
    version = find_version(db, package_id, version_id)
    if not filename.lower().endswith("." + ("exe" if version.installer == "portable" else version.installer)):
        raise HTTPException(422, "package_invalid_format")
    if not replace and db.get(PackageArtifact, version.id) is not None:
        raise HTTPException(409, "package_artifact_immutable")
    db.commit()
    return version.installer, version.architecture


@router.put("/{package_id}/versions/{version_id}/artifact", status_code=201, openapi_extra=BINARY_BODY)
async def upload_artifact(package_id: UUID, version_id: UUID, filename: UploadFilename,
                          request: Request, db: Db, actor: Operator, replace: bool = False) -> wire.ArtifactView:
    check_binary_body(request)
    installer, expected = await run_in_threadpool(validate_upload, db, package_id, version_id, filename, replace)
    with storage.temporary_upload(request) as upload:
        path = await storage.receive(request, upload)
        if await run_in_threadpool(storage.installer_architecture, path, installer) != expected:
            raise HTTPException(422, "package_architecture_mismatch")
        signature = await run_in_threadpool(storage.authenticity, path)
        return await run_in_threadpool(finalize_upload, package_id, version_id, filename, path, upload, signature, request, db, replace, (installer, expected))


@router.post("/{package_id}/versions/{version_id}/approve")
def approve_version(package_id: UUID, version_id: UUID, request: Request, db: Db, actor: Operator) -> wire.VersionView:
    find_package(db, package_id, lock=True)
    version = find_version(db, package_id, version_id, lock=True)
    artifact = db.get(PackageArtifact, version_id)
    if artifact is None or artifact.signature != "verified":
        raise HTTPException(409, "package_signature_required")
    verify_stored_digest(version_id, artifact.sha256, artifact.storage_key)
    return record_approval(db, request, actor, version, artifact, "authenticode")


@router.post("/{package_id}/versions/{version_id}/approve-manual")
def approve_manual(package_id: UUID, version_id: UUID, data: wire.ManualApproval, request: Request,
                   db: Db, actor: SystemAdmin) -> wire.VersionView:
    find_package(db, package_id, lock=True)
    version = find_version(db, package_id, version_id, lock=True)
    artifact = db.get(PackageArtifact, version_id)
    if artifact is None or artifact.signature != "unverified":
        raise HTTPException(409, "package_manual_approval_unavailable")
    if data.sha256.lower() != artifact.sha256:
        raise HTTPException(409, "package_approval_hash_mismatch")
    verify_stored_digest(version_id, artifact.sha256, artifact.storage_key)
    return record_approval(db, request, actor, version, artifact, "manual")


def verify_stored_digest(version_id: UUID, expected: str, storage_key: UUID | None) -> None:
    try:
        with storage.artifact_path(version_id, storage_key).open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
    except OSError as exc:
        raise HTTPException(503, "package_storage_unavailable") from exc
    if digest != expected:
        raise HTTPException(409, "package_approval_hash_mismatch")


def record_approval(db: Db, request: Request, actor: User, version: SoftwareVersion,
                    artifact: PackageArtifact, kind: str) -> wire.VersionView:
    version_id = version.id
    if not storage.artifact_path(version_id, artifact.storage_key).is_file():
        raise HTTPException(503, "package_storage_unavailable")
    if not artifact_approved(version, artifact):
        version.approved_at = datetime.now(UTC)
        version.approved_by = actor.id
        version.approval_kind = kind
        version.approved_sha256 = artifact.sha256
        audit(db, request, "package_version_approved", actor=actor, details={
            "version_id": str(version_id), "approval_kind": kind, "sha256": artifact.sha256,
            "approved_at": version.approved_at.isoformat(),
        })
    rule = db.get_one(PackageDetectionRule, version_id)
    db.commit()
    return version_view(version, rule, artifact)


@router.get("/{package_id}/versions/{version_id}/artifact", response_class=FileResponse, responses={
    200: {"content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}},
})
def download_artifact(package_id: UUID, version_id: UUID, db: Db, actor: Operator):
    find_package(db, package_id)
    find_version(db, package_id, version_id)
    artifact = db.get(PackageArtifact, version_id)
    if artifact is None:
        raise HTTPException(404, "package_artifact_not_found")
    path = storage.artifact_path(version_id, artifact.storage_key)
    if not path.is_file():
        raise HTTPException(503, "package_storage_unavailable")
    db.commit()
    return FileResponse(path, filename=artifact.filename, media_type="application/octet-stream",
                        headers={"X-DeployCore-SHA256": artifact.sha256})
