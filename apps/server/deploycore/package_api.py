import hashlib
import os
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from starlette.concurrency import run_in_threadpool

from . import package_schemas as wire
from . import package_storage as storage
from .models import User
from .package_models import PackageArtifact, PackageDetectionRule, SoftwarePackage, SoftwareVersion, artifact_approved
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


def version_view(version, rule, artifact) -> wire.VersionView:
    approved = artifact_approved(version, artifact)
    return wire.VersionView.model_validate({
        **{key: getattr(version, key) for key in wire.VersionInput.model_fields if key != "detection"},
        "id": version.id,
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
                  limit: Annotated[int, Query(ge=1, le=100)] = 25) -> wire.PackagePage:
    query = select(SoftwarePackage).where(SoftwarePackage.archived_at.is_(None))
    if term := q.strip():
        query = query.where(or_(SoftwarePackage.name.icontains(term, autoescape=True),
                                SoftwarePackage.publisher.icontains(term, autoescape=True)))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(query.order_by(SoftwarePackage.name, SoftwarePackage.id).offset(offset).limit(limit))
    result = wire.PackagePage(items=[wire.PackageView.model_validate(row) for row in rows], total=total)
    db.commit()
    return result


@router.post("", status_code=201)
def create_package(data: wire.PackageInput, request: Request, db: Db, actor: Operator) -> wire.PackageView:
    package = SoftwarePackage(id=uuid4(), **data.model_dump())
    db.add(package)
    audit(db, request, "package_created", actor=actor, details={"package_id": str(package.id)})
    commit(db)
    return wire.PackageView.model_validate(package)


@router.get("/{package_id}")
def package_detail(package_id: UUID, db: Db, actor: Reader) -> wire.PackageDetail:
    package = find_package(db, package_id)
    rows = db.execute(
        select(SoftwareVersion, PackageDetectionRule, PackageArtifact)
        .join(PackageDetectionRule, PackageDetectionRule.version_id == SoftwareVersion.id)
        .outerjoin(PackageArtifact, PackageArtifact.version_id == SoftwareVersion.id)
        .where(SoftwareVersion.package_id == package_id)
        .order_by(SoftwareVersion.version.desc(), SoftwareVersion.architecture)
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


def finalize_upload(package_id: UUID, version_id: UUID, filename: str, path, upload: storage.Upload, signature: str, request: Request, db: Db) -> wire.ArtifactView:
    actor = manage(active_session(request, db, request.cookies.get(COOKIE)))
    find_package(db, package_id, lock=True)
    version = find_version(db, package_id, version_id)
    if db.get(PackageArtifact, version.id) is not None:
        raise HTTPException(409, "package_artifact_immutable")
    artifact = PackageArtifact(version_id=version.id, filename=filename, size_bytes=upload.size,
                               sha256=upload.hash.hexdigest(), signature=signature)
    os.replace(path, storage.artifact_path(version.id))
    descriptor = os.open(storage.storage_root(), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    db.add(artifact)
    audit(db, request, "package_artifact_uploaded", actor=actor,
          details={"version_id": str(version.id), "sha256": artifact.sha256, "signature": signature})
    db.commit()
    return wire.ArtifactView.model_validate(artifact)


def validate_upload(db: Db, package_id: UUID, version_id: UUID, filename: str) -> tuple[str, str]:
    find_package(db, package_id)
    version = find_version(db, package_id, version_id)
    if not filename.lower().endswith("." + version.installer):
        raise HTTPException(422, "package_invalid_format")
    if db.get(PackageArtifact, version.id) is not None:
        raise HTTPException(409, "package_artifact_immutable")
    db.commit()
    return version.installer, version.architecture


@router.put("/{package_id}/versions/{version_id}/artifact", status_code=201, openapi_extra={
    "requestBody": {"required": True, "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}},
})
async def upload_artifact(package_id: UUID, version_id: UUID,
                          filename: Annotated[str, Query(min_length=5, max_length=180, pattern=r"^[^/\\\x00-\x1f\x7f]+$")],
                          request: Request, db: Db, actor: Operator) -> wire.ArtifactView:
    if request.headers.get("content-type", "").split(";")[0].strip() != "application/octet-stream":
        raise HTTPException(415, "package_upload_content_type")
    installer, expected = await run_in_threadpool(validate_upload, db, package_id, version_id, filename)
    with storage.temporary_upload(request) as upload:
        path = await storage.receive(request, upload)
        if await run_in_threadpool(storage.installer_architecture, path, installer) != expected:
            raise HTTPException(422, "package_architecture_mismatch")
        signature = await run_in_threadpool(storage.authenticity, path)
        return await run_in_threadpool(finalize_upload, package_id, version_id, filename, path, upload, signature, request, db)


@router.post("/{package_id}/versions/{version_id}/approve")
def approve_version(package_id: UUID, version_id: UUID, request: Request, db: Db, actor: Operator) -> wire.VersionView:
    find_package(db, package_id, lock=True)
    version = find_version(db, package_id, version_id, lock=True)
    artifact = db.get(PackageArtifact, version_id)
    if artifact is None or artifact.signature != "verified":
        raise HTTPException(409, "package_signature_required")
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
    try:
        with storage.artifact_path(version_id).open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
    except OSError as exc:
        raise HTTPException(503, "package_storage_unavailable") from exc
    if digest != artifact.sha256:
        raise HTTPException(409, "package_approval_hash_mismatch")
    return record_approval(db, request, actor, version, artifact, "manual")


def record_approval(db: Db, request: Request, actor: User, version: SoftwareVersion,
                    artifact: PackageArtifact, kind: str) -> wire.VersionView:
    version_id = version.id
    if not storage.artifact_path(version_id).is_file():
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
    path = storage.artifact_path(version_id)
    if not path.is_file():
        raise HTTPException(503, "package_storage_unavailable")
    db.commit()
    return FileResponse(path, filename=artifact.filename, media_type="application/octet-stream",
                        headers={"X-DeployCore-SHA256": artifact.sha256})
