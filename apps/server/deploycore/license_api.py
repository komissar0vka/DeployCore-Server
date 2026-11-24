import json
import os
from subprocess import SubprocessError
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select

from . import cloud_link, licensing
from .device_models import Device
from .device_schemas import Wire
from .license_models import LicenseState
from .licensing_contracts import SignedGrant
from .models import User
from .security import Db, Permission, audit, require

router = APIRouter(prefix="/api/v1/licenses", tags=["Licensing"])
Reader = Annotated[User, Depends(require(Permission.READ))]
SystemAdmin = Annotated[User, Depends(require(Permission.MANAGE_SYSTEM))]


class LicenseView(Wire):
    instance_id: UUID
    edition: Literal["free", "business", "enterprise"]
    status: Literal["free", "valid", "grace", "fallback"]
    limit: int
    managed: int
    expires_at: datetime | None = None


def state_for(db: Db, *, lock: bool = False) -> LicenseState:
    return db.get_one(LicenseState, 1, with_for_update=lock)


def managed_count(db: Db) -> int:
    return db.scalar(select(func.count()).select_from(Device).where(
        Device.management_state == "managed", Device.deleted_at.is_(None),
    ))


def local_trust() -> tuple[bytes, dict[str, bytes]]:
    path = os.environ.get("DEPLOYCORE_LICENSE_TRUST")
    if not path:
        try:
            cloud = cloud_link.connection()
            return cloud_link.instance_public_key(), {"cloud-license-1": cloud.license_key}
        except (OSError, ValueError, TypeError, KeyError, SubprocessError) as exc:
            raise licensing.LicenseValidationError("license_trust_unavailable") from exc
    try:
        with open(path, "rb") as source:
            raw = source.read(16385)
        if len(raw) > 16384:
            raise ValueError("oversized trust configuration")
        data = json.loads(raw, object_pairs_hook=licensing.strict_object)
        if set(data) != {"instance_public_key", "issuer_keys"} or not isinstance(data["issuer_keys"], dict):
            raise ValueError("invalid trust configuration")
        key = licensing.decode_base64url(data["instance_public_key"])
        issuers = {kid: licensing.decode_base64url(value) for kid, value in data["issuer_keys"].items()}
        if len(key) != 32 or not issuers or any(len(value) != 32 for value in issuers.values()):
            raise ValueError("invalid trust keys")
        return key, issuers
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        raise licensing.LicenseValidationError("license_trust_unavailable") from exc


def verify(state: LicenseState, raw: bytes) -> licensing.VerifiedGrant:
    key, issuers = local_trust()
    previous = (licensing.GrantWatermark(state.issue_number, state.payload_sha256)
                if state.issue_number is not None else None)
    return licensing.verify_grant(raw, trusted_keys=issuers, instance_id=state.instance_id,
                                  instance_public_key=key, now=datetime.now(UTC), previous=previous)


def effective(state: LicenseState, managed: int) -> LicenseView:
    if state.grant is not None:
        try:
            grant = verify(state, state.grant)
        except licensing.LicenseValidationError:
            return LicenseView(instance_id=state.instance_id, edition="free", status="fallback",
                               limit=licensing.FREE_DEVICE_LIMIT, managed=managed)
        return LicenseView(instance_id=state.instance_id, edition=grant.payload.edition, status=grant.status,
                           limit=grant.payload.device_limit, managed=managed, expires_at=grant.payload.expires_at)
    return LicenseView(instance_id=state.instance_id, edition="free", status="free",
                       limit=licensing.FREE_DEVICE_LIMIT, managed=managed)


def ensure_slot(db: Db, state: LicenseState) -> None:
    view = effective(state, managed_count(db))
    if view.managed >= view.limit:
        raise HTTPException(409, "license_limit_reached")


@router.get("")
def license_status(db: Db, actor: Reader) -> LicenseView:
    result = effective(state_for(db), managed_count(db))
    db.commit()
    return result


@router.post("/import")
def import_license(data: SignedGrant, request: Request, db: Db, actor: SystemAdmin) -> LicenseView:
    state = state_for(db, lock=True)
    raw = data.model_dump_json().encode()
    try:
        verified = verify(state, raw)
    except licensing.LicenseValidationError as exc:
        code = str(exc)
        status = 503 if code in ("license_trust_unavailable", "license_verifier_unavailable") else 422
        raise HTTPException(status, code) from exc
    if state.grant != raw:
        state.grant = raw
        state.issue_number = verified.watermark.issue_number
        state.payload_sha256 = verified.watermark.payload_sha256
        audit(db, request, "license_imported", actor=actor, details={
            "license_id": str(verified.payload.license_id), "issue_number": str(state.issue_number),
        })
    result = LicenseView(instance_id=state.instance_id, edition=verified.payload.edition, status=verified.status,
                         limit=verified.payload.device_limit, managed=managed_count(db),
                         expires_at=verified.payload.expires_at)
    db.commit()
    return result


@router.get("/updates/{channel}")
def available_updates(channel: Literal["stable", "beta"], actor: Reader):
    try:
        cloud = cloud_link.connection()
        manifest = cloud_link.signed_response(cloud.request(f"/v1/releases/{channel}"), "release", cloud.release_key)
        if manifest["channel"] != channel or datetime.fromisoformat(manifest["expires_at"]) <= datetime.now(UTC):
            raise ValueError("wrong_release_channel")
        return {"current_version": cloud_link.VERSION, "releases": manifest["releases"]}
    except (OSError, ValueError, TypeError, KeyError):
        raise HTTPException(503, "cloud_updates_unavailable") from None
