import hashlib
import io
import json
import re
import secrets
import shutil
import ssl
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import BoundedSemaphore
from zipfile import ZIP_STORED, ZipFile

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import Field

from .device_api import Operator
from .device_models import EnrollmentToken
from .device_schemas import TokenInput
from .models import Installation
from .security import Db, audit, digest

router = APIRouter(prefix="/api/v1", tags=["Enrollment"])
TEMPLATE = Path("/opt/deploycore/agent")
MSI_TYPE = "application/x-msi"
builder = BoundedSemaphore(1)
pem_certificate = re.compile(r"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----")


class PackageInput(TokenInput):
    ca: str = Field(default="", max_length=65536)
    rollout: bool = False


def validate_ca(pem: str) -> str:
    pem = pem.strip()
    if not pem:
        return pem
    if pem_certificate.sub("", pem).strip():
        raise HTTPException(422, "agent_package_invalid_ca")
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=pem)
    except (ValueError, ssl.SSLError) as exc:
        raise HTTPException(422, "agent_package_invalid_ca") from exc
    return pem


def build_msi(server: str, token: str, ca: str) -> bytes:
    if not builder.acquire(blocking=False):
        raise HTTPException(429, "agent_package_busy")
    try:
        version = (TEMPLATE / "VERSION").read_text().strip()
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise ValueError("invalid installer template version")
        with TemporaryDirectory(prefix="deploycore-agent-") as directory:
            path = Path(directory)
            for filename in ("deploycore-agent.exe", "configured-agent.wxs"):
                shutil.copyfile(TEMPLATE / filename, path / filename)
            (path / "enrollment.json").write_text(json.dumps({"server": server, "token": token, "ca": ca}))
            subprocess.run(["wixl", "-a", "x64", "-D", f"Version={version}", "-o", "agent.msi", "configured-agent.wxs"],
                           cwd=path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=True)
            return (path / "agent.msi").read_bytes()
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise HTTPException(503, "agent_package_unavailable") from exc
    finally:
        builder.release()


@router.post("/agent-packages", response_class=Response, responses={200: {
    "content": {media: {"schema": {"type": "string", "format": "binary"}} for media in (MSI_TYPE, "application/zip")},
}})
def create_agent_package(data: PackageInput, request: Request, db: Db, actor: Operator) -> Response:
    if data.device_id is not None:
        raise HTTPException(422, "agent_package_recovery_unsupported")
    server = db.get_one(Installation, 1).agent_url
    if server is None:
        raise HTTPException(409, "agent_package_address_required")
    ca = validate_ca(data.ca)
    raw = secrets.token_urlsafe(32)
    msi = build_msi(server, raw, ca)
    filename = "deploycore-managed-agent.msi"
    if data.rollout:
        try:
            migration = (TEMPLATE / "upgrade-agent.ps1").read_bytes()
        except OSError as exc:
            raise HTTPException(503, "agent_package_unavailable") from exc
        result = rollout_zip(msi, migration)
        filename = "deploycore-agent-rollout.zip"
    else:
        result = msi
    token = EnrollmentToken(
        token_hash=digest(raw), label=data.label, max_uses=data.max_uses, uses=0,
        expires_at=datetime.now(UTC) + timedelta(minutes=data.ttl_minutes), created_by=actor.id,
    )
    db.add(token)
    db.flush()
    audit(db, request, "agent_package_created", actor=actor, details={"token_id": str(token.id)})
    db.commit()
    return Response(result, media_type="application/zip" if data.rollout else MSI_TYPE, headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
    })


def rollout_zip(msi: bytes, migration: bytes) -> bytes:
    contents = {"deploycore-managed-agent.msi": msi, "upgrade-agent.ps1": migration}
    checksum = hashlib.sha256(msi).hexdigest()
    contents["run-upgrade.ps1"] = (
        "$ErrorActionPreference = 'Stop'\r\n"
        "& (Join-Path $PSScriptRoot 'upgrade-agent.ps1') "
        "-Msi (Join-Path $PSScriptRoot 'deploycore-managed-agent.msi') "
        f"-Sha256 '{checksum}'\r\n"
    ).encode()
    stream = io.BytesIO()
    with ZipFile(stream, "w", compression=ZIP_STORED) as archive:
        for name, data in contents.items():
            archive.writestr(name, data)
        archive.writestr("SHA256SUMS", "".join(
            f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in contents.items()
        ))
    return stream.getvalue()
