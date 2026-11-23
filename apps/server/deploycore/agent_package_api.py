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
    "content": {MSI_TYPE: {"schema": {"type": "string", "format": "binary"}}},
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
    token = EnrollmentToken(
        token_hash=digest(raw), label=data.label, max_uses=data.max_uses, uses=0,
        expires_at=datetime.now(UTC) + timedelta(minutes=data.ttl_minutes), created_by=actor.id,
    )
    db.add(token)
    db.flush()
    audit(db, request, "agent_package_created", actor=actor, details={"token_id": str(token.id)})
    db.commit()
    return Response(msi, media_type=MSI_TYPE, headers={
        "Content-Disposition": 'attachment; filename="deploycore-managed-agent.msi"',
        "Cache-Control": "no-store",
    })
