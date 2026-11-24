"""Ed25519 authorization for agents with an independently installed trust policy."""
import base64
import json
import os
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID

from fastapi import HTTPException
from typing import Literal

from pydantic import BaseModel

CONTEXT = b"DeployCore-execution-v1\0"
LIFETIME = timedelta(minutes=15)


class ExecutionBinding(BaseModel):
    device_id: UUID
    target_id: UUID
    attempt_id: UUID
    version_id: UUID
    operation: Literal["install", "uninstall"]


class SignedExecution(BaseModel):
    version: Literal[1] = 1
    key_id: str
    payload: str
    signature: str


def encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def authorize(binding: ExecutionBinding, manifest: BaseModel, now: datetime) -> SignedExecution:
    key_file = os.environ.get("DEPLOYCORE_JOB_SIGNING_KEY_FILE")
    key_id = os.environ.get("DEPLOYCORE_JOB_SIGNING_KEY_ID", "")
    if not key_file or not Path(key_file).is_absolute() or not re.fullmatch("[A-Za-z0-9_-]{1,48}", key_id):
        raise HTTPException(503, "execution_signing_unavailable")
    payload = json.dumps({
        **binding.model_dump(mode="json"),
        "issued_at": now.isoformat(),
        "expires_at": (now + LIFETIME).isoformat(),
        "manifest": manifest.model_dump(mode="json"),
    }, separators=(",", ":"), sort_keys=True).encode("utf-8")
    try:
        with TemporaryDirectory(prefix="deploycore-execution-") as directory:
            message = Path(directory) / "message"
            message.write_bytes(CONTEXT + key_id.encode("ascii") + b"\0" + payload)
            result = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key_file, "-in", str(message)],
                                    stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise HTTPException(503, "execution_signing_unavailable") from exc
    if len(result.stdout) != 64:
        raise HTTPException(503, "execution_signing_unavailable")
    return SignedExecution(key_id=key_id, payload=encode(payload), signature=encode(result.stdout))
