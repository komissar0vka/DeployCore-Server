import json
import subprocess
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi import HTTPException
from pydantic import BaseModel

from deploycore.job_signing import CONTEXT, ExecutionBinding, authorize
from deploycore.licensing import decode_base64url, verify_ed25519


class ManifestFixture(BaseModel):
    sha256: str


def test_execution_authorization_binds_manifest_device_and_attempt(tmp_path, monkeypatch):
    pem = tmp_path / "key.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(pem)], check=True)
    public = subprocess.check_output(["openssl", "pkey", "-pubout", "-outform", "DER", "-in", str(pem)])[-32:]
    monkeypatch.setenv("DEPLOYCORE_JOB_SIGNING_KEY_FILE", str(pem))
    monkeypatch.setenv("DEPLOYCORE_JOB_SIGNING_KEY_ID", "execution-test")
    now = datetime.now(UTC)
    binding = ExecutionBinding(device_id=uuid4(), target_id=uuid4(), attempt_id=uuid4(),
                               version_id=uuid4(), operation="install")
    manifest = ManifestFixture(sha256="1" * 64)
    result = authorize(binding, manifest, now)
    payload = decode_base64url(result.payload)
    verify_ed25519(public, CONTEXT + b"execution-test\0" + payload, decode_base64url(result.signature))
    decoded = json.loads(payload)
    assert {key: decoded[key] for key in ExecutionBinding.model_fields} == binding.model_dump(mode="json")
    assert decoded["manifest"] == manifest.model_dump()
    assert datetime.fromisoformat(decoded["expires_at"]) > now


def test_missing_execution_signer_fails_closed(monkeypatch):
    monkeypatch.delenv("DEPLOYCORE_JOB_SIGNING_KEY_FILE", raising=False)
    with pytest.raises(HTTPException) as error:
        authorize(ExecutionBinding(device_id=uuid4(), target_id=uuid4(), attempt_id=uuid4(),
                                   version_id=uuid4(), operation="uninstall"),
                  ManifestFixture(sha256="1" * 64), datetime.now(UTC))
    assert error.value.status_code == 503
