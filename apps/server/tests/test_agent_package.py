from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from deploycore import agent_package_api, schemas


@pytest.mark.parametrize("url", ["http://192.0.2.14:8444", "https://192.0.2.14/settings", "https://u:p@host"])
def test_setup_rejects_invalid_agent_origin(url):
    with pytest.raises(ValidationError):
        schemas.SetupInput(organization="Example", instance_name="Lab", username="admin",
                           password="test-password", setup_token="secret", agent_url=url)


def test_msi_build_failure_does_not_create_token(monkeypatch):
    db = Mock()
    db.get_one.return_value = SimpleNamespace(agent_url="https://192.0.2.14:8444")

    def unavailable(*_):
        raise HTTPException(503, "agent_package_unavailable")

    monkeypatch.setattr(agent_package_api, "build_msi", unavailable)
    with pytest.raises(HTTPException, match="agent_package_unavailable"):
        agent_package_api.create_agent_package(agent_package_api.PackageInput(label="Lab"), None, db, None)
    db.add.assert_not_called()
    db.commit.assert_not_called()


def test_package_rejects_private_key_as_ca():
    with pytest.raises(HTTPException, match="agent_package_invalid_ca"):
        agent_package_api.validate_ca("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----")


def test_rollout_bundle_contains_pinned_migration():
    from hashlib import sha256
    from io import BytesIO
    from zipfile import ZipFile

    installer = b"approved test installer"
    data = agent_package_api.rollout_zip(installer, b"migration script")
    with ZipFile(BytesIO(data)) as archive:
        assert set(archive.namelist()) == {"deploycore-managed-agent.msi", "upgrade-agent.ps1", "run-upgrade.ps1", "SHA256SUMS"}
        assert archive.read("deploycore-managed-agent.msi") == installer
        assert sha256(installer).hexdigest().encode() in archive.read("run-upgrade.ps1")
