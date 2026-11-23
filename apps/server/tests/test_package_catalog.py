import hashlib
import io
import struct
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from deploycore import package_storage as storage
from deploycore.package_schemas import PackageInput, PackagePatch, VersionInput


def test_stream_checks_limit_and_disk_reserve(monkeypatch):
    free = 100
    monkeypatch.setattr(storage.shutil, "disk_usage", lambda _: SimpleNamespace(free=free))
    output = io.BytesIO()
    upload = storage.Upload(output, limit=6, reserve=20)
    upload.append(b"abc")
    free = 21
    with pytest.raises(HTTPException) as caught:
        upload.append(b"de")
    assert caught.value.status_code == 507
    free = 100
    with pytest.raises(HTTPException) as caught:
        upload.append(b"defg")
    assert caught.value.status_code == 413
    upload.append(b"def")
    assert output.getvalue() == b"abcdef"
    assert upload.hash.hexdigest() == hashlib.sha256(output.getvalue()).hexdigest()


def test_pe_input_distinguishes_architecture_and_rejects_library(tmp_path):
    installer = tmp_path / "fixture"
    header = bytearray(90)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 60, 64)
    header[64:68] = b"PE\x00\x00"
    arch = ((0x14C, 0x10B, "x86"), (0x8664, 0x20B, "x64"))
    for machine, magic, name in arch:
        struct.pack_into("<H", header, 68, machine)
        struct.pack_into("<HH", header, 86, 2, magic)
        installer.write_bytes(header)
        assert storage.installer_architecture(installer, "exe") == name
    struct.pack_into("<H", header, 86, 0x2002)
    installer.write_bytes(header)
    with pytest.raises(HTTPException, match="package_invalid_format"):
        storage.installer_architecture(installer, "exe")


def test_catalog_payload_rejects_nulls_and_duplicate_exit_codes():
    with pytest.raises(ValidationError):
        PackageInput(name="Fixture", publisher="Example", description="bad\x00value")
    with pytest.raises(ValidationError):
        PackagePatch(name=None)
    assert PackagePatch().model_dump(exclude_unset=True) == {}
    with pytest.raises(ValidationError):
        VersionInput(version="1.0", architecture="x64", installer="exe", success_codes=[0, 0],
                     detection={"kind": "registry_software", "display_name": "Fixture", "version": "1.0"})


@pytest.mark.parametrize(
    ("kind", "signature", "hash_matches", "approved"),
    [
        ("manual", "unverified", True, True),
        ("manual", "unverified", False, False),
        ("manual", "verified", True, False),
        ("authenticode", "verified", True, True),
        ("authenticode", "verified", False, False),
        ("authenticode", "unverified", True, False),
        (None, "verified", True, False),
    ],
)
def test_approval_is_bound_to_digest_and_method(kind, signature, hash_matches, approved):
    from deploycore.package_models import PackageArtifact, SoftwareVersion, artifact_approved

    version = SoftwareVersion(approval_kind=kind, approved_at=datetime.now(UTC) if kind else None,
                              approved_sha256="a" * 64 if kind else None)
    artifact = PackageArtifact(signature=signature, sha256=("a" if hash_matches else "b") * 64)
    assert artifact_approved(version, artifact) is approved
    assert not artifact_approved(version, None)


def test_manual_approval_checks_stored_file_and_audits_actor(monkeypatch, tmp_path):
    from deploycore import package_api
    from deploycore.package_models import PackageArtifact, PackageDetectionRule, SoftwareVersion
    from deploycore.package_schemas import ManualApproval

    path = tmp_path / "fixture.msi"
    path.write_bytes(b"known MSI bytes")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    version = SoftwareVersion(id=uuid4())
    artifact = PackageArtifact(version_id=version.id, signature="unverified", sha256=digest)
    actor = SimpleNamespace(id=uuid4())
    rule = object()
    db = Mock()
    db.get.return_value = artifact
    db.get_one.return_value = rule
    monkeypatch.setattr(package_api, "find_package", Mock())
    monkeypatch.setattr(package_api, "find_version", Mock(return_value=version))
    monkeypatch.setattr(package_api.storage, "artifact_path", Mock(return_value=path))
    monkeypatch.setattr(package_api, "version_view", Mock())
    audit = Mock()
    monkeypatch.setattr(package_api, "audit", audit)
    request = object()

    def approve(sha256):
        return package_api.approve_manual(uuid4(), version.id, ManualApproval(sha256=sha256), request, db, actor)

    with pytest.raises(HTTPException, match="package_approval_hash_mismatch"):
        approve("0" * 64)
    approve(digest.upper())
    approve(digest)
    assert version.approval_kind == "manual"
    assert version.approved_sha256 == digest and version.approved_by == actor.id
    assert artifact.signature == "unverified"
    audit.assert_called_once_with(db, request, "package_version_approved", actor=actor, details={
        "version_id": str(version.id), "approval_kind": "manual", "sha256": digest,
        "approved_at": version.approved_at.isoformat(),
    })
    db.get_one.assert_called_with(PackageDetectionRule, version.id)
    path.write_bytes(b"changed MSI data")
    with pytest.raises(HTTPException, match="package_approval_hash_mismatch"):
        approve(digest)
