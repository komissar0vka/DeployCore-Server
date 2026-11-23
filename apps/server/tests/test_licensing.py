import base64
import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from deploycore.licensing import (
    FREE_DEVICE_LIMIT, SIGNING_CONTEXT, GrantWatermark, LicenseValidationError, ManagementState,
    free_registration, resume_device, retire_device, used_slots, verify_grant,
)
from deploycore.licensing_contracts import cloud_contract


def test_free_counts_managed_identities_and_requires_explicit_retirement():
    devices = {uuid4(): ManagementState.MANAGED for _ in range(FREE_DEVICE_LIMIT)}
    existing, new = next(iter(devices)), uuid4()
    assert used_slots(devices) == 5
    assert free_registration(devices, existing) == "reuse_slot"
    assert free_registration(devices, new) == "limit_reached"
    with pytest.raises(ValueError, match="device_execution_unresolved"):
        retire_device(devices[existing], unresolved_execution=True)
    devices[existing] = retire_device(devices[existing], unresolved_execution=False)
    assert used_slots(devices) == 4
    assert free_registration(devices, existing) == "retired"
    assert free_registration(devices, new) == "new_slot"
    assert resume_device(devices, existing) == ManagementState.MANAGED
    devices[new] = ManagementState.MANAGED
    with pytest.raises(ValueError, match="license_limit_reached"):
        resume_device(devices, existing)


def test_cloud_contract_matches_snapshot():
    path = Path(__file__).resolve().parents[3] / "packages/licensing-contract/cloud-openapi.json"
    assert json.loads(path.read_text()) == cloud_contract()


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


@pytest.fixture
def grant(tmp_path):
    private = tmp_path / "private.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)], check=True)
    public = subprocess.check_output(["openssl", "pkey", "-in", str(private), "-pubout", "-outform", "DER"])[-32:]
    instance_id, activation = uuid4(), uuid4()
    instance_key = bytes(range(32))
    now = datetime(2026, 1, 1, tzinfo=UTC)
    fields = {
        "license_id": str(uuid4()), "activation_id": str(activation), "instance_id": str(instance_id),
        "instance_key_sha256": hashlib.sha256(instance_key).hexdigest(), "edition": "business",
        "device_limit": 20, "features": ["inventory", "catalog", "deployments"], "issue_number": 10, "issued_at": (now - timedelta(days=3)).isoformat(),
        "not_before": (now - timedelta(days=2)).isoformat(), "expires_at": (now + timedelta(days=1)).isoformat(),
        "grace_until": (now + timedelta(days=15)).isoformat(),
    }

    def signed(payload: bytes) -> bytes:
        message = tmp_path / "message"
        message.write_bytes(SIGNING_CONTEXT + b"test\x00" + payload)
        signature = subprocess.check_output([
            "openssl", "pkeyutl", "-sign", "-inkey", str(private), "-rawin", "-in", str(message),
        ])
        return json.dumps({"version": 1, "kid": "test", "payload": encode(payload), "signature": encode(signature)}).encode()

    options = {"trusted_keys": {"test": public}, "instance_id": instance_id, "instance_public_key": instance_key, "now": now}
    return fields, signed, options, activation


def test_signed_grant_and_expiry(grant):
    fields, signed, options, _ = grant
    raw = signed(json.dumps(fields).encode())
    accepted = verify_grant(raw, **options)
    assert (accepted.payload.device_limit, accepted.status) == (20, "valid")
    assert verify_grant(raw, **{**options, "previous": accepted.watermark}).watermark == accepted.watermark
    assert verify_grant(raw, **{**options, "now": options["now"] + timedelta(days=1)}).status == "grace"
    with pytest.raises(LicenseValidationError, match="license_outside_validity"):
        verify_grant(raw, **{**options, "now": options["now"] + timedelta(days=15)})


@pytest.mark.parametrize("change, reason", [
    ({"trusted_keys": {}}, "untrusted_license_key"),
    ({"instance_id": uuid4()}, "license_instance_mismatch"),
    ({"instance_public_key": b"Z" * 32}, "license_instance_mismatch"),
    ({"previous": GrantWatermark(11, "a" * 64)}, "license_issue_regression"),
    ({"previous": GrantWatermark(10, "a" * 64)}, "license_issue_regression"),
])
def test_rejects_untrusted_or_stale_grant(grant, change, reason):
    fields, signed, options, _ = grant
    with pytest.raises(LicenseValidationError, match=reason):
        verify_grant(signed(json.dumps(fields).encode()), **{**options, **change})


def test_rejects_changed_signed_bytes_and_revoked_activation(grant):
    fields, signed, options, activation = grant
    raw = signed(json.dumps(fields).encode())
    modified = {**json.loads(raw), "payload": encode(json.dumps({**fields, "device_limit": 400}).encode())}
    with pytest.raises(LicenseValidationError, match="invalid_license_signature"):
        verify_grant(json.dumps(modified).encode(), **options)
    with pytest.raises(LicenseValidationError, match="license_revoked"):
        verify_grant(raw, **options, revoked_activations=frozenset({activation}))


def test_strict_document_rejects_duplicate_and_wrong_version_type(grant):
    fields, signed, options, _ = grant
    payload = json.dumps(fields).encode()
    duplicate = signed(payload[:-1] + b', "device_limit": 99}')
    with pytest.raises(LicenseValidationError, match="duplicate_license_field"):
        verify_grant(duplicate, **options)
    raw = json.loads(signed(payload))
    with pytest.raises(LicenseValidationError, match="invalid_license_document"):
        verify_grant(json.dumps({**raw, "version": True}).encode(), **options)
