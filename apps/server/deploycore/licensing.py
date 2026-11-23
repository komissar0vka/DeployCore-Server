import base64
import hashlib
import json
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal
from uuid import UUID

from pydantic import ValidationError

from .licensing_contracts import GrantPayload, SignedGrant

FREE_DEVICE_LIMIT = 5
SIGNING_CONTEXT = b"DeployCore-license-v1\x00"
ED25519_SPKI = bytes.fromhex("302a300506032b6570032100")


class ManagementState(StrEnum):
    MANAGED = "managed"
    RETIRED = "retired"


def free_registration(devices: Mapping[UUID, ManagementState], device_id: UUID) -> Literal[
    "reuse_slot", "new_slot", "retired", "limit_reached"
]:
    state = devices.get(device_id)
    if state == ManagementState.MANAGED:
        return "reuse_slot"
    if state == ManagementState.RETIRED:
        return "retired"
    return "new_slot" if used_slots(devices) < FREE_DEVICE_LIMIT else "limit_reached"


def used_slots(devices: Mapping[UUID, ManagementState]) -> int:
    return sum(state == ManagementState.MANAGED for state in devices.values())


def retire_device(state: ManagementState, *, unresolved_execution: bool) -> ManagementState:
    if state == ManagementState.MANAGED and unresolved_execution:
        raise ValueError("device_execution_unresolved")
    return ManagementState.RETIRED


def resume_device(devices: Mapping[UUID, ManagementState], device_id: UUID) -> ManagementState:
    if devices.get(device_id) != ManagementState.RETIRED:
        raise ValueError("device_not_retired")
    if used_slots(devices) >= FREE_DEVICE_LIMIT:
        raise ValueError("license_limit_reached")
    return ManagementState.MANAGED


class LicenseValidationError(ValueError):
    pass


@dataclass(frozen=True)
class GrantWatermark:
    issue_number: int
    payload_sha256: str


@dataclass(frozen=True)
class VerifiedGrant:
    payload: GrantPayload
    watermark: GrantWatermark
    status: Literal["valid", "grace"]


def decode_base64url(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise LicenseValidationError("invalid_license_encoding") from exc
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise LicenseValidationError("invalid_license_encoding")
    return decoded


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LicenseValidationError("duplicate_license_field")
        result[key] = value
    return result


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> None:
    if len(public_key) != 32 or len(signature) != 64:
        raise LicenseValidationError("invalid_signature_material")
    try:
        with TemporaryDirectory(prefix="deploycore-grant-") as scratch:
            directory = Path(scratch)
            key_path, payload_path, signature_path = (directory / name for name in ("public.der", "payload", "signature"))
            key_path.write_bytes(ED25519_SPKI + public_key)
            payload_path.write_bytes(message)
            signature_path.write_bytes(signature)
            result = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", str(key_path),
                 "-rawin", "-in", str(payload_path), "-sigfile", str(signature_path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LicenseValidationError("license_verifier_unavailable") from exc
    if result.returncode:
        raise LicenseValidationError("invalid_license_signature")


def verify_grant(raw: bytes, *, trusted_keys: Mapping[str, bytes], instance_id: UUID, instance_public_key: bytes,
                 now: datetime, previous: GrantWatermark | None = None,
                 revoked_activations: frozenset[UUID] = frozenset()) -> VerifiedGrant:
    if not 0 < len(raw) <= 24 * 1024 or len(instance_public_key) != 32 or now.utcoffset() is None:
        raise LicenseValidationError("invalid_license_input")
    try:
        envelope = SignedGrant.model_validate(json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object))
        public_key = trusted_keys.get(envelope.kid)
        if public_key is None:
            raise LicenseValidationError("untrusted_license_key")
        payload_bytes = decode_base64url(envelope.payload)
        verify_ed25519(public_key, SIGNING_CONTEXT + envelope.kid.encode("ascii") + b"\x00" + payload_bytes,
                       decode_base64url(envelope.signature))
        payload = GrantPayload.model_validate(json.loads(payload_bytes.decode("utf-8"), object_pairs_hook=strict_object))
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValidationError) as exc:
        raise LicenseValidationError("invalid_license_document") from exc

    if payload.instance_id != instance_id or payload.instance_key_sha256 != hashlib.sha256(instance_public_key).hexdigest():
        raise LicenseValidationError("license_instance_mismatch")
    if payload.activation_id in revoked_activations:
        raise LicenseValidationError("license_revoked")
    if now < payload.not_before or now >= payload.grace_until:
        raise LicenseValidationError("license_outside_validity")
    watermark = GrantWatermark(payload.issue_number, hashlib.sha256(payload_bytes).hexdigest())
    if previous is not None and (watermark.issue_number < previous.issue_number or (
        watermark.issue_number == previous.issue_number and watermark != previous
    )):
        raise LicenseValidationError("license_issue_regression")
    return VerifiedGrant(payload, watermark, "valid" if now < payload.expires_at else "grace")
