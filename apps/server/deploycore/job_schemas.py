from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, field_validator

from .device_schemas import Wire
from .package_schemas import DetectionState

Operation = Literal["install", "uninstall"]
JobScope = Literal["all", "active", "problem"]
TargetState = Literal["queued", "leased", "running", "not_executed", "cancelled", "failed",
                      "succeeded", "already_installed", "already_absent", "reboot_required", "awaiting_reboot", "unknown"]
Mode = Literal["transport_only", "execute_v1"]
Stage = Literal["checking", "downloading", "executing", "verifying"]
Outcome = Literal["not_executed", "cancelled", "failed", "succeeded", "already_installed",
                  "already_absent", "reboot_required", "unknown"]
Diagnostic = Literal["download_failed", "hash_mismatch", "insufficient_space", "detection_failed", "installer_error",
                     "timeout", "interrupted", "platform_unsupported", "manifest_invalid", "process_error",
                     "operator_resolved", "detection_mismatch", "reboot_timeout", "device_removed"]


class JobInput(Wire):
    mode: Mode = "transport_only"
    version_id: UUID
    operation: Operation
    device_ids: Annotated[list[UUID], Field(min_length=1, max_length=100)]
    request_id: UUID

    @field_validator("device_ids")
    @classmethod
    def distinct_devices(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("device IDs must be unique")
        return value


class JobView(Wire):
    mode: Mode
    id: UUID
    version_id: UUID
    package_name: str
    version: str
    operation: Operation
    created_at: datetime
    counts: dict[TargetState, int]


class JobPage(Wire):
    items: list[JobView]
    total: int
    active: int
    problem: int


class TargetView(Wire):
    id: UUID
    device_id: UUID
    hostname: str
    state: TargetState
    cancel_requested: bool
    attempt: int | None
    lease_expires_at: datetime | None
    recovery_required: bool
    retry_requires_admin: bool = False
    stage: Stage | None = None
    exit_code: int | None = None
    diagnostic: Diagnostic | None = None
    output_bytes: int | None = None
    started_at: datetime | None = None
    process_started: bool | None = None
    detection: DetectionState | None = None
    reboot_deadline: datetime | None = None
    reboot_detection: DetectionState | None = None
    reboot_finished_at: datetime | None = None
    reboot_diagnostic: Diagnostic | None = None


class JobDetail(JobView):
    targets: list[TargetView]


class EventView(Wire):
    id: int
    target_id: UUID | None
    attempt_id: UUID | None
    attempt_number: int | None = None
    action: str
    created_at: datetime


class Assignment(Wire):
    target_id: UUID
    attempt_id: UUID
    version_id: UUID
    operation: Operation
    lease_expires_at: datetime
    mode: Mode = "transport_only"


class PollReply(Wire):
    assignment: Assignment | None = None
    recovery_required: bool = False


class Lease(Wire):
    attempt_id: UUID


class Heartbeat(Lease):
    stage: Stage | None = None


class LeaseReply(Wire):
    lease_expires_at: datetime
    cancel_requested: bool


class Result(Lease):
    outcome: Outcome
    exit_code: Annotated[int, Field(strict=True, ge=0, le=4294967295)] | None = None
    diagnostic: Diagnostic | None = None
    output_bytes: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)] | None = None


    process_started: bool | None = None
    detection: DetectionState | None = None
    reboot_pending: Literal[True] | None = None


class RebootResult(Lease):
    detection: DetectionState | None


class Resolve(Wire):
    verified_stopped: Literal[True]
