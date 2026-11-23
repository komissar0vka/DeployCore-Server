from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, StringConstraints, model_validator

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=253, pattern=r"^[^\x00-\x1f\x7f]+$")]
Short = Annotated[str, StringConstraints(max_length=253, pattern=r"^[^\x00-\x1f\x7f]*$")]
Version = Annotated[str, StringConstraints(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9._+\-]+$")]
Secret = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{43}$")]
Size = Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]


class Wire(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class Heartbeat(Wire):
    hostname: Name
    fqdn: Short = ""
    network_name: Short = ""
    domain_joined: Annotated[bool, Field(strict=True)]
    ips: Annotated[list[IPvAnyAddress], Field(max_length=64)]
    os_version: Annotated[str, StringConstraints(min_length=1, max_length=200, pattern=r"^[^\x00-\x1f\x7f]+$")]
    agent_version: Version
    uptime_seconds: Size


class Enroll(Wire):
    installation_id: UUID
    enrollment_token: Secret
    credential: Secret
    heartbeat: Heartbeat


class Connection(Wire):
    device_id: UUID
    heartbeat_seconds: int
    last_seen_at: datetime


class OSInfo(Wire):
    version: Annotated[str, StringConstraints(min_length=1, max_length=200, pattern=r"^[^\x00-\x1f\x7f]*$")]
    build: Annotated[str, StringConstraints(max_length=80, pattern=r"^[^\x00-\x1f\x7f]*$")]
    architecture: Literal["amd64", "arm64", "386"]


class CPU(Wire):
    model: Annotated[str, StringConstraints(min_length=1, max_length=240, pattern=r"^[^\x00-\x1f\x7f]*$")]
    cores: Annotated[int, Field(strict=True, ge=1, le=65535)]
    threads: Annotated[int, Field(strict=True, ge=1, le=65535)]


class Disk(Wire):
    letter: Annotated[str, StringConstraints(pattern=r"^[A-Z]:$")]
    size_bytes: Size
    free_bytes: Size
    filesystem: Short = ""
    label: Short = ""

    @model_validator(mode="after")
    def free_space(self):
        if self.free_bytes > self.size_bytes:
            raise ValueError("Free space exceeds disk size")
        return self


class Interface(Wire):
    name: Name
    mac: Short = ""
    ips: Annotated[list[IPvAnyAddress], Field(max_length=64)]


class Hardware(Wire):
    manufacturer: Short = ""
    model: Short = ""
    os: OSInfo
    cpus: Annotated[list[CPU], Field(min_length=1, max_length=64)]
    ram_bytes: Size
    disks: Annotated[list[Disk], Field(max_length=26)]
    interfaces: Annotated[list[Interface], Field(max_length=128)]


class Software(Wire):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=240, pattern=r"^[^\x00-\x1f\x7f]*$")]
    version: Annotated[str, StringConstraints(max_length=120, pattern=r"^[^\x00-\x1f\x7f]*$")] = ""
    publisher: Annotated[str, StringConstraints(max_length=200, pattern=r"^[^\x00-\x1f\x7f]*$")] = ""


class Inventory(Wire):
    hardware: Hardware
    software: Annotated[list[Software], Field(max_length=2000)]


class InventoryView(Wire):
    hardware: Hardware
    collected_at: datetime


class TokenInput(Wire):
    label: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120, pattern=r"^[^\x00-\x1f\x7f]*$")]
    ttl_minutes: Annotated[int, Field(strict=True, ge=1, le=10080)] = 60
    max_uses: Annotated[int, Field(strict=True, ge=1, le=100)] = 1
    device_id: UUID | None = None

    @model_validator(mode="after")
    def recovery_usage(self):
        if self.device_id is not None and self.max_uses != 1:
            raise ValueError("Recovery tokens are single use")
        return self


class TokenView(Wire):
    id: UUID
    label: str
    expires_at: datetime
    revoked_at: datetime | None
    created_at: datetime
    max_uses: int
    uses: int
    device_id: UUID | None


class IssuedToken(Wire):
    token: str
    enrollment: TokenView


class DeviceView(Heartbeat):
    id: UUID
    last_seen_at: datetime
    online: bool
    agent_revoked: bool
    management_state: Literal["managed", "retired"] = "managed"


class DevicePage(Wire):
    items: list[DeviceView]
    total: int


class EventView(Wire):
    id: int
    action: str
    created_at: datetime


class DeviceDetail(Wire):
    device: DeviceView
    inventory: InventoryView | None
    software: list[Software]
    events: list[EventView]


class FleetEvent(EventView):
    hostname: str


class FleetError(Wire):
    action: str
    hostname: str | None = None
    created_at: datetime


class FleetSummary(Wire):
    total: int
    online: int
    offline: int
    versions: dict[str, int]
    events: list[FleetEvent]
    errors: list[FleetError]


class AgentIssue(Wire):
    action: Literal["inventory_failed"]
