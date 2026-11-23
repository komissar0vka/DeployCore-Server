from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field, HttpUrl, SecretStr, StringConstraints


class Role(StrEnum):
    SUPER_ADMIN = "super_admin"
    ADMINISTRATOR = "administrator"
    VIEWER = "viewer"


Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
Username = Annotated[
    str,
    StringConstraints(min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9._@-]*$"),
    BeforeValidator(lambda value: value.strip().lower() if isinstance(value, str) else value),
]
NewPassword = Annotated[SecretStr, Field(min_length=12, max_length=128)]


def validate_agent_origin(url: HttpUrl | None) -> HttpUrl | None:
    if url is not None and (
        url.scheme != "https" or url.username is not None or url.password is not None
        or url.query is not None or url.fragment is not None or url.path not in ("", "/")
        or len(str(url)) > 512
    ):
        raise ValueError("Expected an HTTPS origin")
    return url


AgentOrigin = Annotated[HttpUrl | None, AfterValidator(validate_agent_origin)]


class Organization(BaseModel):
    organization: Name
    instance_name: Name


class SetupInput(Organization):
    username: Username
    password: NewPassword
    agent_url: AgentOrigin = None
    setup_token: Annotated[SecretStr, Field(min_length=1, max_length=256)]


class SetupStatus(BaseModel):
    configured: bool
    token_configured: bool
    language: Literal["ru", "en"]


class LoginInput(BaseModel):
    username: Username
    password: Annotated[SecretStr, Field(min_length=1, max_length=128)]


class PublicUser(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    username: str
    role: Role


class SessionView(BaseModel):
    user: PublicUser
    csrf_token: str
    expires_at: datetime


class CreateUser(BaseModel):
    username: Username
    password: NewPassword
    role: Role


class ChangeRole(BaseModel):
    role: Role


class SettingsInput(Organization):
    agent_url: AgentOrigin
    heartbeat_seconds: Annotated[int, Field(strict=True, ge=15, le=3600)]
    language: Literal["ru", "en"]



class SettingsView(SettingsInput):
    model_config = ConfigDict(from_attributes=True)

    version: str


class AuditView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    action: str
    actor_id: UUID | None
    target_id: UUID | None
    details: dict[str, str]
    created_at: datetime
