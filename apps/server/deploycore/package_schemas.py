from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StringConstraints, field_validator, model_validator

from .device_schemas import Wire

Title = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=160, pattern=r"^[^\x00-\x1f\x7f]+$")]
Category = Annotated[str, StringConstraints(strip_whitespace=True, max_length=160, pattern=r"^[^\x00-\x1f\x7f]*$")]
Description = Annotated[str, StringConstraints(max_length=4000, pattern=r"^[^\x00]*$")]
Arg = Annotated[str, StringConstraints(max_length=1024, pattern=r"^[^\x00-\x1f\x7f]*$")]
ExitCode = Annotated[int, Field(strict=True, ge=0, le=2**32 - 1)]


class PackageInput(Wire):
    name: Title
    publisher: Title
    description: Description = ""
    category: Category = ""


class PackagePatch(Wire):
    name: Title | None = None
    publisher: Title | None = None
    description: Description | None = None

    category: Category | None = None

    @field_validator("name", "publisher", "description", "category")
    @classmethod
    def reject_explicit_null(cls, value):
        if value is None:
            raise ValueError("field cannot be null")
        return value


class MSIProduct(Wire):
    kind: Literal["msi_product"]
    product_code: UUID


class RegistrySoftware(Wire):
    kind: Literal["registry_software"]
    display_name: Title
    version: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120, pattern=r"^[^\x00-\x1f\x7f]+$")]


LocalPath = Annotated[str, StringConstraints(max_length=240, pattern=r"^[A-Za-z]:\\[^:\x00-\x1f]+$")]


class FileExists(Wire):
    kind: Literal["file_exists"]
    path: LocalPath


class FileVersion(Wire):
    kind: Literal["file_version"]
    path: LocalPath
    version: Annotated[str, StringConstraints(pattern=r"^[0-9]{1,5}(\.[0-9]{1,5}){3}$")]


class PortableFile(Wire):
    kind: Literal["portable_file"]
    folder: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9]([A-Za-z0-9 _-]{0,62}[A-Za-z0-9])?$")]
    shortcut: bool = True

    @field_validator("folder")
    @classmethod
    def safe_folder(cls, folder):
        if folder.upper() in {"CON", "PRN", "AUX", "NUL", *(f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(10))}:
            raise ValueError("reserved Windows folder")
        return folder


DetectionLeaf = Annotated[MSIProduct | RegistrySoftware | FileExists | FileVersion, Field(discriminator="kind")]


class DetectionGroup(Wire):
    kind: Literal["all", "any"]
    schema_version: Literal[1] = 1
    rules: Annotated[list[DetectionLeaf], Field(min_length=2, max_length=8)]


Detection = Annotated[MSIProduct | RegistrySoftware | FileExists | FileVersion | DetectionGroup, Field(discriminator="kind")]
DetectionState = Literal["installed", "not_installed", "unknown"]



class VersionInput(Wire):
    version: Annotated[str, StringConstraints(strip_whitespace=True, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")]
    architecture: Literal["x64", "x86"]
    installer: Literal["msi", "exe", "portable"]
    min_windows_build: Annotated[int, Field(strict=True, ge=1, le=2**31 - 1)] | None = None
    install_args: Annotated[list[Arg], Field(max_length=64)] = Field(default_factory=list)
    uninstall_args: Annotated[list[Arg], Field(max_length=64)] | None = None
    detection: Detection
    timeout_seconds: Annotated[int, Field(strict=True, ge=1, le=86400)] = 1800
    success_codes: Annotated[list[ExitCode], Field(min_length=1, max_length=32)] = Field(default_factory=lambda: [0, 3010])
    reboot_required: bool = False

    @model_validator(mode="after")
    def portable_settings(self):
        if (self.installer == "portable") != (self.detection.kind == "portable_file"):
            raise ValueError("Portable requires a managed destination")
        if self.installer == "portable" and (self.install_args or self.uninstall_args or self.reboot_required):
            raise ValueError("Portable uses file operations without process arguments")
        return self

    @field_validator("success_codes")
    @classmethod
    def unique_codes(cls, codes):
        if len(set(codes)) != len(codes):
            raise ValueError("exit codes must be unique")
        return codes


class PackageView(PackageInput):
    id: UUID
    archived_at: datetime | None


class ArtifactView(Wire):
    filename: str
    size_bytes: int
    sha256: str
    signature: Literal["verified", "unverified"]
    uploaded_at: datetime


class ManualApproval(Wire):
    sha256: Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{64}$")]


class VersionView(VersionInput):
    id: UUID
    editable: bool
    revision: int
    approved_at: datetime | None
    approved_by: UUID | None
    approval_kind: Literal["authenticode", "manual"] | None
    approved_sha256: str | None
    artifact: ArtifactView | None


class PackageListItem(PackageView):
    can_deploy: bool


class PackagePage(Wire):
    items: list[PackageListItem]
    total: int


class PackageDetail(PackageView):
    versions: list[VersionView]


class IntakeView(Wire):
    id: UUID
    filename: str
    size_bytes: int
    sha256: str
    signature: Literal["verified", "unverified"]
    installer: Literal["msi", "exe"]
    architecture: Literal["x64", "x86"]
    name: str | None = None
    publisher: str | None = None
    version: str | None = None
    product_code: UUID | None = None
    family: Literal["inno", "nsis", "installshield", "installshield_basic_msi"] | None = None
    install_args: list[Arg] = Field(default_factory=list)
    uninstall_args: list[Arg] | None = None


class IntakeSave(Wire):
    package: PackageInput
    version: VersionInput


class IntakeSaved(Wire):
    package: PackageView
    version: VersionView


class PackageHistoryEvent(Wire):
    action: str
    created_at: datetime
    actor: str | None
