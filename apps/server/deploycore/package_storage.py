import errno
import fcntl
import hashlib
import os
import shutil
import struct
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import BinaryIO
from uuid import UUID

import anyio
from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

MIB = 1024 * 1024
DEFAULT_CA = "/etc/ssl/certs/ca-certificates.crt"


def storage_root() -> Path:
    return Path(os.getenv("DEPLOYCORE_PACKAGE_DIR", "/var/lib/deploycore/packages"))


def artifact_path(version_id: UUID, storage_key: UUID | None = None) -> Path:
    return storage_root() / str(storage_key or version_id)


def sync_directory():
    descriptor = os.open(storage_root(), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def upload_slot(root: Path):
    try:
        descriptor = (root / ".upload.lock").open("a+b")
    except OSError as exc:
        raise storage_error(exc) from exc
    with descriptor:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise HTTPException(429, "package_upload_busy", headers={"Retry-After": "15"}) from exc
        yield


def storage_error(exc: OSError) -> HTTPException:
    if exc.errno in {errno.ENOSPC, errno.EDQUOT}:
        return HTTPException(507, "package_storage_full")
    return HTTPException(503, "package_storage_unavailable")


def installer_architecture(path: Path, installer: str) -> str:
    if installer == "msi":
        with path.open("rb") as file:
            if file.read(8) != bytes.fromhex("d0cf11e0a1b11ae1"):
                raise HTTPException(422, "package_invalid_format")
        info = tool(["msiinfo", "suminfo", str(path)])
        tables = tool(["msiinfo", "tables", str(path)])
        if info.returncode == 0 and tables.returncode == 0 and "Property" in tables.stdout.splitlines():
            for line in info.stdout.splitlines():
                if line.startswith("Template:"):
                    platform = line.partition(":")[2].strip().partition(";")[0].lower()
                    if platform in {"intel", "x64"}:
                        return "x86" if platform == "intel" else "x64"
        raise HTTPException(422, "package_invalid_format")

    with path.open("rb") as file:
        dos = file.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise HTTPException(422, "package_invalid_format")
        pe_offset, = struct.unpack_from("<I", dos, 60)
        if not 64 <= pe_offset <= path.stat().st_size - 26:
            raise HTTPException(422, "package_invalid_format")
        file.seek(pe_offset)
        header = file.read(26)
        machine = int.from_bytes(header[4:6], "little")
        flags = int.from_bytes(header[22:24], "little")
        magic = int.from_bytes(header[24:26], "little")
        architecture = {(0x14C, 0x10B): "x86", (0x8664, 0x20B): "x64"}.get((machine, magic))
        if header[:4] != b"PE\x00\x00" or not (flags & 0x0002) or flags & 0x2000 or not architecture:
            raise HTTPException(422, "package_invalid_format")
        return architecture


def tool(args: list[str], *, capture: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
                              encoding="utf-8", errors="replace", timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HTTPException(503, "package_verifier_unavailable") from exc


def authenticity(path: Path) -> str:
    ca = os.getenv("DEPLOYCORE_PACKAGE_CA_FILE") or DEFAULT_CA
    if not os.access(ca, os.R_OK):
        raise HTTPException(503, "package_verifier_unavailable")
    result = tool(["osslsigncode", "verify", "-CAfile", ca, "-TSA-CAfile", ca, "-in", str(path)], capture=False)
    return "verified" if result.returncode == 0 else "unverified"


@dataclass
class Upload:
    file: BinaryIO
    limit: int
    reserve: int
    size: int = 0

    def __post_init__(self):
        self.hash = hashlib.sha256()

    def append(self, data: bytes):
        remaining = self.size + len(data)
        if remaining > self.limit:
            raise HTTPException(413, "package_too_large")
        if shutil.disk_usage(storage_root()).free < self.reserve + len(data):
            raise HTTPException(507, "package_storage_full")
        self.file.write(data)
        self.hash.update(data)
        self.size = remaining


@contextmanager
def temporary_upload(request: Request):
    root = storage_root()
    limit = min(2048, max(1, int(os.getenv("DEPLOYCORE_PACKAGE_MAX_MIB", "1024")))) * MIB
    reserve = max(0, int(os.getenv("DEPLOYCORE_PACKAGE_RESERVE_MIB", "256"))) * MIB
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isascii() or not declared.isdecimal() or len(declared) > 12):
        raise HTTPException(400, "package_body_length")
    if declared is not None and int(declared) > limit:
        raise HTTPException(413, "package_too_large")
    try:
        with upload_slot(root):
            if shutil.disk_usage(root).free < reserve + (int(declared) if declared is not None else 1):
                raise HTTPException(507, "package_storage_full")
            # No other upload holds the volume lock. Discard a partial transfer left by an unexpected process exit.
            for partial in root.glob(".part-*"):
                partial.unlink(missing_ok=True)
            with NamedTemporaryFile(mode="wb", dir=root, prefix=".part-", delete_on_close=False) as file:
                yield Upload(file, limit, reserve)
    except OSError as exc:
        raise storage_error(exc) from exc


async def receive(request: Request, upload: Upload) -> Path:
    try:
        with anyio.fail_after(900):
            async for chunk in request.stream():
                if chunk:
                    await run_in_threadpool(upload.append, chunk)
    except TimeoutError as exc:
        raise HTTPException(408, "package_upload_timeout") from exc
    except ClientDisconnect as exc:
        raise HTTPException(400, "package_upload_disconnected") from exc
    declared = request.headers.get("content-length")
    if not upload.size or (declared is not None and int(declared) != upload.size):
        raise HTTPException(400, "package_body_length")
    await run_in_threadpool(upload.file.flush)
    await run_in_threadpool(os.fsync, upload.file.fileno())
    return Path(upload.file.name)
