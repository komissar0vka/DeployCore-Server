#!/usr/bin/env python3
"""Apply a signed DeployCore Server release during a local maintenance window."""
import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import ssl
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"
STATE = DEPLOY / ".updater"
COMPOSE = ["docker", "compose", "--env-file", str(DEPLOY / ".env"), "-f", str(DEPLOY / "compose.yaml")]
ARTIFACT_HOST = "github.com"
ARTIFACT_PREFIX = "/komissar0vka/DeployCore-Releases/releases/download/"
FILES = {"apps/server/Dockerfile", "deploy/Dockerfile.web", "deploy/compose.yaml", "install.sh"}
MAX_ARCHIVE = 256 * 1024 * 1024
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(beta)\.([1-9][0-9]*))?")


def compose(*args, override=None, **kwargs):
    command = COMPOSE + (["-f", str(override)] if override else [])
    return subprocess.run([*command, *args], check=True, **kwargs)


def order(version):
    match = VERSION.fullmatch(version)
    if not match:
        raise ValueError("Unsupported version " + version)
    major, minor, patch, beta, number = match.groups()
    return int(major), int(minor), int(patch), not beta, int(number or 0)


def release_plan(channel, version):
    program = """
import json, sys
from deploycore.cloud_link import VERSION, connection, signed_response
cloud = connection()
channel = sys.argv[1]
manifest = signed_response(cloud.request('/v1/releases/' + channel), 'release', cloud.release_key)
print(json.dumps({'current': VERSION, 'manifest': manifest}))
"""
    output = compose("exec", "-T", "server", "python", "-c", program, channel, capture_output=True).stdout
    data = json.loads(output)
    manifest = data["manifest"]
    if manifest["channel"] != channel or datetime.fromisoformat(manifest["expires_at"]) <= datetime.now(timezone.utc):
        raise ValueError("Release manifest expired or wrong channel")
    if (channel == "stable" and "-" in version) or order(version) <= order(data["current"]):
        raise ValueError("Select a newer version from the requested channel")
    return next((row for row in manifest["releases"] if row["version"] == version), None)


def download(release, destination):
    url = urlsplit(release["archive_url"])
    expected = release["size_bytes"]
    if (url.scheme != "https" or url.netloc != ARTIFACT_HOST or not url.path.startswith(ARTIFACT_PREFIX)
            or url.query or url.fragment or not 0 < expected <= MAX_ARCHIVE):
        raise ValueError("Unexpected release archive location or size")
    digest = hashlib.sha256()
    remaining = expected
    with urlopen(release["archive_url"], context=ssl.create_default_context(), timeout=20) as source:
        if urlsplit(source.geturl()).scheme != "https":
            raise ValueError("Release download requires HTTPS")
        with destination.open("xb") as output:
            while chunk := source.read(1024 * 1024):
                remaining -= len(chunk)
                if remaining < 0:
                    raise ValueError("Download exceeds signed size")
                digest.update(chunk)
                output.write(chunk)
    if remaining or digest.hexdigest() != release["sha256"]:
        raise ValueError("Archive size or checksum differs from signed manifest")


def extract(archive, source):
    source.mkdir()
    size = 0
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isdir() or member.isreg()):
                raise ValueError("Unsafe archive entry")
            target = source / path
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            size += member.size
            if size > 4 * MAX_ARCHIVE:
                raise ValueError("Extracted release exceeds size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.extractfile(member) as data, target.open("xb") as output:
                shutil.copyfileobj(data, output)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    for directory, _, _ in os.walk(source):
        Path(directory).chmod(0o755)
    if not all((source / name).is_file() for name in FILES):
        raise ValueError("Incomplete release archive")
    if (source / "deploy/compose.yaml").read_bytes() != (DEPLOY / "compose.yaml").read_bytes():
        raise ValueError("Release changes the permanent Compose configuration; manual migration required")


def override(path, image_names, source=None):
    services = {}
    for service, image in image_names.items():
        services[service] = {"image": image}
        if source is not None:
            services[service]["build"] = {"context": str(source)}
    path.write_text(json.dumps({"services": services}))
    return path


def sql(statement, **values):
    command = ["exec", "-T", "db", "sh", "-c",
               'exec psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d template1 "$@"', "psql"]
    for name, value in values.items():
        command.extend(["-v", f"{name}={value}"])
    compose(*command, input=statement, text=True)


def backup(directory, restore_db):
    with (directory / "database.dump").open("xb") as output:
        compose("exec", "-T", "db", "sh", "-c",
                'exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc', stdout=output)
    sql('CREATE DATABASE :"restore";\n', restore=restore_db)
    with (directory / "database.dump").open("rb") as source:
        compose("exec", "-T", "db", "sh", "-c",
                'exec pg_restore --exit-on-error -U "$POSTGRES_USER" -d "$1"', "restore", restore_db, stdin=source)
    with (directory / "configuration.tar.gz").open("xb") as output, tarfile.open(fileobj=output, mode="w:gz") as bundle:
        for filename in (".env", "tls", "compose.yaml"):
            path = DEPLOY / filename
            if path.exists():
                bundle.add(path, arcname=filename)
    paths = (("server", "packages", "/var/lib/deploycore/packages"),
             ("server", "cloud", "/var/lib/deploycore/cloud"),
             ("web", "tls", "/etc/deploycore/tls"))
    for service, name, path in paths:
        container = compose("ps", "-aq", service, capture_output=True, text=True).stdout.strip()
        archive = directory / (name + ".tar")
        with archive.open("xb") as output:
            subprocess.run(["docker", "cp", f"{container}:{path}/.", "-"], stdout=output, check=True)
        with tarfile.open(archive) as bundle:
            bundle.getmembers()


def install(channel, version):
    release = release_plan(channel, version)
    if not release:
        raise ValueError("Signed manifest does not include requested version")
    database_size = int(compose("exec", "-T", "db", "sh", "-c",
        'exec psql -At -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT pg_database_size(current_database())"',
        capture_output=True, text=True).stdout)
    volume_sizes = [compose("exec", "-T", service, "du", "-sk", path, capture_output=True, text=True).stdout
                    for service, path in (("server", "/var/lib/deploycore"), ("web", "/etc/deploycore/tls"))]
    backup_space = database_size * 2 + sum(int(size.split()[0]) * 1024 for size in volume_sizes)
    docker_directory = Path(subprocess.check_output(["docker", "info", "--format", "{{.DockerRootDir}}"], text=True).strip())
    available = min(shutil.disk_usage(STATE).free, shutil.disk_usage(docker_directory).free)
    if available < 1024**3 + backup_space + release["size_bytes"] * 5:
        raise ValueError("Insufficient free space to build and retain backup")
    suffix = uuid4().hex[:12]
    work = STATE / (version + "-" + suffix)
    work.mkdir()
    archive, source = work / "release.tar.gz", work / "source"
    download(release, archive)
    extract(archive, source)
    old_images = {}
    new_images = {}
    for service in ("server", "web"):
        container = compose("ps", "-q", service, capture_output=True, text=True).stdout.strip()
        old_image = subprocess.check_output(["docker", "inspect", "--format", "{{.Image}}", container], text=True).strip()
        old_images[service] = f"deploycore-local-{service}:previous-{suffix}"
        new_images[service] = f"deploycore-local-{service}:{version}-{suffix}"
        subprocess.run(["docker", "tag", old_image, old_images[service]], check=True)
    previous = override(work / "previous.json", old_images)
    candidate = override(work / "candidate.json", new_images, source)
    compose("build", "server", "web", override=candidate)
    database = compose("exec", "-T", "db", "printenv", "POSTGRES_DB", capture_output=True, text=True).stdout.strip()
    restore_db, failed_db = "restore_" + suffix, "failed_" + suffix
    backup_complete = False
    attempt_started = False
    try:
        compose("stop", "web", "server")
        backup(work, restore_db)
        backup_complete = True
        attempt_started = True
        compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "180", "server", override=candidate)
        running_version = compose("exec", "-T", "server", "python", "-c",
                                  "from deploycore.cloud_link import VERSION; print(VERSION)",
                                  capture_output=True, text=True).stdout.strip()
        if running_version != version:
            raise ValueError("Running version differs from signed manifest")
        compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "90", "web", override=candidate)
    except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt):
        if backup_complete and attempt_started:
            compose("stop", "web", "server", override=candidate)
            sql('BEGIN;\nALTER DATABASE :"current" RENAME TO :"failed";\nALTER DATABASE :"restore" RENAME TO :"current";\nCOMMIT;\n',
                current=database, failed=failed_db, restore=restore_db)
        compose("up", "-d", "--no-build", "--wait", "server", "web", override=previous)
        raise
    marker = STATE / "active.json"
    temporary = STATE / "active.tmp"
    temporary.write_text(candidate.read_text())
    temporary.replace(marker)
    sql('DROP DATABASE :"restore";\n', restore=restore_db)
    print(f"Installed {version}. Backup retained at {work}")


def terminate(_signal, _frame):
    raise KeyboardInterrupt


def main():
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("channel", choices=["stable", "beta"])
    parser.add_argument("version")
    args = parser.parse_args()
    STATE.mkdir(mode=0o700, exist_ok=True)
    os.umask(0o077)
    with (STATE / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        install(args.channel, args.version)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
