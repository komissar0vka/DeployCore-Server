"""Local host service for fixed backup and signed-update operations."""
import argparse
import fcntl
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tarfile
import time
from pathlib import Path
from uuid import UUID

spec = importlib.util.spec_from_file_location("deploycore_updater", Path(__file__).with_name("update-server.py"))
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)

ROOT = updater.DEPLOY / ".operations"
INBOX = ROOT / "inbox"
OUTBOX = ROOT / "outbox"
STATUS = OUTBOX / "status.json"


def status(request, stage):
    temporary = OUTBOX / "status.tmp"
    temporary.write_text(json.dumps({"id": request["id"], "action": request["action"], "stage": stage}))
    temporary.chmod(0o644)
    temporary.replace(STATUS)


def read_request(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 10001 or info.st_size > 4096:
            raise ValueError("Invalid request file")
        raw = stream.read(4097)
    data = json.loads(raw)
    if not isinstance(data, dict) or str(UUID(data["id"])) != data["id"]:
        raise ValueError("Invalid operation identity")
    if data["action"] == "backup" and set(data) == {"id", "action"}:
        return data
    if (data["action"] == "update" and set(data) == {"id", "action", "channel", "version"}
            and data["channel"] in {"stable", "beta"} and updater.VERSION.fullmatch(data["version"])):
        return data
    raise ValueError("Unsupported operation")


def make_backup(request):
    if shutil.disk_usage(ROOT).free < 256 * 1024 * 1024:
        raise ValueError("Insufficient disk space to create a backup")
    target = ROOT / request["id"]
    target.mkdir(mode=0o700)
    restore_db = "ops_" + UUID(request["id"]).hex[:24]
    marker = updater.STATE / "active.json"
    active = marker if marker.is_file() else None
    status(request, "backing_up")
    try:
        updater.compose("stop", "web", "server", override=active)
        updater.backup(target, restore_db)
    finally:
        try:
            updater.sql('DROP DATABASE IF EXISTS :"restore";\n', restore=restore_db)
        finally:
            updater.compose("up", "-d", "--no-build", "--wait", "server", "web", override=active)
    pending = ROOT / (request["id"] + ".tar.gz")
    with tarfile.open(pending, "x:gz") as archive:
        for file in sorted(target.iterdir()):
            archive.add(file, arcname=file.name, recursive=False)
    pending.chmod(0o644)
    pending.replace(OUTBOX / pending.name)
    for file in target.iterdir():
        file.unlink()
    target.rmdir()


def process(path):
    request = read_request(path)
    status(request, "running")
    try:
        updater.STATE.mkdir(mode=0o700, exist_ok=True)
        with (updater.STATE / "lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if request["action"] == "backup":
                make_backup(request)
            else:
                updater.install(request["channel"], request["version"], progress=lambda stage: status(request, stage))
    except Exception:
        status(request, "failed")
        raise
    status(request, "completed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    queue = INBOX / "request.json"
    running = ROOT / "running.json"
    if running.exists() or running.is_symlink():
        try:
            status(read_request(running), "interrupted")
        finally:
            running.unlink(missing_ok=True)
    while True:
        try:
            queue.replace(running)
        except FileNotFoundError:
            pass
        else:
            try:
                process(running)
            except Exception as error:
                print(f"DeployCore operation failed: {type(error).__name__}", flush=True)
            finally:
                running.unlink(missing_ok=True)
        if args.once:
            break
        time.sleep(2)


if __name__ == "__main__":
    main()
