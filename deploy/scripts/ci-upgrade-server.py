"""Verify a beta.3 instance using the release updater and a hosted registry bundle."""
import hashlib
import http.cookiejar
import importlib.util
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.request import HTTPSHandler, HTTPCookieProcessor, Request, build_opener
from uuid import uuid4

root = Path(sys.argv[1])
artifact = Path(sys.argv[2])
origin = sys.argv[3]
os.environ["DEPLOYCORE_INSTALL_ROOT"] = str(root)
spec = importlib.util.spec_from_file_location("release_updater", Path(__file__).with_name("update-server.py"))
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)
token = next(line.partition("=")[2] for line in (root / "deploy/.env").read_text().splitlines()
             if line.startswith("DEPLOYCORE_SETUP_TOKEN="))
client = build_opener(HTTPSHandler(context=ssl.create_default_context(cafile=root / "deploy/tls/fullchain.pem")),
                      HTTPCookieProcessor(http.cookiejar.CookieJar()))
credentials = {"username": "admin", "password": secrets.token_urlsafe(24)}


def call(path, data=None, secret=None):
    headers = {"Origin": origin, "X-DeployCore-Request": "1"}
    if secret:
        headers["X-CSRF-Token"] = secret
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(origin + "/api/v1" + path, json.dumps(data).encode() if data is not None else None, headers)
    with client.open(request, timeout=10) as response:
        return json.load(response)


assert call("/setup")["configured"] is False
call("/setup", {**credentials, "organization": "Beta.3 data", "instance_name": "Keep upgrade fixture",
                "agent_url": origin, "setup_token": token})
csrf = call("/auth/login", credentials)["csrf_token"]
assert call("/settings")["version"] == "1.0.0-beta.3"
license_ = call("/licenses")
package = call("/packages", {"name":"Upgrade fixture","publisher":"CI","description":"Keep this record"}, csrf)
registration = call("/enrollment-tokens", {"label":"Upgrade fixture","max_uses":1}, csrf)["token"]
device, agent_key = str(uuid4()), secrets.token_urlsafe(32)
call("/agent/enroll", {
    "installation_id": device, "credential": agent_key, "enrollment_token": registration,
    "heartbeat": {"hostname":"WIN-UPGRADE","network_name":"WORKGROUP","domain_joined":False,
                  "ips":[],"os_version":"Windows","agent_version":"0.3.7","uptime_seconds":10},
})
recorded_hash = (artifact.parent / "SHA256SUMS").read_text().split()[0]
assert hashlib.file_digest(artifact.open("rb"), "sha256").hexdigest() == recorded_hash
# Replace only internet transport with the exact bundle produced in this hosted workflow.
updater.release_plan = lambda _channel, _version: {"size_bytes": artifact.stat().st_size}
updater.download = lambda _release, destination: shutil.copyfile(artifact, destination)
updater.STATE.mkdir(mode=0o700, exist_ok=True)
compose = updater.compose


def fail_start(*args, override=None, **kwargs):
    if args[0] == "up" and override and override.name == "candidate.json":
        compose("exec", "-T", "db", "psql", "-U", "deploycore", "-d", "deploycore", "-v", "ON_ERROR_STOP=1",
                "-c", "UPDATE installation_settings SET instance_name='Unexpected failed candidate change' WHERE id=1")
        raise subprocess.CalledProcessError(79, "simulated candidate startup failure")
    return compose(*args, override=override, **kwargs)


updater.compose = fail_start
try:
    updater.install("beta", "1.0.0-beta.4")
except subprocess.CalledProcessError as exc:
    assert exc.returncode == 79, exc
else:
    raise AssertionError("Candidate failure was not exercised")
assert call("/settings")["version"] == "1.0.0-beta.3"
assert call("/settings")["instance_name"] == "Keep upgrade fixture"

updater.compose = compose
updater.install("beta", "1.0.0-beta.4")
assert call("/settings")["version"] == "1.0.0-beta.4"
assert call("/settings")["organization"] == "Beta.3 data"
assert call("/licenses")["instance_id"] == license_["instance_id"]
assert any(item["id"] == device for item in call("/devices")["items"])
assert call("/packages/" + package["id"])["description"] == "Keep this record"
print("Beta.3 upgrade using GHCR images preserved settings, signup, license UUID, device and package; forced rollback restored the previous database")
