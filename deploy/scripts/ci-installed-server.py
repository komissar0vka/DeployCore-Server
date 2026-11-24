"""Verify the installed web interface can request and download a real host backup."""
import http.cookiejar
import io
import json
import secrets
import ssl
import sys
import tarfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import HTTPSHandler, HTTPCookieProcessor, Request, build_opener

root = Path(sys.argv[1])
origin = sys.argv[2]
token = next(line.partition("=")[2] for line in (root / "deploy/.env").read_text().splitlines()
             if line.startswith("DEPLOYCORE_SETUP_TOKEN="))
client = build_opener(HTTPSHandler(context=ssl.create_default_context(cafile=root / "deploy/tls/fullchain.pem")),
                      HTTPCookieProcessor(http.cookiejar.CookieJar()))
credentials = {"username": "admin", "password": secrets.token_urlsafe(24)}


def call(path, data=None, csrf=None, raw=False):
    headers = {"Origin": origin, "X-DeployCore-Request": "1"}
    if csrf:
        headers["X-CSRF-Token"] = csrf
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(origin + "/api/v1" + path, json.dumps(data).encode() if data is not None else None, headers)
    with client.open(request, timeout=10) as response:
        return response.read() if raw else json.load(response)


assert not call("/setup")["configured"]
call("/setup", {**credentials, "organization": "CI", "instance_name": "Image-only install",
                "agent_url": origin, "setup_token": token})
csrf = call("/auth/login", credentials)["csrf_token"]
assert call("/licenses")["limit"] == 5
status = call("/operations")
assert status["available"]
queued = call("/operations", {"action": "backup"}, csrf)
deadline = time.monotonic() + 180
while time.monotonic() < deadline:
    try:
        state = call("/operations")
    except (OSError, URLError):
        time.sleep(2)
        continue
    status = state["status"]
    if status and status["id"] == queued["id"]:
        assert status["stage"] not in {"failed", "interrupted"}, status
        if status["stage"] == "completed":
            break
    time.sleep(2)
else:
    raise RuntimeError("Host backup did not finish")
assert state["backups"][0]["id"] == queued["id"]
archive = call("/operations/backups/" + queued["id"], raw=True)
with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as files:
    assert {"database.dump", "packages.tar", "cloud.tar", "tls.tar", "configuration.tar.gz"} <= set(files.getnames())
print("Fresh image-only installation, initial settings, host backup and authorized download verified")
