"""Optional outbound connection to a pinned DeployCore Cloud."""
import asyncio
import base64
import json
import logging
import re
import ssl
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, UTC
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from . import licensing
from .license_models import LicenseState

DIRECTORY = Path("/var/lib/deploycore/cloud")
CONFIG = DIRECTORY / "connection.json"
PRIVATE_KEY = DIRECTORY / "instance.pem"
VERSION = "1.0.0-beta.2"
LOG = logging.getLogger(__name__)


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def run(*args):
    return subprocess.run(["openssl", *args], capture_output=True, check=True, timeout=5).stdout


def instance_public_key():
    der = run("pkey", "-in", str(PRIVATE_KEY), "-pubout", "-outform", "DER")
    if not der.startswith(licensing.ED25519_SPKI) or len(der) != len(licensing.ED25519_SPKI) + 32:
        raise ValueError("invalid_instance_key")
    return der[-32:]


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class Connection:
    origin: str
    token: str
    license_key: bytes
    release_key: bytes
    ca: str | None

    def request(self, path, payload=None):
        context = ssl.create_default_context()
        if self.ca:
            context.load_verify_locations(cadata=self.ca)
        headers = {"Accept": "application/json"}
        body = None
        if payload is not None:
            headers.update(Authorization=f"Bearer {self.token}", **{"Content-Type": "application/json"})
            body = json.dumps(payload).encode()
        request = Request(self.origin + path, headers=headers, data=body)
        with build_opener(HTTPSHandler(context=context), NoRedirect()).open(request, timeout=7) as response:
            raw = response.read(524289)
        if len(raw) > 524288:
            raise ValueError("oversized_cloud_response")
        return json.loads(raw, object_pairs_hook=licensing.strict_object)


def connection(data=None):
    if data is None:
        data = json.loads(CONFIG.read_text())
    origin = urlsplit(data["origin"])
    if (origin.scheme != "https" or not origin.hostname or origin.username or origin.password
            or origin.path or origin.query or origin.fragment):
        raise ValueError("https_origin_required")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", data["token"]):
        raise ValueError("invalid_activation_token")
    license_key, release_key = (licensing.decode_base64url(data[key]) for key in ("license_key", "release_key"))
    if len(license_key) != 32 or len(release_key) != 32:
        raise ValueError("invalid_cloud_key")
    return Connection(data["origin"], data["token"], license_key, release_key, data.get("ca"))


def signed_response(envelope, purpose, key):
    kid = f"cloud-{purpose}-1"
    if set(envelope) != {"version", "kid", "payload", "signature"} or envelope["version"] != 1 or envelope["kid"] != kid:
        raise ValueError("invalid_cloud_envelope")
    payload = licensing.decode_base64url(envelope["payload"])
    signature = licensing.decode_base64url(envelope["signature"])
    context = f"DeployCore-{purpose}-v1\0{kid}\0".encode()
    licensing.verify_ed25519(key, context + payload, signature)
    return json.loads(payload, object_pairs_hook=licensing.strict_object)


def refresh(engine):
    cloud = connection()
    public = instance_public_key()
    with Session(engine) as db:
        instance_id = db.get_one(LicenseState, 1).instance_id
    identity = dict(protocol=1, instance_id=str(instance_id), instance_public_key=encoded(public))
    challenge = cloud.request("/v1/activation/challenge", identity)
    request_id = str(uuid4())
    proof = f"DeployCore-activation-v1\0{instance_id}\0{challenge['challenge_id']}\0{challenge['nonce']}\0{request_id}".encode()
    with NamedTemporaryFile() as payload:
        payload.write(proof)
        payload.flush()
        signature = run("pkeyutl", "-sign", "-rawin", "-inkey", str(PRIVATE_KEY), "-in", payload.name)
    envelope = cloud.request("/v1/activation/complete", {
        **identity, "challenge_id": challenge["challenge_id"], "proof": encoded(signature),
        "request_id": request_id, "server_version": VERSION,
    })
    result = signed_response(envelope, "license", cloud.license_key)
    with Session(engine) as db, db.begin():
        state = db.get_one(LicenseState, 1, with_for_update=True)
        if result.get("status") in {"revoked", "expired"}:
            if result.get("instance_id") != str(instance_id) or result.get("challenge_id") != challenge["challenge_id"]:
                raise ValueError("invalid_cloud_status")
            if result["status"] == "revoked" and result["issue_number"] > (state.issue_number or 0):
                state.grant = None
                state.issue_number = result["issue_number"]
                state.payload_sha256 = "0" * 64
            return
        raw = json.dumps(envelope).encode()
        previous = (licensing.GrantWatermark(state.issue_number, state.payload_sha256)
                    if state.issue_number is not None else None)
        grant = licensing.verify_grant(raw, trusted_keys={"cloud-license-1": cloud.license_key},
                                       instance_id=instance_id, instance_public_key=public,
                                       now=datetime.now(UTC), previous=previous)
        state.grant = raw
        state.issue_number = grant.watermark.issue_number
        state.payload_sha256 = grant.watermark.payload_sha256


async def poll(engine):
    while True:
        if CONFIG.is_file():
            try:
                await asyncio.to_thread(refresh, engine)
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, SQLAlchemyError) as exc:
                LOG.warning("Cloud license refresh failed (%s); using local license policy", type(exc).__name__)
        await asyncio.sleep(300)


def configure():
    data = json.load(sys.stdin)
    cloud = connection(data)
    keys = cloud.request("/v1/keys")
    if keys != {"cloud-license-1": encoded(cloud.license_key), "cloud-release-1": encoded(cloud.release_key)}:
        raise SystemExit("Cloud keys do not match the pinned keys")
    if not PRIVATE_KEY.exists():
        with NamedTemporaryFile(dir=DIRECTORY, delete=False) as temporary:
            generated = Path(temporary.name)
            try:
                generated.write_bytes(run("genpkey", "-algorithm", "ED25519"))
                PRIVATE_KEY.hardlink_to(generated)
            except FileExistsError:
                pass
            finally:
                generated.unlink(missing_ok=True)
    with NamedTemporaryFile(mode="w", dir=DIRECTORY, delete=False) as temporary:
        json.dump(data, temporary)
    Path(temporary.name).replace(CONFIG)


if __name__ == "__main__":
    configure()
