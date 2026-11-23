"""Exercise quota and local grants with disposable devices and keys."""
import base64
import concurrent.futures
import hashlib
import json
import secrets
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4


def clear_managed_fixture_devices(check, admin):
    active = check("/devices?management_state=managed&limit=100", {200}, **admin)[1]
    for row in active["items"]:
        check(f'/devices/{row["id"]}/retire', {204}, method="POST", **admin)


def exercise_license(check, login, compose, admin):
    operator_cookie, operator_csrf, _ = login("operator")
    operator = {"cookie": operator_cookie, "csrf": operator_csrf}
    initial = check("/licenses", {200}, **operator)[1]
    assert (initial["status"], initial["limit"], initial["managed"]) == ("free", 5, 0)
    check("/licenses", {401})
    request = check("/enrollment-tokens", {201}, method="POST",
                    data={"label": "License fixture", "max_uses": 8}, **operator)[1]
    heartbeat = {"hostname": "FREE-FIXTURE", "ips": [], "domain_joined": False,
                 "os_version": "Windows", "agent_version": "0.3.4", "uptime_seconds": 60}
    fixtures = [(str(uuid4()), secrets.token_urlsafe(32)) for _ in range(6)]

    def enroll(fixture, expected, token=request["token"]):
        device_id, credential = fixture
        return check("/agent/enroll", expected, method="POST", origin=None, data={
            "installation_id": device_id, "credential": credential, "enrollment_token": token, "heartbeat": heartbeat,
        })

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda fixture: enroll(fixture, {200, 409}), fixtures))
    assert sorted(result[0] for result in results) == [200] * 5 + [409]
    accepted = [fixture for fixture, result in zip(fixtures, results) if result[0] == 200]
    refused = next(fixture for fixture, result in zip(fixtures, results) if result[0] == 409)
    rejected = next(result[1] for result in results if result[0] == 409)
    assert rejected["detail"] == "license_limit_reached"
    enroll(accepted[0], {200})
    device_id, old_credential = accepted[0]
    snapshot = {"hardware": {"os": {"version": "Windows", "build": "26100", "architecture": "amd64"},
                            "cpus": [{"model": "Fixture CPU", "cores": 2, "threads": 2}], "ram_bytes": 1024, "disks": [], "interfaces": []},
                "software": [{"name": "License fixture software", "version": "1", "publisher": "Fixture"}]}
    check(f"/agent/{device_id}/inventory", {204}, method="PUT", data=snapshot, origin=None,
          extra={"Authorization": "Bearer " + old_credential})
    check(f"/devices/{device_id}/agent", {204}, method="DELETE", **operator)
    assert check("/licenses", {200}, **admin)[1]["managed"] == 5
    check(f"/devices/{device_id}/retire", {403}, method="POST", **operator)
    check(f"/devices/{device_id}/retire", {403}, method="POST", cookie=admin["cookie"])
    check(f"/devices/{device_id}/retire", {204}, method="POST", **admin)
    check(f"/devices/{device_id}/retire", {204}, method="POST", **admin)
    retained = check(f"/devices/{device_id}", {200}, **operator)[1]
    assert retained["device"]["management_state"] == "retired" and retained["software"] == snapshot["software"]
    check(f"/agent/{device_id}/heartbeat", {401}, method="POST", data=heartbeat, origin=None,
          extra={"Authorization": "Bearer " + old_credential})
    check("/enrollment-tokens", {409}, method="POST", data={"label": "Retired", "device_id": device_id}, **operator)
    enroll(refused, {200})
    check(f"/devices/{device_id}/resume", {409}, method="POST", **admin)

    def encode(value):
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    with TemporaryDirectory() as directory:
        private = Path(directory) / "issuer.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)], check=True)
        issuer = subprocess.check_output(["openssl", "pkey", "-in", str(private), "-pubout", "-outform", "DER"])[-32:]
        key = secrets.token_bytes(32)
        trust = Path(directory) / "trust.json"
        trust.write_text(json.dumps({"instance_public_key": encode(key), "issuer_keys": {"smoke": encode(issuer)}}))
        subprocess.run([*compose, "cp", str(trust), "server:/tmp/deploycore-license-smoke-trust.json"], check=True,
                       stdout=subprocess.DEVNULL)
        now = datetime.now(UTC)
        claims = {"license_id": str(uuid4()), "activation_id": str(uuid4()), "instance_id": initial["instance_id"],
                  "instance_key_sha256": hashlib.sha256(key).hexdigest(), "edition": "business", "device_limit": 8,
                  "features": ["inventory"], "issue_number": 2, "issued_at": (now - timedelta(hours=1)).isoformat(),
                  "not_before": (now - timedelta(minutes=10)).isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(),
                  "grace_until": (now + timedelta(hours=2)).isoformat()}

        def sign(fields):
            payload = json.dumps(fields).encode()
            message = Path(directory) / "message"
            message.write_bytes(b"DeployCore-license-v1\x00smoke\x00" + payload)
            signature = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-inkey", str(private),
                                                  "-rawin", "-in", str(message)])
            return {"version": 1, "kid": "smoke", "payload": encode(payload), "signature": encode(signature)}

        grant = sign(claims)
        check("/licenses/import", {403}, method="POST", data=grant, **operator)
        check("/licenses/import", {403}, method="POST", data=grant, cookie=admin["cookie"])
        tampered = {**grant, "payload": encode(json.dumps({**claims, "device_limit": 99}).encode())}
        assert check("/licenses/import", {422}, method="POST", data=tampered, **admin)[1]["detail"] == "invalid_license_signature"
        for _ in range(2):
            view = check("/licenses/import", {200}, method="POST", data=grant, **admin)[1]
            assert (view["edition"], view["limit"], view["managed"]) == ("business", 8, 5)
        stale = sign({**claims, "issue_number": 1})
        assert check("/licenses/import", {422}, method="POST", data=stale, **admin)[1]["detail"] == "license_issue_regression"
        check(f"/devices/{device_id}/resume", {204}, method="POST", **admin)
        assert check("/licenses", {200}, **admin)[1]["managed"] == 6
        recovery = check("/enrollment-tokens", {201}, method="POST",
                         data={"label": "Resumed fixture", "device_id": device_id}, **operator)[1]
        enroll((device_id, secrets.token_urlsafe(32)), {200}, recovery["token"])
        subprocess.run([*compose, "restart", "server"], check=True, stdout=subprocess.DEVNULL)
        subprocess.run([*compose, "up", "-d", "--no-build", "--wait", "--wait-timeout", "90"], check=True,
                       stdout=subprocess.DEVNULL)
        assert check("/licenses", {200}, **admin)[1]["limit"] == 8
    imports = [event for event in check("/audit", {200}, **admin)[1] if event["action"] == "license_imported"]
    assert len(imports) == 1
    clear_managed_fixture_devices(check, admin)
    print("Licensing: six concurrent enrollments, Free capacity, recovery, privilege gates and signed import passed")
