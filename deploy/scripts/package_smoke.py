"""Exercise catalog RBAC, binary transfer and signing using the isolated stack."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler

from deployment_smoke import exercise_deployments
from execution_smoke import exercise_execution


def exercise_packages(check, login, sql, compose, base, context, admin):
    operator_cookie, csrf, _ = login("operator")
    operator = {"cookie": operator_cookie, "csrf": csrf}
    viewer_cookie, viewer_csrf, _ = login("viewer")
    viewer = {"cookie": viewer_cookie, "csrf": viewer_csrf}
    fields = {"name": "Catalog test", "publisher": "Test CA", "description": "Isolated fixture"}

    def create_version(path, version, installer, architecture="x64", detection=None):
        return check(path + "/versions", {201}, method="POST", **operator, data={
            "version": version, "architecture": architecture, "installer": installer,
            "detection": detection or {"kind": "registry_software", "display_name": "Catalog test", "version": version},
            "install_args": ["/quiet"] if installer == "exe" else ["/qn"],
            "uninstall_args": ["/remove"] if version in {"1.0", "2.0"} else None, "success_codes": [0, 3010], "min_windows_build": 19045,
            "timeout_seconds": 300, "reboot_required": True,
        })[1]

    def request(url, method="GET", body=None, headers=None, expected=200):
        req = Request(base + url, data=body, method=method, headers=headers or {})
        try:
            response = opener.open(req, timeout=60)
        except HTTPError as exc:
            response = exc
        with response:
            data = response.read()
            assert response.status == expected, (method, url, response.status, data[:500])
            return data, response.headers

    def upload(url, name, payload, expected, identity=operator):
        if isinstance(payload, bytes):
            size = len(payload)
            chunks = (payload[i:i + 65536] for i in range(0, size, 65536))
        else:
            size = payload.stat().st_size
            chunks = iter_file(payload)
        headers = {"Cookie": identity["cookie"], "X-CSRF-Token": identity["csrf"],
                   "X-DeployCore-Request": "1", "Origin": base, "Content-Type": "application/octet-stream"}
        # Exercise both fixed length (large fixture) and chunked forwarding (small probes).
        if not isinstance(payload, bytes):
            headers["Content-Length"] = str(size)
        data, _ = request("/api/v1" + url + "?" + urlencode({"filename": name}), "PUT",
                          body=chunks, headers=headers, expected=expected)
        return json.loads(data)

    def iter_file(path):
        with path.open("rb") as file:
            while chunk := file.read(65536):
                yield chunk

    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    check("/packages", {401})
    assert check("/packages", {200}, **viewer)[1]["total"] == 0
    check("/packages", {403}, method="POST", data=fields, **viewer)
    check("/packages", {403}, method="POST", data=fields, cookie=operator_cookie)
    item = check("/packages", {201}, method="POST", data=fields, **operator)[1]
    path = "/packages/" + item["id"]
    check("/packages", {409}, method="POST", data=fields, **operator)
    assert check("/packages?q=Test%20CA&sort=publisher&direction=desc", {200}, **viewer)[1]["total"] == 1
    check("/packages?sort=updated", {422}, **viewer)
    assert check(path, {200}, **viewer)[1]["versions"] == []
    check(path, {403}, method="PATCH", **viewer, data={"description": "blocked"})
    check(path, {422}, method="PATCH", **operator, data={"name": None})
    assert check(path, {200}, method="PATCH", **operator, data={"description": "Updated"})[1]["description"] == "Updated"
    check(path + "/versions", {403}, method="POST", **viewer, data={})
    check(path + "/versions", {422}, method="POST", **operator, data={})
    version = create_version(path, "1.0", "exe")
    version_path = f'{path}/versions/{version["id"]}'
    artifact_url = version_path + "/artifact"
    check(version_path + "/approve", {403}, method="POST", **viewer)
    check(version_path + "/approve", {409}, method="POST", **operator)
    assert upload(artifact_url, "test.exe", b"not-pe", 422)["detail"] == "package_invalid_format"
    upload(artifact_url, "test.exe", b"not-pe", 403, viewer)
    request("/api/v1" + artifact_url, headers={"Cookie": viewer_cookie}, expected=403)
    request("/api/v1" + artifact_url, headers={"Cookie": operator_cookie}, expected=404)
    with tempfile.TemporaryDirectory() as scratch:
        directory = Path(scratch)
        for extension in ("exe", "msi"):
            asset, _ = request("/assets/agent/deploycore-agent." + extension)
            (directory / ("fixture." + extension)).write_bytes(asset)
        exe = directory / "fixture.exe"
        assert exe.stat().st_size > 2 * 1024 * 1024
        record = upload(artifact_url, "fixture.exe", exe, 201)
        assert record["signature"] == "unverified"
        assert record["sha256"] == hashlib.sha256(exe.read_bytes()).hexdigest()
        assert upload(artifact_url, "fixture.exe", b"retry", 409)["detail"] == "package_artifact_immutable"
        request("/api/v1" + artifact_url, headers={"Cookie": viewer_cookie}, expected=403)
        downloaded, headers = request("/api/v1" + artifact_url, headers={"Cookie": operator_cookie})
        assert downloaded == exe.read_bytes() and headers["X-DeployCore-SHA256"] == record["sha256"]
        check(version_path + "/approve", {409}, method="POST", **operator)
        manual_path = version_path + "/approve-manual"
        confirmation = {"sha256": record["sha256"].upper()}
        check(manual_path, {403}, method="POST", data=confirmation, **viewer)
        check(manual_path, {403}, method="POST", data=confirmation, **operator)
        check(manual_path, {422}, method="POST", data={"sha256": "not-a-hash"}, **admin)
        check(manual_path, {409}, method="POST", data={"sha256": "0" * 64}, **admin)
        manual = check(manual_path, {200}, method="POST", data=confirmation, **admin)[1]
        assert manual["approval_kind"] == "manual" and manual["approved_sha256"] == record["sha256"]
        assert manual["artifact"]["signature"] == "unverified"
        assert check(manual_path, {200}, method="POST", data=confirmation, **admin)[1] == manual

        wrong_arch = create_version(path, "1.0", "exe", "x86")
        wrong_path = f'{path}/versions/{wrong_arch["id"]}/artifact'
        assert upload(wrong_path, "fixture.exe", exe, 422)["detail"] == "package_architecture_mismatch"
        assert upload(wrong_path, "oversize.exe", b"x" * (16 * 1024 * 1024 + 1), 413)["detail"] == "package_too_large"

        msi = create_version(path, "1.1", "msi")
        msi_path = f'{path}/versions/{msi["id"]}/artifact'
        assert upload(msi_path, "fixture.msi", directory / "fixture.msi", 201)["signature"] == "unverified"

        subprocess.run([*compose, "cp", str(exe), "server:/tmp/catalog-test.exe"], check=True, stdout=subprocess.DEVNULL)
        subprocess.run([*compose, "cp", str(directory / "fixture.msi"), "server:/tmp/catalog-test.msi"], check=True, stdout=subprocess.DEVNULL)
        subprocess.run([*compose, "exec", "-T", "server", "sh", "-ec", """
            umask 077
            openssl req -x509 -nodes -newkey rsa:2048 -days 1 -subj '/CN=DeployCore Catalog Test'                 -addext 'keyUsage=critical,digitalSignature,keyCertSign'                 -addext 'extendedKeyUsage=codeSigning'                 -keyout /tmp/catalog-smoke.key -out /tmp/catalog-smoke-ca.pem 2>/dev/null
            osslsigncode sign -certs /tmp/catalog-smoke-ca.pem -key /tmp/catalog-smoke.key                 -in /tmp/catalog-test.exe -out /tmp/catalog-signed.exe
            osslsigncode sign -certs /tmp/catalog-smoke-ca.pem -key /tmp/catalog-smoke.key \
                -in /tmp/catalog-test.msi -out /tmp/catalog-signed.msi
        """], check=True, stdout=subprocess.DEVNULL)
        signed_path = directory / "signed.exe"
        subprocess.run([*compose, "cp", "server:/tmp/catalog-signed.exe", str(signed_path)], check=True, stdout=subprocess.DEVNULL)
        signed = create_version(path, "2.0", "exe")
        signed_version_path = f'{path}/versions/{signed["id"]}'
        assert upload(signed_version_path + "/artifact", "signed.exe", signed_path, 201)["signature"] == "verified"
        approval = check(signed_version_path + "/approve", {200}, method="POST", **operator)[1]
        assert approval["approved_at"] and approval["approved_by"] and approval["approval_kind"] == "authenticode"
        assert check(signed_version_path + "/approve", {200}, method="POST", **operator)[1] == approval
        assert upload(signed_version_path + "/artifact", "signed.exe", b"replace", 409)["detail"] == "package_artifact_immutable"

        leaf = {"kind": "file_exists", "path": r"C:\Program Files\DeployCoreSmoke\marker.exe"}
        group = {"kind": "any", "schema_version": 1, "rules": [
            leaf, {**leaf, "path": r"C:\Program Files\DeployCoreSmoke\other.exe"},
        ]}
        composite = create_version(path, "3.0", "exe", detection=group)
        composite_path = f'{path}/versions/{composite["id"]}'
        assert composite["detection"] == group
        assert upload(composite_path + "/artifact", "signed.exe", signed_path, 201)["signature"] == "verified"
        check(composite_path + "/approve", {200}, method="POST", **operator)

        signed_msi_path = directory / "signed.msi"
        subprocess.run([*compose, "cp", "server:/tmp/catalog-signed.msi", str(signed_msi_path)], check=True, stdout=subprocess.DEVNULL)
        signed_msi = create_version(path, "2.1", "msi")
        assert upload(f'{path}/versions/{signed_msi["id"]}/artifact', "signed.msi", signed_msi_path, 201)["signature"] == "verified"

        tampered_path = directory / "tampered.exe"
        altered = bytearray(signed_path.read_bytes())
        altered[4096] ^= 1
        tampered_path.write_bytes(altered)
        tampered = create_version(path, "2.2", "exe")
        bad_version_path = f'{path}/versions/{tampered["id"]}'
        assert upload(bad_version_path + "/artifact", "tampered.exe", tampered_path, 201)["signature"] == "unverified"
        check(bad_version_path + "/approve", {409}, method="POST", **operator)
    subprocess.run([*compose, "up", "-d", "--no-build", "--force-recreate", "--no-deps", "--wait", "server"], check=True)
    stored = {entry["id"]: entry for entry in check(path, {200}, **viewer)[1]["versions"]}
    assert stored[signed["id"]]["approved_at"] == approval["approved_at"]
    downloaded, _ = request("/api/v1" + artifact_url, headers={"Cookie": operator_cookie})
    assert hashlib.sha256(downloaded).hexdigest() == record["sha256"]
    exercise_deployments(check, login, sql, compose, signed["id"], admin)
    assert stored[version["id"]] == manual
    exercise_execution(check, login, sql, base, context, version["id"], composite["id"], group, admin)
    sql(f"""
        DO $$
        BEGIN
            IF (SELECT count(*) FROM audit_events
                WHERE action = 'package_version_approved' AND actor_id = '{manual["approved_by"]}'
                  AND details->>'version_id' = '{version["id"]}'
                  AND details->>'approval_kind' = 'manual'
                  AND details->>'sha256' = '{record["sha256"]}'
                  AND details->>'approved_at' IS NOT NULL) <> 1 THEN
                RAISE EXCEPTION 'Expected one manual approval audit event';
            END IF;
        END;
        $$;
    """)
    sql(f"UPDATE package_artifacts SET sha256 = repeat('0', 64) WHERE version_id = '{version["id"]}';")
    check(manual_path, {409}, method="POST", data=confirmation, **admin)
    sql(f"UPDATE package_artifacts SET sha256 = '{record["sha256"]}' WHERE version_id = '{version["id"]}';")
    invalidated = {entry["id"]: entry for entry in check(path, {200}, **viewer)[1]["versions"]}[version["id"]]
    assert all(invalidated[key] is None for key in ("approved_at", "approved_by", "approval_kind", "approved_sha256"))
    check(path, {403}, method="DELETE", **viewer)
    check(path, {204}, method="DELETE", **operator)
    check(path, {404}, **viewer)
    assert check("/packages", {200}, **viewer)[1]["total"] == 0
    actions = {event["action"] for event in check("/audit", {200}, **admin)[1]}
    assert actions >= {"package_created", "package_changed", "package_archived", "package_version_created",
                       "package_artifact_uploaded", "package_version_approved",
                       "detection_preview_requested", "detection_preview_completed"}
    print("Catalog API, RBAC, streaming EXE/MSI, SHA-256, signing, approval, immutability and persistence passed")
