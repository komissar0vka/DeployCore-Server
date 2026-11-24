"""Exercise agent APIs against the isolated DeployCore stack."""
import concurrent.futures
import hashlib
import io
import json
import secrets
import subprocess
import uuid
from zipfile import ZipFile


def exercise_devices(check, login, sql, compose, admin_cookie, admin_csrf, password):
    operator_cookie, operator_csrf, _ = login("operator")
    operator = {"cookie": operator_cookie, "csrf": operator_csrf}
    admin = {"cookie": admin_cookie, "csrf": admin_csrf}
    check("/users", {201}, method="POST", data={"username": "viewer", "password": password, "role": "viewer"}, **admin)
    viewer_cookie, viewer_csrf, _ = login("viewer")
    viewer = {"cookie": viewer_cookie, "csrf": viewer_csrf}

    def issue(label, **options):
        _, issued, _ = check("/enrollment-tokens", {201}, method="POST", data={"label": label, **options}, **operator)
        return issued["token"], issued["enrollment"]["id"]

    def enroll(device_id, token, credential, expected, beat=None):
        return check("/agent/enroll", expected, method="POST", data={
            "installation_id": device_id, "enrollment_token": token, "credential": credential,
            "heartbeat": heartbeat if beat is None else beat,
        }, origin=None)

    def agent_call(device_id, endpoint, credential, data, expected, method="POST"):
        return check(f"/agent/{device_id}/{endpoint}", expected, method=method, data=data,
                     origin=None, extra={"Authorization": f"Bearer {credential}"})

    device_id = str(uuid.uuid4())
    credential = secrets.token_urlsafe(32)
    heartbeat = {
        "hostname": "WIN-SMOKE", "fqdn": "WIN-SMOKE.example.invalid",
        "network_name": "WORKGROUP", "domain_joined": False, "ips": ["192.0.2.4", "2001:db8::1"],
        "os_version": "Windows 10.0.26100", "agent_version": "0.3.0", "uptime_seconds": 120,
    }
    check("/devices", {401})
    check("/devices/summary", {401})
    assert check("/devices/summary", {200}, **viewer)[1] == {
        "total": 0, "online": 0, "offline": 0, "versions": {}, "events": [], "errors": [],
    }
    check("/enrollment-tokens", {403}, **viewer)
    check("/enrollment-tokens", {403}, method="POST", data={"label": "blocked"}, **viewer)
    check("/enrollment-tokens", {403}, method="POST", data={"label": "missing CSRF"}, cookie=operator_cookie)
    issued, token_id = issue("First registration")
    _, listed, _ = check("/enrollment-tokens", {200}, **operator)
    assert all(issued not in str(item) and hashlib.sha256(issued.encode()).hexdigest() not in str(item) for item in listed)
    for _ in range(2):
        _, result, _ = enroll(device_id, issued, credential, {200})
        assert result["device_id"] == device_id and result["heartbeat_seconds"] == 45
    check(f"/enrollment-tokens/{token_id}", {204}, method="DELETE", **operator)
    enroll(device_id, issued, credential, {403})
    _, result, _ = agent_call(device_id, "heartbeat", credential, heartbeat, {200})

    extra, _ = issue("Matching hostname", max_uses=2)
    enroll(device_id, extra, secrets.token_urlsafe(32), {409})
    other_id = str(uuid.uuid4())
    enroll(other_id, extra, secrets.token_urlsafe(32), {200})
    _, result, _ = check("/devices?q=WIN-SMOKE", {200}, **viewer)
    assert sorted(item["id"] for item in result["items"]) == sorted([device_id, other_id])
    assert check("/devices?q=192.0.2.4", {200}, **viewer)[1]["total"] == 2
    assert check("/devices?q=%25", {200}, **viewer)[1]["total"] == 0

    expired, _ = issue("Expiry test")
    sql("UPDATE enrollment_tokens SET expires_at = now() - interval '1 second' WHERE label = 'Expiry test';")
    enroll(str(uuid.uuid4()), expired, secrets.token_urlsafe(32), {403})

    competing_token, _ = issue("Concurrent quota")
    quota_heartbeat = {**heartbeat, "hostname": "WIN-QUOTA", "fqdn": "quota.example.invalid"}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(
            lambda _: enroll(str(uuid.uuid4()), competing_token, secrets.token_urlsafe(32), {200, 403}, quota_heartbeat)[0],
            range(2),
        ))
    assert sorted(statuses) == [200, 403]
    assert len(check("/devices", {200}, **viewer)[1]["items"]) == 3
    group_fields = {"name": "Test site", "device_ids": [device_id, other_id]}
    check("/device-groups", {403}, method="POST", data=group_fields, **viewer)
    group = check("/device-groups", {201}, method="POST", data=group_fields, **operator)[1]
    group_path = "/device-groups/" + group["id"]
    assert {member["id"] for member in check("/device-groups", {200}, **viewer)[1][0]["devices"]} == {device_id, other_id}
    check("/device-groups", {409}, method="POST", data=group_fields, **operator)
    renamed = check(group_path, {200}, method="PUT", **operator, data={
        "name": "Test site renamed", "device_ids": [device_id],
    })[1]
    assert [member["id"] for member in renamed["devices"]] == [device_id]
    check(group_path, {204}, method="DELETE", **operator)
    assert check("/device-groups", {200}, **viewer)[1] == []
    check("/devices?sort=unsupported", {422}, **viewer)
    check("/devices?direction=invalid", {422}, **viewer)
    asc = check("/devices?sort=hostname&direction=asc&limit=1", {200}, **viewer)[1]
    desc = check("/devices?sort=hostname&direction=desc&limit=1", {200}, **viewer)[1]
    assert asc["total"] == desc["total"] == 3
    assert asc["items"][0]["hostname"] == "WIN-QUOTA" and desc["items"][0]["hostname"] == "WIN-SMOKE"
    home = check("/devices/summary", {200}, **viewer)[1]
    assert (home["total"], home["online"], home["offline"], home["versions"]) == (3, 3, 0, {"0.3.0": 3})
    assert len(home["events"]) == 3 and not home["errors"]
    for _ in range(2):
        agent_call(device_id, "issues", credential, {"action": "inventory_failed"}, {204})
    assert [item["action"] for item in check("/devices/summary", {200}, **viewer)[1]["errors"]] == ["inventory_failed"]
    export = f"/devices/{device_id}/diagnostics/export"
    check(export, {403}, method="POST", **viewer)
    check(export, {403}, method="POST", cookie=operator_cookie)
    _, archive, headers = check(export, {200}, method="POST", binary=True, **operator)
    assert headers["Content-Type"] == "application/zip"
    with ZipFile(io.BytesIO(archive)) as payload:
        content = payload.read("agent-summary.json")
        summary = json.loads(content)
    assert summary["online"] and summary["agent_version"] == heartbeat["agent_version"]
    assert any(event["action"] == "inventory_failed" for event in summary["events"])
    assert credential.encode() not in content and heartbeat["hostname"].encode() not in content
    agent_call(device_id, "issues", credential, {"action": "arbitrary_error"}, {422})
    agent_call(device_id, "heartbeat", secrets.token_urlsafe(32), heartbeat, {401})
    agent_call(device_id, "heartbeat", credential, {**heartbeat, "ips": ["invalid"]}, {422})
    agent_call(device_id, "heartbeat", credential, {**heartbeat, "last_seen_at": "2099-01-01"}, {422})

    hardware = {
        "os": {"version": "Windows 10.0.26100", "build": "26100", "architecture": "amd64"},
        "cpus": [{"model": "Test CPU", "cores": 4, "threads": 8}], "ram_bytes": 17179869184,
        "disks": [{"letter": "C:", "size_bytes": 50000, "free_bytes": 20000}],
        "interfaces": [{"name": "Ethernet", "ips": ["192.0.2.4"]}],
    }
    software = {"name": "Example Program", "version": "1.0", "publisher": "Example"}
    snapshot = {"hardware": hardware, "software": [software, software]}
    for _ in range(2):
        agent_call(device_id, "inventory", credential, snapshot, {204}, method="PUT")
    agent_call(device_id, "inventory", credential, {**snapshot, "software": [software] * 2001}, {422}, method="PUT")
    _, detail, _ = check(f"/devices/{device_id}", {200}, **viewer)
    saved = detail["inventory"]["hardware"]
    assert saved["os"] == hardware["os"] and saved["cpus"] == hardware["cpus"]
    assert saved["manufacturer"] == saved["model"] == ""  # Legacy agent snapshot
    updated = {**hardware, "manufacturer": "Example", "model": "PC",
               "disks": [{**hardware["disks"][0], "filesystem": "NTFS", "label": "System"}],
               "interfaces": [{**hardware["interfaces"][0], "mac": "00:11:22:33:44:55"}]}
    assert saved["disks"] == [{**hardware["disks"][0], "filesystem": "", "label": ""}]
    assert saved["interfaces"] == [{**hardware["interfaces"][0], "mac": ""}]
    assert detail["software"] == [software]
    assert [entry["action"] for entry in detail["events"]].count("inventory_updated") == 1

    agent_call(device_id, "inventory", credential, {**snapshot, "hardware": updated}, {204}, method="PUT")
    assert check(f"/devices/{device_id}", {200}, **viewer)[1]["inventory"]["hardware"] == updated

    sql("UPDATE devices SET last_seen_at = now() - interval '4 minutes' WHERE hostname = 'WIN-SMOKE';")
    assert check("/devices?q=WIN-SMOKE&status=offline", {200}, **viewer)[1]["total"] == 2
    agent_call(device_id, "heartbeat", credential, {**heartbeat, "network_name": "corp.example", "domain_joined": True}, {200})
    assert check("/devices?q=WIN-SMOKE&status=online", {200}, **viewer)[1]["total"] == 1
    assert check("/devices?q=WIN-SMOKE&sort=status&direction=desc&limit=1", {200}, **viewer)[1]["items"][0]["online"]
    assert "reconnected" in {item["action"] for item in check(f"/devices/{device_id}", {200}, **viewer)[1]["events"]}
    check(f"/devices/{device_id}/agent", {403}, method="DELETE", **viewer)
    check(f"/devices/{device_id}", {403}, method="DELETE", **viewer)
    check(f"/devices/{device_id}/agent", {204}, method="DELETE", **operator)
    assert check(f"/devices/{device_id}", {200}, **viewer)[1]["device"]["agent_revoked"]
    agent_call(device_id, "heartbeat", credential, heartbeat, {401})
    agent_call(device_id, "inventory", credential, snapshot, {401}, method="PUT")

    recovery, _ = issue("Recovery", device_id=device_id)
    stale_recovery, _ = issue("New recovery", device_id=device_id)
    replacement = secrets.token_urlsafe(32)
    enroll(device_id, recovery, replacement, {403})
    enroll(other_id, stale_recovery, replacement, {409})
    enroll(device_id, stale_recovery, replacement, {200})
    enroll(device_id, stale_recovery, replacement, {200})
    enroll(device_id, stale_recovery, secrets.token_urlsafe(32), {409})
    agent_call(device_id, "heartbeat", credential, heartbeat, {401})
    agent_call(device_id, "heartbeat", replacement, heartbeat, {200})

    subprocess.run([*compose, "stop", "db"], check=True)
    subprocess.run([*compose, "up", "-d", "--wait", "--wait-timeout", "90"], check=True)
    assert check(f"/devices/{device_id}", {200}, **viewer)[1]["software"] == [software]
    agent_call(device_id, "heartbeat", replacement, heartbeat, {200})

    check(f"/devices/{device_id}", {204}, method="DELETE", **operator)
    check(f"/devices/{device_id}", {404}, **viewer)
    agent_call(device_id, "heartbeat", replacement, heartbeat, {401})
    assert any(event["action"] == "device_deleted" and event["details"]["device_id"] == device_id
               for event in check("/audit", {200}, **admin)[1])
    sql("""
DO $$ BEGIN
  IF EXISTS (SELECT FROM enrollment_tokens WHERE token_hash !~ '^[a-f0-9]{64}$')
     OR EXISTS (SELECT FROM agents WHERE credential_hash !~ '^[a-f0-9]{64}$') THEN
    RAISE EXCEPTION 'Credential storage must contain hashes only';
  END IF;
END $$;
""")
    print("Agent enrollment, quotas, expiry, recovery, roles, heartbeat, inventory, events and PostgreSQL persistence passed")
