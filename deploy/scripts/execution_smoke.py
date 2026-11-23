"""Exercise execution authorization and transitions. Never execute a Windows payload."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import secrets
import uuid
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


def exercise_execution(check, login, sql, base, context, version_id, composite_id, group, admin):
    operator_cookie, csrf, _ = login("operator")
    operator = {"cookie": operator_cookie, "csrf": csrf}
    viewer_cookie, vc, _ = login("viewer")
    viewer = {"cookie": viewer_cookie, "csrf": vc}
    devices = [str(uuid.uuid4()) for _ in range(4)]
    credentials = [secrets.token_urlsafe(32) for _ in devices]
    token = check("/enrollment-tokens", {201}, method="POST", data={"label": "Execution smoke", "max_uses": 4}, **operator)[1]["token"]
    for i, device in enumerate(devices):
        check("/agent/enroll", {200}, method="POST", origin=None, data={
            "installation_id": device, "enrollment_token": token, "credential": credentials[i],
            "heartbeat": {"hostname": f"EXEC-{i+1}", "ips": [], "domain_joined": False, "os_version": "Windows",
                          "agent_version": ("0.3.4", "0.3.4", "0.3.3", "0.3.5")[i], "uptime_seconds": 60},
        })

    def agent(i, path, method="POST", expected=200, data=None, capable=True, extended=True):
        headers = {"Authorization": f"Bearer {credentials[i]}"}
        if capable:
            headers["X-DeployCore-Capabilities"] = "execute_v1, detection_v1" if i == 3 and extended else "execute_v1"
        return check(f"/agent/{devices[i]}/jobs/{path}", {expected}, method=method, origin=None, extra=headers, data=data)[1]

    def job_payload(device, operation="install", version=version_id):
        return {"version_id": version, "device_ids": [device], "operation": operation,
                "mode": "execute_v1", "request_id": str(uuid.uuid4())}

    def fetch(i, target, attempt, expected, *, headers=None):
        url = f"{base}/api/v1/agent/{devices[i]}/jobs/{target}/artifact?attempt_id={attempt}"
        request = Request(url, headers={"Authorization": f"Bearer {credentials[i]}", **(headers or {})})
        try:
            response = opener.open(request, timeout=20)
        except HTTPError as exc:
            response = exc
        with response:
            assert response.status == expected, response.status
            return response.read(), response.headers

    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    check("/deployments", {403}, method="POST", data=job_payload(devices[0]), **viewer)
    check("/deployments", {403}, method="POST", data=job_payload(devices[0], "uninstall"), **operator)
    check("/deployments", {422}, method="POST", data=job_payload(devices[2]), **operator)
    created = check("/deployments", {201}, method="POST", data=job_payload(devices[0]), **operator)[1]
    path = f'/deployments/{created["id"]}'
    assert agent(0, "poll", capable=False)["assignment"] is None
    assert agent(2, "poll")["assignment"] is None
    issued = agent(0, "poll")["assignment"]
    assert issued["mode"] == "execute_v1"
    target, attempt = issued["target_id"], issued["attempt_id"]
    proof = {"attempt_id": attempt}
    fetch(0, target, attempt, 409)
    agent(0, f"{target}/ack", data=proof)
    fetch(1, target, attempt, 404)
    fetch(0, target, str(uuid.uuid4()), 409)
    suffix = "?attempt_id=" + attempt
    sql(f"UPDATE deployment_jobs SET artifact_sha256 = repeat('0', 64) WHERE id = '{created["id"]}';")
    agent(0, target + "/manifest" + suffix, method="GET", expected=409)
    fetch(0, target, attempt, 409)
    agent(0, target + "/start", data=proof, expected=409)
    sql(f"""
        UPDATE deployment_jobs SET artifact_sha256 = package_artifacts.sha256
        FROM package_artifacts
        WHERE deployment_jobs.id = '{created["id"]}' AND package_artifacts.version_id = deployment_jobs.version_id;
    """)
    manifest = agent(0, target + "/manifest" + suffix, method="GET")
    image, headers = fetch(0, target, attempt, 200)
    assert headers["X-DeployCore-SHA256"] == manifest["sha256"] == hashlib.sha256(image).hexdigest()
    partial, _ = fetch(0, target, attempt, 206, headers={"Range": "bytes=0-63"})
    assert partial == image[:64]
    agent(0, target + "/result", data={**proof, "outcome": "succeeded", "exit_code": 0}, expected=409)
    sql(f"UPDATE deployment_attempts SET lease_expires_at=clock_timestamp()-interval '2 seconds' WHERE id='{attempt}';")
    fetch(0, target, attempt, 409)
    agent(0, target + "/heartbeat", data={**proof, "stage": "downloading"})
    agent(0, target + "/start", data=proof)
    agent(0, target + "/start", data=proof, expected=409)
    fetch(0, target, attempt, 409)
    assert agent(0, "poll")["recovery_required"]
    agent(0, target + "/heartbeat", data={**proof, "stage": "verifying"})
    result = {**proof, "outcome": "unknown", "diagnostic": "interrupted"}
    assert agent(0, target + "/result", data=result) == result
    assert agent(0, target + "/result", data=result) == result
    assert agent(0, "poll")["recovery_required"]
    resolve = f"{path}/targets/{target}/resolve"
    check(resolve, {403}, method="POST", data={"verified_stopped": True}, **operator)
    assert check(resolve, {200}, method="POST", data={"verified_stopped": True}, **admin)[1]["counts"] == {"failed": 1}
    new = check(f"{path}/targets/{target}/retry", {201}, method="POST",
                data={"request_id": str(uuid.uuid4())}, **admin)[1]
    again = agent(0, "poll")["assignment"]
    assert again["target_id"] != target and again["attempt_id"] != attempt
    agent(0, again["target_id"] + "/ack", data={"attempt_id": again["attempt_id"]})
    agent(0, again["target_id"] + "/result", data={"attempt_id": again["attempt_id"], "outcome": "already_installed"})
    assert check('/deployments/' + new["id"], {200}, **viewer)[1]["counts"] == {"already_installed": 1}

    removed = check("/deployments", {201}, method="POST", data=job_payload(devices[1], "uninstall"), **admin)[1]
    next_lease = agent(1, "poll")["assignment"]
    agent(1, next_lease["target_id"] + "/ack", data={"attempt_id": next_lease["attempt_id"]})
    check(f"/devices/{devices[1]}/agent", {204}, method="DELETE", **operator)
    fetch(1, next_lease["target_id"], next_lease["attempt_id"], 401)
    agent(1, next_lease["target_id"] + "/start", data={"attempt_id": next_lease["attempt_id"]}, expected=401)
    assert removed["operation"] == "uninstall"
    print("Execution API: scoped TLS download, Range, old agents, RBAC, start fence, recovery, retry and revocation passed")


    def preview_agent(i, suffix, expected=200, data=None, extended=True):
        headers = {"Authorization": f"Bearer {credentials[i]}"}
        if extended:
            headers["X-DeployCore-Capabilities"] = "execute_v1, detection_v1"
        return check(f"/agent/{devices[i]}/detection-previews/{suffix}", {expected},
                     method="POST", data=data, origin=None, extra=headers)[1]

    preview_input = {"device_id": devices[3], "version_id": composite_id}
    check("/detection-previews", {403}, method="POST", data=preview_input, **viewer)
    check("/detection-previews", {403}, method="POST", data=preview_input, cookie=operator_cookie)
    check("/detection-previews", {409}, method="POST", data={**preview_input, "device_id": devices[0]}, **operator)
    preview = check("/detection-previews", {201}, method="POST", data=preview_input, **operator)[1]
    assert preview["status"] == "queued"
    check("/detection-previews", {429}, method="POST", data=preview_input, **operator)
    preview_path = f'/detection-previews/{preview["id"]}'
    check(preview_path, {403}, **viewer)
    preview_agent(3, "poll", 409, extended=False)
    preview_agent(0, "poll", 409)
    preview_agent(3, f'{preview["id"]}/result', 409, {"observation": "installed"})
    assert preview_agent(3, "poll") == {"task": {"id": preview["id"], "rule": group}}
    assert preview_agent(3, "poll")["task"] is None
    preview_agent(3, f'{preview["id"]}/result', 204, {"observation": "unknown"})
    preview_agent(3, f'{preview["id"]}/result', 204, {"observation": "unknown"})
    preview_agent(3, f'{preview["id"]}/result', 409, {"observation": "installed"})
    assert check(preview_path, {200}, **operator)[1]["observation"] == "unknown"

    check("/deployments", {422}, method="POST", data=job_payload(devices[0], version=composite_id), **operator)
    reboot_job = check("/deployments", {201}, method="POST", data=job_payload(devices[3], version=composite_id), **operator)[1]
    assert agent(3, "poll", extended=False)["assignment"] is None
    reboot_lease = agent(3, "poll")["assignment"]
    target, attempt = reboot_lease["target_id"], reboot_lease["attempt_id"]
    proof = {"attempt_id": attempt}
    agent(3, f"{target}/ack", data=proof)
    assert agent(3, f"{target}/manifest?attempt_id={attempt}", method="GET")["detection"] == group
    agent(3, f"{target}/manifest?attempt_id={attempt}", method="GET", expected=409, extended=False)
    agent(3, f"{target}/start", data=proof, expected=409, extended=False)
    agent(3, f"{target}/start", data=proof)
    pending = {**proof, "outcome": "reboot_required", "exit_code": 3010,
               "process_started": True, "reboot_pending": True}
    assert agent(3, f"{target}/result", data=pending) == pending
    detail = check(f'/deployments/{reboot_job["id"]}', {200}, **viewer)[1]
    assert detail["counts"] == {"awaiting_reboot": 1}
    assert detail["targets"][0]["process_started"] is True
    assert agent(3, "poll")["recovery_required"]
    assert agent(3, f"{target}/result", data=pending) == pending
    agent(3, f"{target}/start", expected=409, data=proof)
    reboot_result = {**proof, "detection": "installed"}
    for _ in range(2):
        agent(3, f"{target}/reboot-result", expected=204, data=reboot_result)
    assert agent(3, f"{target}/result", data=pending) == pending
    detail = check(f'/deployments/{reboot_job["id"]}', {200}, **viewer)[1]
    assert detail["counts"] == {"succeeded": 1}
    assert detail["targets"][0]["exit_code"] == 3010
    assert detail["targets"][0]["detection"] is None
    assert detail["targets"][0]["reboot_detection"] == "installed"
    expired_job = check("/deployments", {201}, method="POST", data=job_payload(devices[3]), **operator)[1]
    expired = agent(3, "poll")["assignment"]
    target, attempt = expired["target_id"], expired["attempt_id"]
    proof = {"attempt_id": attempt}
    agent(3, f"{target}/ack", data=proof)
    agent(3, f"{target}/start", data=proof)
    agent(3, f"{target}/result", data={**pending, **proof})
    sql(f"UPDATE deployment_attempts SET reboot_deadline=clock_timestamp()-interval '1 second' WHERE id='{attempt}';")
    scope = f"q=Catalog&scope=problem&operation=install&device_id={devices[3]}&direction=asc&limit=1"
    problem = check("/deployments?" + scope, {200}, **viewer)[1]
    assert problem["total"] == 1 and problem["problem"] >= 1 and problem["items"][0]["id"] == expired_job["id"]
    assert check("/deployments?q=%25", {200}, **viewer)[1]["total"] == 0
    check("/deployments?scope=unsupported", {422}, **viewer)
    log = check(f'/deployments/{expired_job["id"]}/events?target_id={target}', {200}, **viewer)[1]
    assert log and all(item["target_id"] == target and item["attempt_number"] == 1 for item in log)
    revoked = check("/devices?q=EXEC&status=revoked&agent_version=0.3.4", {200}, **viewer)[1]
    assert [item["id"] for item in revoked["items"]] == [devices[1]]
    assert agent(3, "poll")["recovery_required"]
    agent(3, f"{target}/reboot-result", expected=204, data={**proof, "detection": "installed"})
    expired_view = check(f'/deployments/{expired_job["id"]}', {200}, **viewer)[1]
    assert expired_view["counts"] == {"unknown": 1}
    assert expired_view["targets"][0]["reboot_diagnostic"] == "reboot_timeout"
    stranded = check("/deployments", {201}, method="POST", data=job_payload(devices[0]), **operator)[1]
    active = agent(0, "poll")["assignment"]
    proof = {"attempt_id": active["attempt_id"]}
    agent(0, f'{active["target_id"]}/ack', data=proof)
    agent(0, f'{active["target_id"]}/start', data=proof)
    queued = check("/deployments", {201}, method="POST", data=job_payload(devices[0]), **operator)[1]
    with ThreadPoolExecutor(max_workers=2) as pool:
        race = pool.submit(check, "/deployments", {201, 422}, method="POST",
                           data=job_payload(devices[0]), **operator)
        check(f"/devices/{devices[0]}", {204}, method="DELETE", **operator)
        status, racing_job, _ = race.result()
    if status == 201:
        assert check(f'/deployments/{racing_job["id"]}', {200}, **viewer)[1]["counts"] == {"cancelled": 1}
    assert check(f'/deployments/{queued["id"]}', {200}, **viewer)[1]["counts"] == {"cancelled": 1}
    removed_detail = check(f'/deployments/{stranded["id"]}', {200}, **viewer)[1]
    assert removed_detail["counts"] == {"unknown": 1}
    assert removed_detail["targets"][0]["diagnostic"] == "device_removed"
    agent(0, "poll", expected=401)
    print("Detection API: preview RBAC, CSRF, rate limit, scoped capability, composite lease and idempotent reboot result passed")
