"""Exercise execution authorization and transitions. Never execute a Windows payload."""
import hashlib
import secrets
import uuid
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


def exercise_execution(check, login, sql, base, context, version_id, admin):
    operator_cookie, csrf, _ = login("operator")
    operator = {"cookie": operator_cookie, "csrf": csrf}
    viewer_cookie, vc, _ = login("viewer")
    viewer = {"cookie": viewer_cookie, "csrf": vc}
    devices = [str(uuid.uuid4()) for _ in range(3)]
    credentials = [secrets.token_urlsafe(32) for _ in devices]
    token = check("/enrollment-tokens", {201}, method="POST", data={"label": "Execution smoke", "max_uses": 3}, **operator)[1]["token"]
    for i, device in enumerate(devices):
        check("/agent/enroll", {200}, method="POST", origin=None, data={
            "installation_id": device, "enrollment_token": token, "credential": credentials[i],
            "heartbeat": {"hostname": f"EXEC-{i+1}", "ips": [], "domain_joined": False, "os_version": "Windows",
                          "agent_version": "0.3.3" if i == 2 else "0.3.4", "uptime_seconds": 60},
        })

    def agent(i, path, method="POST", expected=200, data=None, capable=True):
        headers = {"Authorization": f"Bearer {credentials[i]}"}
        if capable:
            headers["X-DeployCore-Capabilities"] = "execute_v1"
        return check(f"/agent/{devices[i]}/jobs/{path}", {expected}, method=method, origin=None, extra=headers, data=data)[1]

    def job_payload(device, operation="install"):
        return {"version_id": version_id, "device_ids": [device], "operation": operation,
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
