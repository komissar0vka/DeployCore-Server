"""Verify the configured MSI and its enrollment without starting Windows."""
import json
import subprocess
import secrets
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


def exercise_agent_package(check, login, compose, base, context, expected_origin, certificate):
    viewer_cookie, viewer_csrf, _ = login("viewer")
    operator_cookie, csrf, _ = login("operator")
    headers = {"Origin": base, "X-DeployCore-Request": "1", "Content-Type": "application/json",
               "Cookie": operator_cookie, "X-CSRF-Token": csrf}
    ca = Path(certificate).read_text().strip()
    request = {"label": "Managed MSI fixture", "ttl_minutes": 15, "max_uses": 1, "ca": ca}
    check("/agent-packages", {403}, method="POST", data=request, cookie=viewer_cookie, csrf=viewer_csrf)
    check("/agent-packages", {403}, method="POST", data=request, cookie=operator_cookie)
    check("/agent-packages", {422}, method="POST", data={**request, "ca": "not PEM"}, cookie=operator_cookie, csrf=csrf)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    with opener.open(Request(base + "/api/v1/agent-packages", json.dumps(request).encode(), headers), timeout=60) as response:
        assert response.status == 200 and response.headers["Cache-Control"] == "no-store"
        assert "deploycore-managed-agent.msi" in response.headers["Content-Disposition"]
        payload = response.read()
    assert payload.startswith(bytes.fromhex("d0cf11e0a1b11ae1"))
    with TemporaryDirectory() as directory:
        artifact = Path(directory) / "managed.msi"
        artifact.write_bytes(payload)
        remote = subprocess.check_output([*compose, "exec", "-T", "server", "mktemp", "-d"], text=True).strip()
        try:
            subprocess.run([*compose, "cp", str(artifact), f"server:{remote}/managed.msi"], check=True,
                           stdout=subprocess.DEVNULL)
            config = subprocess.check_output([*compose, "exec", "-T", "server", "sh", "-ec", r"""
                directory="$1"
                msiinfo export "$directory/managed.msi" ServiceInstall | grep -q service-msi
                msiinfo export "$directory/managed.msi" ServiceControl | grep -q DeployCoreAgent
                msiinfo export "$directory/managed.msi" LaunchCondition | grep -q EXISTINGDEPLOYCORESERVICE
                msiextract -C "$directory" "$directory/managed.msi" >/dev/null
                find "$directory" -name enrollment.json -exec cat '{}' \;
            """, "sh", remote])
        finally:
            subprocess.run([*compose, "exec", "-T", "server", "rm", "-r", remote], check=True)
    config = json.loads(config)
    assert config["server"].rstrip("/") == expected_origin
    assert len(config["token"]) == 43 and config["ca"] == ca
    device = "1b288fcc-89ec-4599-8ccc-c73c3ce4f912"
    registration = {
        "installation_id": device, "enrollment_token": config["token"], "credential": secrets.token_urlsafe(32),
        "heartbeat": {"hostname": "MSI-FIXTURE", "ips": [], "domain_joined": False,
                      "os_version": "Windows", "agent_version": "0.3.7", "uptime_seconds": 60},
    }
    assert check("/agent/enroll", {200}, method="POST", data=registration, origin=None)[1]["device_id"] == device
    second = {**registration, "installation_id": "664048e3-3625-49ec-98dc-0a2f174d381e"}
    assert check("/agent/enroll", {403}, method="POST", data=second, origin=None)[1]["detail"] == "enrollment_invalid"
    print("Configured MSI: RBAC, CSRF, service tables, server address and token quota passed")
