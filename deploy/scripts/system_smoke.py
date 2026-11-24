"""Exercise stage 2 against the isolated HTTPS stack created by smoke.sh."""
import concurrent.futures
import json
import os
import secrets
import ssl
import subprocess
import sys
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler

from device_smoke import exercise_devices
from license_smoke import clear_managed_fixture_devices, exercise_license
from agent_package_smoke import exercise_agent_package
from package_smoke import exercise_packages

base, certificate, *compose = sys.argv[1:]
context = ssl.create_default_context(cafile=certificate)
password = secrets.token_urlsafe(24)
wrong_password = secrets.token_urlsafe(24)
setup_token = os.environ["DEPLOYCORE_SETUP_TOKEN"]


def check(path, expected, *, method="GET", data=None, cookie="", csrf=None, origin=base, extra=None):
    headers = {"X-DeployCore-Request": "1"}
    if origin:
        headers["Origin"] = origin
    if cookie:
        headers["Cookie"] = cookie
    if csrf:
        headers["X-CSRF-Token"] = csrf
    if data is not None:
        headers["Content-Type"] = "application/json"
    headers.update(extra or {})
    request = Request(
        base + "/api/v1" + path,
        None if data is None else json.dumps(data).encode(), headers, method=method,
    )
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    try:
        response = opener.open(request, timeout=10)
    except HTTPError as error:
        response = error
    with response:
        body = response.read()
        assert response.status in expected, (method, path, response.status, body)
        assert response.headers["Cache-Control"] == "no-store"
        assert not any(secret.encode() in body for secret in (password, wrong_password, setup_token))
        return response.status, json.loads(body) if body else None, response.headers


def credentials(username, value=password):
    return {"username": username, "password": value}


def login(username):
    _, body, headers = check("/auth/login", {200}, method="POST", data=credentials(username))
    cookie = headers["Set-Cookie"]
    for attribute in ("__Host-deploycore=", "HttpOnly", "Secure", "SameSite=strict", "Path=/"):
        assert attribute in cookie
    return cookie.partition(";")[0], body["csrf_token"], body["user"]


def sql(query):
    subprocess.run(
        [*compose, "exec", "-T", "db", "psql", "-U", "deploycore", "-d", "deploycore", "-v", "ON_ERROR_STOP=1", "-c", query],
        check=True, stdout=subprocess.DEVNULL,
    )


assert not check("/setup", {200})[1]["configured"]
setup = {
    **credentials("admin"), "setup_token": setup_token,
    "organization": "Test organization", "instance_name": "Stage 2",
    "agent_url": "https://192.0.2.14:8444",
}
check("/setup", {403}, method="POST", data={**setup, "setup_token": "incorrect"})
check("/setup", {403}, method="POST", data=setup, origin="https://example.invalid")
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    results = list(pool.map(lambda _: check("/setup", {201, 409}, method="POST", data=setup)[0], range(2)))
assert sorted(results) == [201, 409]
assert check("/setup", {200})[1]["configured"]
check("/setup", {409}, method="POST", data=setup)
check("/settings", {401})
check("/auth/login", {403}, method="POST", data=credentials("admin"), origin=None)
admin_cookie, csrf, admin = login("ADMIN")
assert admin["role"] == "super_admin"
check("/system/events", {401})
assert check("/system/events", {200}, cookie=admin_cookie)[1][-1]["kind"] == "started"
assert check("/users", {200}, cookie=admin_cookie)[1] == [admin]
check(f'/users/{admin["id"]}/role', {409}, method="PATCH", cookie=admin_cookie, csrf=csrf, data={"role": "viewer"})
_, user, _ = check(
    "/users", {201}, method="POST", cookie=admin_cookie, csrf=csrf,
    data={**credentials("operator"), "role": "viewer"},
)
check("/users", {409}, method="POST", cookie=admin_cookie, csrf=csrf,
      data={**credentials("OPERATOR"), "role": "viewer"})
operator_cookie, operator_csrf, user_view = login("operator")
check("/system/events", {403}, cookie=operator_cookie)
assert user_view["role"] == "viewer"
assert check("/settings", {200}, cookie=admin_cookie)[1]["agent_url"].rstrip("/") == setup["agent_url"]
settings = {
    "organization": "Updated organization", "instance_name": "DeployCore example",
    "agent_url": "https://agent.example.invalid:8443", "heartbeat_seconds": 45, "language": "en",
}
check("/settings", {200}, cookie=operator_cookie)
check("/settings", {403}, method="PUT", cookie=operator_cookie, csrf=operator_csrf, data=settings)
check("/users", {403}, cookie=operator_cookie)
check("/audit", {403}, cookie=operator_cookie)
check("/settings", {403}, method="PUT", cookie=admin_cookie, data=settings)
check("/settings", {403}, method="PUT", cookie=admin_cookie, csrf=csrf, data=settings, origin="https://example.invalid")
check("/settings", {422}, method="PUT", cookie=admin_cookie, csrf=csrf, data={**settings, "agent_url": f"http://user:{password}@host"})
check("/settings", {422}, method="PUT", cookie=admin_cookie, csrf=csrf, data={**settings, "heartbeat_seconds": 1})
assert check("/settings", {200}, method="PUT", cookie=admin_cookie, csrf=csrf, data=settings)[1]["language"] == "en"
assert check("/setup", {200})[1]["language"] == "en"
check(f'/users/{user["id"]}/role', {200}, method="PATCH", cookie=admin_cookie, csrf=csrf, data={"role": "administrator"})
assert check("/auth/session", {200}, cookie=operator_cookie)[1]["user"]["role"] == "administrator"
check("/settings", {403}, method="PUT", cookie=operator_cookie, csrf=operator_csrf, data=settings)
check("/auth/logout", {204}, method="POST", cookie=operator_cookie, csrf=operator_csrf)
check("/auth/session", {401}, cookie=operator_cookie)

for _ in range(5):
    check("/auth/login", {401}, method="POST", data=credentials("unknown", wrong_password))
_, _, headers = check("/auth/login", {429}, method="POST", data=credentials("unknown", wrong_password))
assert int(headers["Retry-After"]) > 0
events = check("/audit", {200}, cookie=admin_cookie)[1]
assert {event["action"] for event in events} >= {
    "user_created", "setup_completed", "login_succeeded", "login_failed", "logout", "settings_changed", "role_changed",
}
assert all("account_key" not in event for event in events)

sql("""
DO $$ BEGIN
  IF EXISTS (SELECT FROM users WHERE password_hash NOT LIKE '$argon2id$%') THEN
    RAISE EXCEPTION 'Unexpected password hash format';
  END IF;
  IF EXISTS (SELECT FROM sessions WHERE token_hash !~ '^[a-f0-9]{64}$') THEN
    RAISE EXCEPTION 'Unexpected session hash format';
  END IF;
END $$;
UPDATE sessions SET last_seen_at = now() - interval '31 minutes';
""")
assert check("/auth/session", {401}, cookie=admin_cookie)[1]["detail"] == "session_expired"
admin_cookie, csrf, _ = login("admin")
sql("UPDATE sessions SET expires_at = now() - interval '1 second';")
assert check("/auth/session", {401}, cookie=admin_cookie)[1]["detail"] == "session_expired"
admin_cookie, csrf, _ = login("admin")
subprocess.run([*compose, "restart", "server"], check=True, stdout=subprocess.DEVNULL)
subprocess.run([*compose, "up", "-d", "--no-build", "--wait", "--wait-timeout", "90"], check=True, stdout=subprocess.DEVNULL)
assert check("/setup", {200})[1]["configured"]
assert check("/auth/session", {200}, cookie=admin_cookie)[1]["user"] == admin
assert check("/settings", {200}, cookie=admin_cookie)[1]["language"] == "en"
print("Setup race, migrations on restart, session security, roles, login limits, settings and audit passed")

exercise_devices(check, login, sql, compose, admin_cookie, csrf, password)

admin_auth = {"cookie": admin_cookie, "csrf": csrf}
clear_managed_fixture_devices(check, admin_auth)
exercise_license(check, login, compose, admin_auth)
exercise_packages(check, login, sql, compose, base, context, admin_auth)
exercise_agent_package(check, login, compose, base, context, settings["agent_url"], certificate)
