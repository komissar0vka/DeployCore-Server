"""Download large inert artifacts through live authenticated execution routes in CI."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from statistics import median
import subprocess
from time import monotonic
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
from uuid import uuid4


def transfer_profile(check, sql, compose, base, context, agents, mib):
    if mib not in (100, 1024):
        raise ValueError("Unsupported artifact fixture size")
    size = mib * 1024 * 1024
    storage_key, job_id = str(uuid4()), str(uuid4())
    writer = """
import hashlib, sys
from pathlib import Path
from deploycore.package_storage import storage_root
block=b'Z' * (1024*1024)
digest=hashlib.sha256()
with (storage_root() / sys.argv[1]).open('xb') as output:
    for _ in range(int(sys.argv[2])):
        output.write(block)
        digest.update(block)
print(digest.hexdigest())
"""
    expected = subprocess.check_output(
        [*compose, "exec", "-T", "server", "python", "-c", writer, storage_key, str(mib)], text=True,
    ).strip()
    assert len(expected) == 64 and all(x in "0123456789abcdef" for x in expected)
    selected = agents[:8]
    devices = ",".join(f"'{id_}'::uuid" for id_, _, _ in selected)
    sql(f"""
      BEGIN;
      CREATE TEMP TABLE transfer_version ON COMMIT DROP AS
        SELECT v.id,v.package_id FROM software_versions v
        JOIN package_artifacts a ON a.version_id=v.id
        JOIN package_detection_rules r ON r.version_id=v.id
        WHERE v.installer IN ('msi','exe') AND r.kind NOT IN ('all','any','portable_file') LIMIT 1;
      UPDATE software_packages SET archived_at=NULL WHERE id IN (SELECT package_id FROM transfer_version);
      UPDATE package_artifacts SET storage_key='{storage_key}', size_bytes={size}, sha256='{expected}', signature='unverified'
        WHERE version_id IN (SELECT id FROM transfer_version);
      UPDATE software_versions SET approved_at=now(), approved_sha256='{expected}', approval_kind='manual',
        approved_by=(SELECT id FROM users WHERE username='admin') WHERE id IN (SELECT id FROM transfer_version);
      INSERT INTO deployment_jobs(id,version_id,operation,created_by,request_id,artifact_sha256,mode)
        SELECT '{job_id}',v.id,'install',u.id,'{job_id}','{expected}','execute_v1'
        FROM transfer_version v CROSS JOIN users u WHERE u.username='admin';
      INSERT INTO deployment_targets(id,job_id,device_id,state,cancel_requested)
        SELECT gen_random_uuid(),'{job_id}',id,'queued',false FROM devices WHERE id IN ({devices});
      COMMIT;
    """)

    def download(agent):
        id_, token, _ = agent
        headers = {"Authorization": f"Bearer {token}", "X-DeployCore-Capabilities": "execute_v1"}
        prefix = f"/agent/{id_}/jobs/"
        _, result, _ = check(prefix + "poll", {200}, method="POST", origin=None, extra=headers)
        assignment = result["assignment"]
        body = {"attempt_id": assignment["attempt_id"]}
        path = prefix + assignment["target_id"]
        check(path + "/ack", {200}, method="POST", data=body, origin=None, extra=headers)
        check(path + "/heartbeat", {200}, method="POST", data={**body, "stage": "downloading"}, origin=None, extra=headers)
        request = Request(base + "/api/v1" + path + "/artifact?attempt_id=" + body["attempt_id"], headers=headers)
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
        start = monotonic()
        received = 0
        digest = hashlib.sha256()
        with opener.open(request, timeout=60) as response:
            assert response.status == 200 and response.headers["X-DeployCore-SHA256"] == expected
            assert int(response.headers["Content-Length"]) == size
            while chunk := response.read(1024*1024):
                digest.update(chunk)
                received += len(chunk)
        assert received == size and digest.hexdigest() == expected
        return monotonic() - start

    start = monotonic()
    with ThreadPoolExecutor(max_workers=len(selected)) as pool:
        times = list(pool.map(download, selected))
    elapsed = monotonic() - start
    disk = subprocess.check_output([*compose, "exec", "-T", "server", "df", "-k",
                                    "/var/lib/deploycore/packages"], text=True).splitlines()[-1].split()
    return dict(artifact_bytes=size, simultaneous_downloads=len(times), bytes_received=size*len(times),
                aggregate_mib_per_second=round(size*len(times)/elapsed/(1024*1024), 2),
                median_seconds=round(median(times), 3), max_seconds=round(max(times), 3),
                package_filesystem_available_kib=int(disk[3]))


def verify_low_space_rejection(compose, base, context, admin):
    """Use an artificial reserve far above available space, without filling the runner."""
    from urllib.error import HTTPError
    from time import sleep
    import os

    reserve_mib = 1_048_576
    env = {**os.environ, "DEPLOYCORE_PACKAGE_RESERVE_MIB": str(reserve_mib)}
    subprocess.run([*compose, "up", "-d", "--no-build", "--no-deps", "--wait", "--wait-timeout", "90", "server"],
                   env=env, check=True, stdout=subprocess.DEVNULL)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    request = Request(base + "/api/v1/packages/intakes?filename=low-space.exe", data=b"bounded probe", method="POST",
                      headers={"Origin": base, "Cookie": admin["cookie"], "X-CSRF-Token": admin["csrf"],
                               "Content-Type": "application/octet-stream", "X-DeployCore-Request": "1"})
    for _ in range(8):
        try:
            with opener.open(request, timeout=10):
                raise AssertionError("Catalog accepted an upload below the storage reserve")
        except HTTPError as error:
            with error:
                if error.code == 502:
                    sleep(1)
                    continue
                assert error.code == 507, (error.code, error.read()[:100])
                assert json.load(error)["detail"] == "package_storage_full"
                remaining = subprocess.check_output([
                    *compose, "exec", "-T", "server", "python", "-c",
                    "from deploycore.package_storage import storage_root; print(len(list(storage_root().glob('.part-*'))))",
                ], text=True).strip()
                assert remaining == "0"
                return {"http_status": 507, "reserve_mib": reserve_mib, "partial_uploads": int(remaining)}
    raise RuntimeError("Catalog did not respond after test container restart")
