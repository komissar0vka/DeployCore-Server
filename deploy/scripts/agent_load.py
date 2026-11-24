"""Exercise authenticated simulated agents on a disposable CI stack."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from statistics import median
from time import monotonic
from uuid import uuid4
from urllib.error import HTTPError
from urllib.request import Request, HTTPSHandler, ProxyHandler, build_opener
import json
import os
import secrets
import subprocess
import threading


def exercise_load(check, sql, compose, base, context, count, report):
    if count not in {100, 500, 1000} or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("Load checks require an isolated GitHub Actions matrix job")

    agents = [(str(uuid4()), secrets.token_urlsafe(32), f"LOAD-{i:04}") for i in range(count)]
    enrollment_id, job_id = str(uuid4()), str(uuid4())
    token_hash = sha256(secrets.token_bytes(32)).hexdigest()
    records = ",".join(f"('{id_}'::uuid,'{sha256(token.encode()).hexdigest()}','{hostname}')"
                       for id_, token, hostname in agents)
    fixture_sql = f"""
      BEGIN;
      CREATE TEMP TABLE load_fixture(id uuid, hash text, hostname text) ON COMMIT DROP;
      INSERT INTO load_fixture VALUES {records};
      INSERT INTO enrollment_tokens(id, token_hash, label, max_uses, uses, expires_at, created_by)
        SELECT '{enrollment_id}', '{token_hash}', 'Isolated load fixture', 1, 1, now(), id
        FROM users WHERE username='admin';
      INSERT INTO devices(id, hostname, fqdn, network_name, domain_joined, ips, os_version, agent_version,
                          uptime_seconds, last_seen_at)
        SELECT id, hostname, hostname, 'WORKGROUP', false, '[]', 'Windows', '0.3.8', 60, now() FROM load_fixture;
      INSERT INTO agents(device_id, credential_hash, enrollment_id, issued_at)
        SELECT id, hash, '{enrollment_id}', now() FROM load_fixture;
      INSERT INTO deployment_jobs(id, version_id, operation, created_by, request_id)
        SELECT '{job_id}', r.version_id, 'install', u.id, '{job_id}'
        FROM users u CROSS JOIN (SELECT version_id FROM package_detection_rules LIMIT 1) r WHERE u.username='admin';
      INSERT INTO deployment_targets(id, job_id, device_id, state, cancel_requested)
        SELECT gen_random_uuid(), '{job_id}', id, 'queued', false FROM load_fixture;
      COMMIT;
    """
    subprocess.run([*compose, "exec", "-T", "db", "psql", "-U", "deploycore", "-d", "deploycore",
                    "-v", "ON_ERROR_STOP=1"], input=fixture_sql, text=True, check=True, stdout=subprocess.DEVNULL)

    percentiles = {}
    samples = []
    sample_error = []
    stop = threading.Event()

    def postgres():
        return json.loads(subprocess.check_output([
            *compose, "exec", "-T", "db", "psql", "-U", "deploycore", "-d", "deploycore", "-Atc",
            """SELECT json_build_object('transactions',xact_commit+xact_rollback,'blocks_read',blks_read,
            'blocks_cache_hit',blks_hit,'rows_inserted',tup_inserted,'rows_updated',tup_updated,
            'temporary_bytes',temp_bytes,'deadlocks',deadlocks) FROM pg_stat_database WHERE datname=current_database()""",
        ], text=True))

    def sample():
        try:
            ids = subprocess.check_output([*compose, "ps", "-q"], text=True).split()
            while not stop.is_set():
                rows = subprocess.check_output(["docker", "stats", "--no-stream", "--format", "{{json .}}", *ids],
                                               text=True, timeout=15).splitlines()
                samples.append([json.loads(row) for row in rows])
                stop.wait(1)
        except (OSError, subprocess.SubprocessError) as exc:
            sample_error.append(str(exc))

    def request(agent, endpoint, *, data=None, expected=200):
        id_, token, _ = agent
        start = monotonic()
        _, result, _ = check(f"/agent/{id_}/{endpoint}", {expected}, method="POST", data=data, origin=None,
                             extra={"Authorization": f"Bearer {token}"})
        return result, (monotonic() - start) * 1000

    def heartbeat(agent):
        _, _, hostname = agent
        data = dict(hostname=hostname, fqdn=hostname, network_name="WORKGROUP", domain_joined=False, ips=[],
                    os_version="Windows", agent_version="0.3.8", uptime_seconds=61)
        return request(agent, "heartbeat", data=data)[1]

    def deployment(agent):
        start = monotonic()
        assignment = request(agent, "jobs/poll")[0]["assignment"]
        assert assignment and assignment["mode"] == "transport_only"
        path = "jobs/" + assignment["target_id"]
        attempt = {"attempt_id": assignment["attempt_id"]}
        request(agent, path + "/ack", data=attempt)
        request(agent, path + "/result", data={**attempt, "outcome": "not_executed"})
        return (monotonic() - start) * 1000

    def batch(name, operation):
        start = monotonic()
        with ThreadPoolExecutor(max_workers=32) as pool:
            times = sorted(pool.map(operation, agents))
        elapsed = monotonic() - start
        percentiles[name] = dict(p50_ms=round(median(times), 2), p95_ms=round(times[int(0.95*len(times))-1], 2),
                                 max_ms=round(times[-1], 2), operations_per_second=round(count/elapsed, 2))

    before = postgres()
    sampler = threading.Thread(target=sample)
    sampler.start()
    try:
        batch("parallel_heartbeat", heartbeat)
        batch("queue_delivery_and_result", deployment)
        subprocess.run([*compose, "stop", "server"], check=True, stdout=subprocess.DEVNULL)
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
        unavailable = Request(base + "/api/health/ready")
        try:
            with opener.open(unavailable, timeout=10):
                raise AssertionError("API remained available with Server stopped")
        except HTTPError as error:
            with error:
                assert error.code in (502, 504), error.code
        subprocess.run([*compose, "up", "-d", "--no-build", "--no-deps", "--wait", "--wait-timeout", "90", "server"],
                       check=True, stdout=subprocess.DEVNULL)
        batch("post_restart_heartbeat", heartbeat)
    finally:
        stop.set()
        sampler.join()
    sql(f"""
      DO $$ BEGIN
      IF (SELECT count(*) FROM deployment_targets WHERE job_id='{job_id}' AND state='not_executed') <> {count}
      THEN RAISE EXCEPTION 'Unexpected load fixture outcome'; END IF; END $$;
    """)
    after = postgres()
    assert samples and not sample_error, sample_error
    results = dict(simulated_agents=count, concurrency=32, profile=percentiles, docker_samples=samples,
                   postgres_delta={key: after[key]-before[key] for key in before})
    Path(report).write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({key: value for key, value in results.items() if key != "docker_samples"}))
