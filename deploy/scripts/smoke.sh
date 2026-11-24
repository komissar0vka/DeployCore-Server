#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch="$(mktemp -d)"
export POSTGRES_PASSWORD="$(openssl rand -hex 32)"
export DEPLOYCORE_SETUP_TOKEN="$(openssl rand -hex 32)"
export DEPLOYCORE_PACKAGE_MAX_MIB=16
export DEPLOYCORE_ENABLE_EXECUTION=1
export DEPLOYCORE_LICENSE_TRUST=/tmp/deploycore-license-smoke-trust.json
export DEPLOYCORE_PACKAGE_CA_FILE=/tmp/catalog-smoke-ca.pem
export POSTGRES_USER=deploycore
export POSTGRES_DB=deploycore
export DEPLOYCORE_HTTPS_BIND=127.0.0.1
export DEPLOYCORE_HTTPS_PORT="${SMOKE_PORT:-18443}"
export DEPLOYCORE_TLS_DIR="$scratch"
compose=(docker compose --env-file "$root/deploy/.env.example" -f "$root/deploy/compose.yaml" -p "deploycore-smoke-$$")
base="https://localhost:$DEPLOYCORE_HTTPS_PORT"

cleanup() {
    local status=$?
    if (( status != 0 )); then
        "${compose[@]}" ps -a || true
        "${compose[@]}" logs --tail 40 || true
    fi
    "${compose[@]}" down --volumes --remove-orphans --rmi local || true
    local file
    for file in "$scratch"/*; do
        if [ -f "$file" ]; then
            rm -- "$file" || true
        fi
    done
    rmdir -- "$scratch" || true
    exit "$status"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost \
    -keyout "$scratch/privkey.pem" -out "$scratch/fullchain.pem" 2>/dev/null
request() {
    curl --silent --show-error --max-time 10 --cacert "$scratch/fullchain.pem" "$@"
}

"${compose[@]}" config --quiet
"${compose[@]}" up -d --wait --wait-timeout 90 db
test "$("${compose[@]}" exec -T db psql -U deploycore -d deploycore -Atc "SELECT to_regclass('public.alembic_version') IS NULL")" = t
"${compose[@]}" build server web
"${compose[@]}" run --rm --no-deps server python -m alembic upgrade 0002_devices
"${compose[@]}" exec -T db psql -U deploycore -d deploycore -v ON_ERROR_STOP=1 \
    -c "UPDATE installation_settings SET instance_name='Pre-catalog instance' WHERE id=1"
"${compose[@]}" run --rm --no-deps server python -m alembic upgrade 0006_manual_approval
test "$("${compose[@]}" exec -T db psql -U deploycore -d deploycore -Atc "SELECT version_num FROM alembic_version")" = '0006_manual_approval'
"${compose[@]}" run --rm --no-deps server python -m alembic upgrade 0008_local_licensing
previous_instance=$("${compose[@]}" exec -T db psql -U deploycore -d deploycore -Atc "SELECT instance_id FROM license_state WHERE id=1")
"${compose[@]}" exec -T db psql -U deploycore -d deploycore -v ON_ERROR_STOP=1 \
    -c "INSERT INTO software_packages(id,name,publisher,description,archived_at) VALUES
        ('f21540f5-7669-4cf2-83c9-dba111ac090f','Beta 3 fixture','DeployCore','Preserved catalog metadata', now())"
"${compose[@]}" up -d --no-build --wait --wait-timeout 120
test "$("${compose[@]}" exec -T db psql -U deploycore -d deploycore -Atc "SELECT instance_name FROM installation_settings WHERE id=1")" = 'Pre-catalog instance'
test "$("${compose[@]}" exec -T db psql -U deploycore -d deploycore -Atc "SELECT version_num FROM alembic_version")" = '0013_portable_packages'
test "$("${compose[@]}" exec -T db psql -U deploycore -d deploycore -Atc "SELECT instance_id FROM license_state WHERE id=1")" = "$previous_instance"
test "$("${compose[@]}" exec -T db psql -U deploycore -d deploycore -Atc "SELECT description FROM software_packages WHERE name='Beta 3 fixture' AND category=''")" = 'Preserved catalog metadata'
echo 'Upgrade through beta.3 to 0013 preserved settings, catalog data and license identity'

request --fail "$base/" > "$scratch/index.html"
grep -q '<title>DeployCore' "$scratch/index.html"
asset="$(sed -nE 's/.*src="(\/assets\/[^"]+\.js)".*/\1/p' "$scratch/index.html")"
test -n "$asset"
request --fail "$base$asset" > /dev/null
for agent_artifact in deploycore-agent.exe deploycore-agent.msi SHA256SUMS build.json; do
    request --fail "$base/assets/agent/$agent_artifact" > "$scratch/$agent_artifact"
done
(cd "$scratch" && sha256sum -c SHA256SUMS)
python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); assert data["os"] == "windows" and data["architecture"] == "amd64"' "$scratch/build.json"
request --fail "$base/api/docs" > "$scratch/swagger.html"
grep -q '/assets/swagger/swagger-ui-bundle.js' "$scratch/swagger.html"
if grep -qiE 'src="https?://|href="https?://' "$scratch/swagger.html"; then
    echo 'Swagger UI references external assets' >&2
    exit 1
fi
for swagger_asset in swagger-ui-bundle.js swagger-ui.css favicon-32x32.png; do
    request --fail "$base/assets/swagger/$swagger_asset" > /dev/null
done
request --fail "$base/api/openapi.json" > "$scratch/openapi.json"
python3 - "$root/packages/api-contract/openapi.json" "$scratch/openapi.json" <<'PY'
import json
import sys
from pathlib import Path

expected, actual = (json.loads(Path(path).read_text()) for path in sys.argv[1:])
assert expected == actual, "OpenAPI snapshot differs from the running service"
PY
test "$(request --fail "$base/api/health/live")" = '{"status":"ok"}'
test "$(request --fail "$base/api/health/ready")" = '{"status":"ok"}'
echo 'HTTPS, React assets, local Swagger UI, OpenAPI, live and ready passed'
"${compose[@]}" exec -T server python -m alembic check
"${compose[@]}" exec -T server cp /etc/ssl/certs/ca-certificates.crt /tmp/catalog-smoke-ca.pem
python3 "$root/deploy/scripts/system_smoke.py" "$base" "$scratch/fullchain.pem" "${compose[@]}"

"${compose[@]}" stop db
test "$(request -o "$scratch/ready.json" -w '%{http_code}' "$base/api/health/ready")" = 503
test "$(cat "$scratch/ready.json")" = '{"status":"unavailable"}'
test "$(request --fail "$base/api/health/live")" = '{"status":"ok"}'
"${compose[@]}" start db
for attempt in {1..30}; do
    if test "$(request "$base/api/health/ready")" = '{"status":"ok"}'; then
        echo 'Readiness failure and recovery passed'
        exit 0
    fi
    sleep 1
done
echo 'Readiness did not recover after PostgreSQL restart' >&2
exit 1
