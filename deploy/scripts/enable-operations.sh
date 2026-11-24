#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
[[ $EUID == 0 ]] || { echo 'Requires root' >&2; exit 1; }
[[ $PWD =~ ^[A-Za-z0-9_./-]+$ ]] || { echo 'Unsupported installation directory' >&2; exit 1; }
install -d -m 700 deploy/.operations
install -d -m 700 -o 10001 -g 10001 deploy/.operations/inbox
install -d -m 755 deploy/.operations/outbox
python3 - <<'PY'
import json
from pathlib import Path
root = Path("deploy/.operations").resolve()
config = {"services": {"server": {"volumes": [
    {"type": "bind", "source": str(root / "inbox"), "target": "/run/deploycore-ops/inbox"},
    {"type": "bind", "source": str(root / "outbox"), "target": "/run/deploycore-ops/outbox", "read_only": True},
]}}}
(root / "compose.json").write_text(json.dumps(config))
PY
cat > /etc/systemd/system/deploycore-operations.service <<UNIT
[Unit]
Description=DeployCore host operations
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $PWD/deploy/scripts/operations.py
WorkingDirectory=$PWD
Restart=on-failure
Environment=PYTHONUNBUFFERED=1
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now deploycore-operations.service
compose=(docker compose --env-file deploy/.env -f deploy/compose.yaml -f deploy/.operations/compose.json)
if [[ -f deploy/.updater/active.json ]]; then
  compose+=(-f deploy/.updater/active.json)
fi
"${compose[@]}" up -d --no-build --wait server web
