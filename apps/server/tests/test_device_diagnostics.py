import json
from datetime import UTC, datetime, timedelta
from io import BytesIO
from types import SimpleNamespace
from zipfile import ZipFile

from deploycore.device_api import diagnostic_archive


def test_diagnostics_exports_only_normalized_connection_state_and_events():
    now = datetime.now(UTC)
    device = SimpleNamespace(agent_version="0.3.9", management_state="managed", last_seen_at=now,
                             hostname="secret-domain-host", ips=["192.0.2.123"])
    agent = SimpleNamespace(revoked_at=None, credential_hash="secret-token-hash")
    good = SimpleNamespace(action="inventory_failed", created_at=now, details={"password": "sensitive"})
    invalid = SimpleNamespace(action="secret-raw-input", created_at=now)
    data = diagnostic_archive(device, agent, [good, invalid], now, now - timedelta(minutes=3))
    with ZipFile(BytesIO(data)) as archive:
        assert archive.namelist() == ["agent-summary.json"]
        raw = archive.read("agent-summary.json")
    assert b"secret" not in raw and b"sensitive" not in raw and b"192.0.2.123" not in raw
    result = json.loads(raw)
    assert result["online"] is True
    assert result["agent_version"] == "0.3.9"
    assert [event["action"] for event in result["events"]] == ["inventory_failed"]
