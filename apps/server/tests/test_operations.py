import json
from uuid import uuid4

import pytest
from pydantic import TypeAdapter, ValidationError

from deploycore import operations_api


def test_host_operations_are_disabled_without_mailbox(monkeypatch, tmp_path):
    monkeypatch.setattr(operations_api, "ROOT", tmp_path)
    assert not operations_api.view().available


def test_mailbox_exposes_progress_and_backup_metadata(monkeypatch, tmp_path):
    monkeypatch.setattr(operations_api, "ROOT", tmp_path)
    (tmp_path / "inbox").mkdir()
    outbox = tmp_path / "outbox"
    outbox.mkdir()
    (outbox / "heartbeat").touch()
    id = uuid4()
    (outbox / "status.json").write_text(json.dumps({"id": str(id), "action": "backup", "stage": "completed"}))
    (outbox / f"{id}.tar.gz").write_bytes(b"test backup")
    result = operations_api.view()
    assert result.available and result.status.stage == "completed"
    assert result.backups[0].id == id and result.backups[0].bytes == 11


def test_update_accepts_only_channels_and_versions():
    adapter = TypeAdapter(operations_api.UpdateRequest)
    assert adapter.validate_python({"action":"update","channel":"beta","version":"1.0.0-beta.4"}).version == "1.0.0-beta.4"
    with pytest.raises(ValidationError):
        adapter.validate_python({"action":"update","channel":"beta","version":"../../update.sh"})
