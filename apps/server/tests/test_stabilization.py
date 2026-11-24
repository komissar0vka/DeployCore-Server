from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from deploycore import execution_api, job_api, package_api
from deploycore.job_schemas import Result


def test_device_deletion_cancels_unstarted_and_preserves_uncertain_execution(monkeypatch):
    items = [SimpleNamespace(id=uuid4(), job_id=uuid4(), state=state) for state in ("queued", "leased", "running")]
    attempts = [None, SimpleNamespace(started_at=None, finished_at=None), SimpleNamespace(started_at=object())]
    db = Mock()
    db.scalars.return_value = items
    monkeypatch.setattr(job_api, "last_attempt", Mock(side_effect=attempts))
    monkeypatch.setattr(job_api, "clock", lambda db: "now")
    event = Mock()
    monkeypatch.setattr(job_api, "event", event)
    job_api.cancel_deleted_device_targets(db, uuid4())
    assert [item.state for item in items] == ["cancelled", "cancelled", "unknown"]
    assert [attempt.outcome for attempt in attempts[1:]] == ["cancelled", "unknown"]
    assert event.call_count == 3


def test_closed_attempt_does_not_acknowledge_unaccepted_result(monkeypatch):
    attempt = SimpleNamespace(finished_at=True, diagnostic="operator_resolved", acknowledged_at=True,
                              exit_code=None, output_bytes=None, detection=None, process_started=None,
                              outcome="unknown", reboot_deadline=None)
    monkeypatch.setattr(job_api, "attempt_for", lambda *args: (SimpleNamespace(job_id=uuid4()), attempt))
    db = Mock()
    db.get_one.return_value.mode = "execute_v1"
    request = SimpleNamespace(headers={"x-deploycore-capabilities": "closed_result_v1"})
    result = Result(attempt_id=uuid4(), outcome="failed")
    with pytest.raises(HTTPException) as error:
        job_api.submit_result(uuid4(), result, request, db, None)
    assert error.value.status_code == 410
    db.commit.assert_not_called()
    assert job_api.submit_result(uuid4(), result, SimpleNamespace(headers={}), db, None) == result


def test_signed_approval_rejects_changed_bytes(monkeypatch, tmp_path):
    path = tmp_path / "artifact"
    path.write_bytes(b"changed content")
    monkeypatch.setattr(package_api.storage, "artifact_path", lambda *_: path)
    for name in ("find_version", "find_package", "record_approval"):
        monkeypatch.setattr(package_api, name, Mock())
    db = Mock()
    db.get.return_value = SimpleNamespace(signature="verified", sha256="0" * 64, storage_key=None)
    with pytest.raises(HTTPException, match="package_approval_hash_mismatch"):
        package_api.approve_version(uuid4(), uuid4(), None, db, None)
    package_api.record_approval.assert_not_called()


def test_download_maps_storage_race_to_unavailable(monkeypatch):
    path = Mock()
    path.is_file.return_value = True
    path.stat.side_effect = FileNotFoundError()
    monkeypatch.setattr(execution_api, "artifact_path", lambda *_: path)
    monkeypatch.setattr(execution_api, "permitted", lambda *args: (
        None, None, None, SimpleNamespace(id=uuid4()), SimpleNamespace(storage_key=None, size_bytes=12), None, None,
    ))
    with pytest.raises(HTTPException) as error:
        execution_api.download(uuid4(), uuid4(), None, Mock(), None)
    assert error.value.status_code == 503


def test_expired_reboot_rejects_late_success_for_new_agent(monkeypatch):
    attempt = SimpleNamespace(reboot_deadline=True, reboot_finished_at=True, reboot_detection=None)
    monkeypatch.setattr(job_api, "detection_capable", lambda *args: True)
    monkeypatch.setattr(job_api, "attempt_for", lambda *args: (None, attempt))
    request = SimpleNamespace(headers={"x-deploycore-capabilities": "closed_result_v1"})
    with pytest.raises(HTTPException) as error:
        job_api.submit_reboot_result(uuid4(), job_api.wire.RebootResult(attempt_id=uuid4(), detection="installed"),
                                     request, Mock(), None)
    assert error.value.status_code == 410
