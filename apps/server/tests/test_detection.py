from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pydantic import TypeAdapter, ValidationError

from deploycore import job_api
from deploycore.package_schemas import Detection

LEAF = {"kind": "file_exists", "path": r"C:\Program Files\DeployCoreTest\marker.exe"}


def test_detection_accepts_legacy_and_versioned_group():
    detect = TypeAdapter(Detection)
    assert detect.validate_python(LEAF).model_dump() == LEAF
    assert detect.validate_python({"kind": "all", "rules": [LEAF, LEAF]}).schema_version == 1


@pytest.mark.parametrize("rules, version", [
    ([], 1),
    ([LEAF], 1),
    ([LEAF] * 9, 1),
    ([LEAF, LEAF], 2),
    ([LEAF, {"kind": "all", "rules": [LEAF, LEAF]}], 1),
    ([LEAF, {"kind": "file_exists", "path": r"\\host\share\file"}], 1),
])
def test_detection_rejects_unbounded_or_unsafe_rules(rules, version):
    with pytest.raises(ValidationError):
        TypeAdapter(Detection).validate_python({"kind": "any", "schema_version": version, "rules": rules})


@pytest.mark.parametrize("operation, observation, state, action", [
    ("install", "installed", "succeeded", "reboot_verified"),
    ("install", "not_installed", "failed", "detection_mismatch"),
    ("uninstall", "not_installed", "succeeded", "reboot_verified"),
    ("uninstall", "installed", "failed", "detection_mismatch"),
    ("install", "unknown", "unknown", "detection_failed"),
    ("install", None, "unknown", "reboot_timeout"),
])
def test_reboot_observation_preserves_the_original_execution(operation, observation, state, action, monkeypatch):
    event = Mock()
    monkeypatch.setattr(job_api, "event", event)
    db = Mock()
    db.get_one.return_value = SimpleNamespace(operation=operation)
    target = SimpleNamespace(job_id="job", state="awaiting_reboot")
    attempt = SimpleNamespace(outcome="reboot_required", exit_code=3010, detection="not_installed")
    now = object()
    job_api.finish_reboot(db, target, attempt, observation, now)
    assert target.state == state
    assert attempt.reboot_detection == observation
    assert attempt.reboot_finished_at is now
    assert (attempt.outcome, attempt.exit_code, attempt.detection) == ("reboot_required", 3010, "not_installed")
    event.assert_called_once_with(db, "job", action, target, attempt)
