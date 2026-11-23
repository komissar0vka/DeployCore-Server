from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from deploycore import license_api, licensing, main


@pytest.mark.parametrize("managed, permitted", [(4, True), (5, False), (7, False)])
def test_free_quota_blocks_only_new_slots(monkeypatch, managed, permitted):
    monkeypatch.setattr(license_api, "managed_count", lambda _: managed)
    state = SimpleNamespace(grant=None, instance_id=uuid4())
    if permitted:
        assert license_api.ensure_slot(None, state) is None
    else:
        with pytest.raises(HTTPException, match="license_limit_reached"):
            license_api.ensure_slot(None, state)


def test_unverifiable_grant_reports_explicit_fallback(monkeypatch):
    state = SimpleNamespace(grant=b"stored", instance_id=uuid4())
    def expired(*_):
        raise licensing.LicenseValidationError("license_outside_validity")

    monkeypatch.setattr(license_api, "verify", expired)
    overview = license_api.effective(state, 9)
    assert (overview.edition, overview.status, overview.limit, overview.managed) == ("free", "fallback", 5, 9)
    assert state.grant == b"stored"


def test_oversized_import_is_rejected_before_parsing():
    response = TestClient(main.app).post("/api/v1/licenses/import", content=b"x" * (24 * 1024 + 1))
    assert response.status_code == 413
    assert response.json() == {"detail": "body_too_large"}
