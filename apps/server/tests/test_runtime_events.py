from deploycore.runtime_events import RuntimeEvents


def test_runtime_events_are_bounded_and_newest_first():
    events = RuntimeEvents()
    events.record("started")
    for _ in range(199):
        events.record("cloud_check_failed")
    events.record("http_error", status=503, route="/api/health/ready")
    rows = events.recent()
    assert len(rows) == 200
    assert rows[0].status == 503 and rows[0].route == "/api/health/ready"
    assert all(row.kind != "started" for row in rows)
