"""Bounded system diagnostics for the current Server process."""
from collections import deque
from datetime import UTC, datetime
from threading import Lock
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request

from .device_schemas import Wire
from .models import User
from .security import Db, Permission, require

router = APIRouter(prefix="/api/v1", tags=["System"])
SystemAdmin = Annotated[User, Depends(require(Permission.MANAGE_SYSTEM))]
EventKind = Literal["started", "http_error", "cloud_check_failed"]


class RuntimeEvent(Wire):
    time: datetime
    kind: EventKind
    status: int | None = None
    route: str | None = None


class RuntimeEvents:
    def __init__(self):
        self._events: deque[RuntimeEvent] = deque(maxlen=200)
        self._lock = Lock()

    def record(self, kind: EventKind, status: int | None = None, route: str | None = None):
        with self._lock:
            self._events.append(RuntimeEvent(time=datetime.now(UTC), kind=kind, status=status, route=route))

    def recent(self) -> list[RuntimeEvent]:
        with self._lock:
            return list(reversed(self._events))


@router.get("/system/events")
def system_events(request: Request, db: Db, actor: SystemAdmin) -> list[RuntimeEvent]:
    result = request.app.state.runtime_events.recent()
    db.commit()
    return result
