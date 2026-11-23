import hashlib
import ipaddress
import secrets
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException, Request, Response, Security
from fastapi.security import APIKeyCookie
from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from .models import AuditEvent, LoginSession, User
from .schemas import PublicUser, Role, SessionView

COOKIE = "__Host-deploycore"
COOKIE_ATTRIBUTES = {"secure": True, "httponly": True, "samesite": "strict", "path": "/"}
IDLE_TIMEOUT = timedelta(minutes=30)
SESSION_LIFETIME = timedelta(hours=12)
LOGIN_WINDOW = timedelta(minutes=10)
PASSWORDS = PasswordHasher()
DUMMY_HASH = PASSWORDS.hash(secrets.token_urlsafe(32))
session_cookie = APIKeyCookie(name=COOKIE, scheme_name="DeployCoreSession", auto_error=False)


class Permission(StrEnum):
    READ = "read"
    MANAGE_OPERATIONS = "manage_operations"
    MANAGE_SYSTEM = "manage_system"
    MANAGE_REMOVALS = "manage_removals"


PERMISSIONS = {
    Role.SUPER_ADMIN: frozenset(Permission),
    Role.ADMINISTRATOR: frozenset({Permission.READ, Permission.MANAGE_OPERATIONS}),
    Role.VIEWER: frozenset({Permission.READ}),
}


def db_session(request: Request):
    with Session(request.app.state.database, expire_on_commit=False) as db:
        yield db


Db = Annotated[Session, Depends(db_session)]


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def source_address(request: Request) -> str | None:
    # Nginx overwrites this header; the API is private to the Compose networks.
    value = request.headers.get("x-real-ip") or (request.client.host if request.client else "")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def audit(db: Session, request: Request, action: str, *, actor=None, target=None, account_key=None, details=None):
    db.add(AuditEvent(
        action=action,
        actor_id=actor.id if actor else None,
        target_id=target.id if target else None,
        source=source_address(request),
        account_key=account_key,
        details=details or {},
    ))


def require_same_origin(request: Request) -> None:
    expected = f"https://{request.headers.get('host', '')}"
    if request.headers.get("origin") != expected or request.headers.get("x-deploycore-request") != "1":
        raise HTTPException(403, "request_origin")


def csrf_for(raw: str) -> str:
    return digest(f"csrf:{raw}")


def issue_session(db: Session, response: Response, user: User, now: datetime) -> SessionView:
    raw = secrets.token_urlsafe(32)
    db.add(LoginSession(
        token_hash=digest(raw), user_id=user.id, last_seen_at=now, expires_at=now + SESSION_LIFETIME,
    ))
    response.set_cookie(COOKIE, raw, max_age=int(SESSION_LIFETIME.total_seconds()), **COOKIE_ATTRIBUTES)
    return SessionView(
        user=PublicUser.model_validate(user), csrf_token=csrf_for(raw), expires_at=now + IDLE_TIMEOUT,
    )


def effective_expiry(session: LoginSession) -> datetime:
    return min(session.last_seen_at + IDLE_TIMEOUT, session.expires_at)


def active_session(
    request: Request, db: Db, raw: Annotated[str | None, Security(session_cookie)],
) -> tuple[User, LoginSession, str]:
    if raw is None or len(raw) != 43:
        raise HTTPException(401, "session_required")
    result = db.execute(
        select(User, LoginSession).join(LoginSession, LoginSession.user_id == User.id)
        .where(LoginSession.token_hash == digest(raw)).with_for_update(of=LoginSession)
    ).one_or_none()
    if result is None:
        raise HTTPException(401, "session_required")
    user, session = result
    now = datetime.now(UTC)
    if effective_expiry(session) <= now:
        db.delete(session)
        db.commit()
        raise HTTPException(401, "session_expired")
    csrf = csrf_for(raw)
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        require_same_origin(request)
        provided = request.headers.get("x-csrf-token", "")
        if not secrets.compare_digest(provided.encode(), csrf.encode()):
            raise HTTPException(403, "csrf_invalid")
    session.last_seen_at = now
    request.state.session_expiry = effective_expiry(session)
    return user, session, csrf


ActiveSession = Annotated[tuple[User, LoginSession, str], Depends(active_session)]


def require(permission: Permission):
    def authorized(active: ActiveSession) -> User:
        user, _, _ = active
        if permission not in PERMISSIONS[Role(user.role)]:
            raise HTTPException(403, "permission_denied")
        return user

    return authorized


def throttle_login(db: Session, request: Request, username: str) -> tuple[str, bool]:
    account_key = digest(username)
    address = source_address(request)
    for namespace, value in ((2, address or ""), (3, account_key)):
        db.execute(text("SELECT pg_advisory_xact_lock(:namespace, hashtext(:value))"),
                   {"namespace": namespace, "value": value})
    recent = select(func.count()).select_from(AuditEvent).where(
        AuditEvent.action == "login_failed",
        AuditEvent.created_at > datetime.now(UTC) - LOGIN_WINDOW,
    )
    limited = (
        db.scalar(recent.where(AuditEvent.source == address)) >= 30
        or db.scalar(recent.where(AuditEvent.account_key == account_key)) >= 5
    )
    return account_key, limited


def verify_password(user: User | None, password: str) -> bool:
    try:
        verified = PASSWORDS.verify(user.password_hash if user else DUMMY_HASH, password)
    except VerifyMismatchError:
        return False
    return verified and user is not None


def prune_sessions(db: Session, now: datetime) -> None:
    # Limit each cleanup batch and skip sessions busy handling a request.
    stale = select(LoginSession.token_hash).where(
        (LoginSession.expires_at <= now) | (LoginSession.last_seen_at <= now - IDLE_TIMEOUT)
    ).limit(100).with_for_update(skip_locked=True)
    db.execute(delete(LoginSession).where(LoginSession.token_hash.in_(stale)))
