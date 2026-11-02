from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, serialize
from app.auth import service
from app.config import settings
from app.auth.schemas import (
    BootstrapRequest,
    LoginRequest,
    MfaDisableRequest,
    MfaVerifyRequest,
    PasswordChangeRequest,
    RefreshRequest,
)
from app.core.audit import record_audit
from app.core.exceptions import ForbiddenError, NotFoundError, UnauthorizedError, ValidationError
from app.core.permissions import ROLE_LABELS, get_current_user
from app.core.security import decode_token, hash_password, new_mfa_secret, provision_mfa_uri, verify_password, verify_totp
from app.database.models.identity import Session as AuthSession
from app.database.models.identity import User
from fastapi.security import HTTPAuthorizationCredentials

from app.core.permissions import bearer_scheme

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get("/bootstrap-status")
def bootstrap_status(db: Session = Depends(get_db)) -> dict:
    has_users = db.scalar(select(User).limit(1)) is not None
    return {
        "requires_bootstrap": not has_users,
        "registration_open": not has_users,
        "demo": settings.is_demo,
        "roles": [{"key": key, "name": label} for key, label in ROLE_LABELS.items()],
    }


@router.post("/bootstrap", status_code=201)
def bootstrap(payload: BootstrapRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    org, user = service.create_organization_with_owner(db, payload)
    db.commit()
    record_audit(
        db,
        user=user,
        action="auth.bootstrap",
        resource_type="organization",
        resource_id=org.id,
        request=request,
    )
    db.commit()
    return {
        "organization": {"id": str(org.id), "name": org.name, "slug": org.slug},
        "user": service.user_profile(user),
    }


@router.post("/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    result = service.login(
        db,
        payload,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    record_audit(db, user=user, action="auth.login", resource_type="session", request=request)
    db.commit()
    return result


@router.post("/refresh")
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)) -> dict:
    return service.refresh_session(db, payload.refresh_token)


@router.post("/logout")
def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    if credentials:
        try:
            payload = decode_token(credentials.credentials)
            service.revoke_session(db, user, payload["jti"])
        except Exception:  # noqa: BLE001 - logout remains idempotent
            pass
    record_audit(db, user=user, action="auth.logout", resource_type="session", request=request)
    db.commit()
    return {"status": "logged_out"}


@router.get("/me")
def me(user: User = Depends(get_current_user)) -> dict:
    return service.user_profile(user)


@router.get("/permissions")
def permissions(user: User = Depends(get_current_user)) -> dict:
    return service.permission_catalog()


@router.post("/mfa/setup")
def mfa_setup(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    secret = new_mfa_secret()
    user.mfa_secret = secret
    user.mfa_enabled = False
    db.commit()
    return {"secret": secret, "otpauth_uri": provision_mfa_uri(secret, user.email)}


@router.post("/mfa/enable")
def mfa_enable(
    payload: MfaVerifyRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    if not user.mfa_secret:
        raise ValidationError("Start MFA setup first")
    if not verify_totp(user.mfa_secret, payload.code):
        raise ValidationError("Invalid MFA code")
    user.mfa_enabled = True
    db.commit()
    return {"mfa_enabled": True}


@router.post("/mfa/disable")
def mfa_disable(
    payload: MfaDisableRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    if not verify_password(payload.password, user.hashed_password):
        raise UnauthorizedError("Invalid password")
    if not verify_totp(user.mfa_secret or "", payload.code):
        raise ValidationError("Invalid MFA code")
    user.mfa_enabled = False
    user.mfa_secret = None
    db.commit()
    return {"mfa_enabled": False}


@router.post("/password")
def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    if not verify_password(payload.current_password, user.hashed_password):
        raise UnauthorizedError("Current password is incorrect")
    user.hashed_password = hash_password(payload.new_password)
    db.commit()
    record_audit(db, user=user, action="auth.password_changed", resource_type="user", resource_id=user.id, request=request)
    db.commit()
    return {"status": "password_updated"}


@router.get("/sessions")
def list_sessions(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    sessions = db.scalars(
        select(AuthSession).where(AuthSession.user_id == user.id).order_by(AuthSession.created_at.desc()).limit(50)
    ).all()
    return {"items": [serialize(item) for item in sessions]}


@router.delete("/sessions/{session_id}")
def revoke_named_session(
    session_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    import uuid as _uuid

    session = db.get(AuthSession, _uuid.UUID(session_id))
    if session is None or session.user_id != user.id:
        raise NotFoundError("Session not found")
    from datetime import UTC, datetime

    session.revoked_at = datetime.now(UTC)
    db.commit()
    return {"status": "revoked"}
