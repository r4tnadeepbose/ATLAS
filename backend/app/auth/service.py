import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core.exceptions import ConflictError, ForbiddenError, UnauthorizedError, ValidationError
from app.core.permissions import ROLE_LABELS, ROLE_PERMISSIONS, permissions_for_roles
from app.core.security import create_token, decode_token, hash_password, verify_password, verify_totp
from app.core.time import iso
from app.database.models.identity import Organization, Role, Session as AuthSession, User, UserRole
from app.auth.schemas import BootstrapRequest, LoginRequest

MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 15


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def user_profile(user: User) -> dict:
    roles = user.role_keys()
    return {
        "id": str(user.id),
        "email": user.email,
        "full_name": user.full_name,
        "title": user.title,
        "organization_id": str(user.organization_id),
        "roles": roles,
        "role_labels": [ROLE_LABELS.get(r, r) for r in roles],
        "permissions": sorted(user.permission_keys()),
        "mfa_enabled": user.mfa_enabled,
        "is_active": user.is_active,
        "last_login_at": iso(user.last_login_at),
    }


def tenant_roles(db: Session, organization_id: uuid.UUID) -> dict[str, Role]:
    roles = db.scalars(
        select(Role).where((Role.organization_id == organization_id) | (Role.organization_id.is_(None)))
    ).all()
    return {role.key: role for role in roles}


def create_organization_with_owner(db: Session, payload: BootstrapRequest) -> tuple[Organization, User]:
    existing = db.scalar(select(User).limit(1))
    if existing is not None:
        raise ForbiddenError("Bootstrap already completed. Ask an administrator for an invitation.")

    slug_base = payload.organization_name.lower().replace(" ", "-")[:80]
    slug = slug_base
    counter = 1
    while db.scalar(select(Organization).where(Organization.slug == slug)):
        counter += 1
        slug = f"{slug_base}-{counter}"

    org = Organization(name=payload.organization_name, slug=slug, settings={"environment_defaults": []})
    db.add(org)
    db.flush()

    user = User(
        organization_id=org.id,
        email=payload.email.lower(),
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        is_active=True,
        title="Platform Owner",
    )
    db.add(user)
    db.flush()

    role = db.scalar(select(Role).where(Role.key == "super_admin", Role.organization_id.is_(None)))
    if role is None:
        role = Role(key="super_admin", name="Super Administrator", description="Complete platform access", is_system=True)
        db.add(role)
        db.flush()
    db.add(UserRole(user_id=user.id, role_id=role.id))
    db.flush()
    db.refresh(user)
    return org, user


def login(
    db: Session,
    payload: LoginRequest,
    *,
    ip_address: str | None,
    user_agent: str | None,
) -> dict:
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    generic = "Invalid email or password"
    if user is None or user.deleted_at is not None:
        raise UnauthorizedError(generic)

    locked_until = _aware(user.locked_until)
    if locked_until and locked_until > datetime.now(UTC):
        raise ForbiddenError("Account temporarily locked after repeated failed sign-in attempts")

    if not verify_password(payload.password, user.hashed_password):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.now(UTC) + timedelta(minutes=LOCK_MINUTES)
            user.failed_login_attempts = 0
        db.commit()
        raise UnauthorizedError(generic)

    if not user.is_active:
        raise ForbiddenError("Account is deactivated")

    if user.mfa_enabled:
        if not payload.mfa_code or not verify_totp(user.mfa_secret or "", payload.mfa_code):
            raise UnauthorizedError("Valid MFA code required", )

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now(UTC)

    access, access_jti, access_exp = create_token(str(user.id), "access", extra={"org": str(user.organization_id)})
    refresh, refresh_jti, _ = create_token(str(user.id), "refresh")

    db.add(
        AuthSession(
            user_id=user.id,
            token_jti=access_jti,
            refresh_jti=refresh_jti,
            ip_address=ip_address,
            user_agent=(user_agent or "")[:300],
            expires_at=access_exp,
        )
    )
    db.commit()
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": settings.access_token_minutes * 60,
        "user": user_profile(user),
    }


def refresh_session(db: Session, refresh_token: str) -> dict:
    try:
        payload = decode_token(refresh_token)
    except Exception as exc:  # noqa: BLE001
        raise UnauthorizedError("Invalid refresh token") from exc
    if payload.get("type") != "refresh":
        raise UnauthorizedError("Refresh token required")

    session = db.scalar(select(AuthSession).where(AuthSession.refresh_jti == payload["jti"]))
    if session is None or session.revoked_at is not None:
        raise UnauthorizedError("Session revoked")
    user = db.get(User, uuid.UUID(str(payload["sub"])))
    if user is None or not user.is_active:
        raise UnauthorizedError("Account unavailable")

    session.revoked_at = datetime.now(UTC)
    access, access_jti, access_exp = create_token(str(user.id), "access", extra={"org": str(user.organization_id)})
    new_refresh, refresh_jti, _ = create_token(str(user.id), "refresh")
    db.add(
        AuthSession(
            user_id=user.id,
            token_jti=access_jti,
            refresh_jti=refresh_jti,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            expires_at=access_exp,
        )
    )
    db.commit()
    return {
        "access_token": access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "expires_in": settings.access_token_minutes * 60,
        "user": user_profile(user),
    }


def revoke_session(db: Session, user: User, jti: str) -> None:
    session = db.scalar(select(AuthSession).where(AuthSession.token_jti == jti, AuthSession.user_id == user.id))
    if session:
        session.revoked_at = datetime.now(UTC)
        db.commit()


def create_user(db: Session, organization_id: uuid.UUID, payload) -> User:
    if db.scalar(select(User).where(User.email == payload.email.lower())):
        raise ConflictError("A user with that email already exists")
    role = tenant_roles(db, organization_id).get(payload.role)
    if role is None:
        raise ValidationError("Unknown role", details={"allowed": sorted(ROLE_PERMISSIONS.keys())})
    user = User(
        organization_id=organization_id,
        email=payload.email.lower(),
        full_name=payload.full_name,
        title=payload.title,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    db.flush()
    db.add(UserRole(user_id=user.id, role_id=role.id))
    db.flush()
    db.refresh(user)
    return user


def set_user_role(db: Session, user: User, role_key: str) -> User:
    role = tenant_roles(db, user.organization_id).get(role_key)
    if role is None:
        raise ValidationError("Unknown role", details={"allowed": sorted(ROLE_PERMISSIONS.keys())})
    for assignment in list(user.roles):
        db.delete(assignment)
    db.flush()
    db.add(UserRole(user_id=user.id, role_id=role.id))
    db.flush()
    db.refresh(user)
    return user


def ensure_roles_seeded(db: Session) -> None:
    for key, permission_keys in ROLE_PERMISSIONS.items():
        role = db.scalar(select(Role).where(Role.key == key, Role.organization_id.is_(None)))
        if role is None:
            role = Role(key=key, name=ROLE_LABELS[key], description=f"Built-in {ROLE_LABELS[key]} role", is_system=True)
            db.add(role)
            db.flush()
    db.commit()


def permission_catalog() -> dict:
    return {
        "roles": [
            {"key": key, "name": ROLE_LABELS[key], "permissions": sorted(ROLE_PERMISSIONS[key])}
            for key in ROLE_PERMISSIONS
        ],
    }
