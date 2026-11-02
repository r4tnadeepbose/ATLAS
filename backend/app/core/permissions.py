"""Role-based access control.

Permissions are enforced server-side by the ``require_permissions`` dependency.
Frontend visibility is a convenience only and is never treated as authorization.
"""

from enum import StrEnum
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import decode_token
from app.database.models.identity import Session as AuthSession
from app.database.models.identity import User
from app.database.session import get_db

bearer_scheme = HTTPBearer(auto_error=False)


class Permission(StrEnum):
    DASHBOARD_READ = "dashboard:read"
    EXECUTIVE_READ = "executive:read"

    ASSET_READ = "assets:read"
    ASSET_WRITE = "assets:write"
    SERVICE_READ = "microservices:read"
    SERVICE_WRITE = "microservices:write"

    SBOM_READ = "sbom:read"
    SBOM_WRITE = "sbom:write"
    SBOM_ANALYZE = "sbom:analyze"

    FINDING_READ = "findings:read"
    FINDING_WRITE = "findings:write"
    FINDING_TRIAGE = "findings:triage"

    SCAN_READ = "scans:read"
    SCAN_RUN = "scans:run"
    SCAN_ADMIN = "scans:admin"

    API_READ = "apis:read"
    API_WRITE = "apis:write"

    CLASSIFICATION_READ = "classification:read"
    CLASSIFICATION_WRITE = "classification:write"

    RISK_READ = "risks:read"
    RISK_WRITE = "risks:write"

    REPORT_READ = "reports:read"
    REPORT_WRITE = "reports:write"

    NOTIFICATION_READ = "notifications:read"
    NOTIFICATION_WRITE = "notifications:write"

    USER_READ = "users:read"
    USER_WRITE = "users:write"
    ORG_ADMIN = "org:admin"
    INTEGRATION_READ = "integrations:read"
    INTEGRATION_WRITE = "integrations:write"
    SETTINGS_READ = "settings:read"
    SETTINGS_WRITE = "settings:write"
    AUDIT_READ = "audit:read"


READ_ONLY = {
    Permission.DASHBOARD_READ,
    Permission.ASSET_READ,
    Permission.SERVICE_READ,
    Permission.SBOM_READ,
    Permission.FINDING_READ,
    Permission.SCAN_READ,
    Permission.API_READ,
    Permission.CLASSIFICATION_READ,
    Permission.RISK_READ,
}


ROLE_PERMISSIONS: dict[str, set[str]] = {
    "super_admin": {p.value for p in Permission},
    "security_admin": {
        p.value
        for p in Permission
        if p
        not in {
            Permission.USER_WRITE,
            Permission.ORG_ADMIN,
            Permission.SETTINGS_WRITE,
        }
    }
    | {Permission.USER_READ.value},
    "soc_analyst": {
        Permission.DASHBOARD_READ.value,
        Permission.ASSET_READ.value,
        Permission.SERVICE_READ.value,
        Permission.SBOM_READ.value,
        Permission.FINDING_READ.value,
        Permission.FINDING_WRITE.value,
        Permission.FINDING_TRIAGE.value,
        Permission.SCAN_READ.value,
        Permission.SCAN_RUN.value,
        Permission.API_READ.value,
        Permission.CLASSIFICATION_READ.value,
        Permission.RISK_READ.value,
        Permission.RISK_WRITE.value,
        Permission.REPORT_READ.value,
        Permission.NOTIFICATION_READ.value,
        Permission.NOTIFICATION_WRITE.value,
    },
    "vapt_analyst": {
        Permission.DASHBOARD_READ.value,
        Permission.ASSET_READ.value,
        Permission.ASSET_WRITE.value,
        Permission.SERVICE_READ.value,
        Permission.SBOM_READ.value,
        Permission.FINDING_READ.value,
        Permission.FINDING_WRITE.value,
        Permission.SCAN_READ.value,
        Permission.SCAN_RUN.value,
        Permission.SCAN_ADMIN.value,
        Permission.API_READ.value,
        Permission.API_WRITE.value,
        Permission.CLASSIFICATION_READ.value,
        Permission.RISK_READ.value,
        Permission.REPORT_READ.value,
        Permission.REPORT_WRITE.value,
        Permission.NOTIFICATION_READ.value,
    },
    "developer": {
        Permission.DASHBOARD_READ.value,
        Permission.ASSET_READ.value,
        Permission.SERVICE_READ.value,
        Permission.SBOM_READ.value,
        Permission.FINDING_READ.value,
        Permission.FINDING_WRITE.value,
        Permission.API_READ.value,
        Permission.REPORT_READ.value,
        Permission.NOTIFICATION_READ.value,
    },
    "executive": {
        Permission.DASHBOARD_READ.value,
        Permission.EXECUTIVE_READ.value,
        Permission.RISK_READ.value,
        Permission.REPORT_READ.value,
        Permission.NOTIFICATION_READ.value,
    },
}

ROLE_LABELS: dict[str, str] = {
    "super_admin": "Super Administrator",
    "security_admin": "Security Administrator",
    "soc_analyst": "SOC Analyst",
    "vapt_analyst": "VAPT Analyst",
    "developer": "Developer",
    "executive": "Executive",
}


def permissions_for_roles(roles: list[str]) -> set[str]:
    permissions: set[str] = set()
    for role in roles:
        permissions |= ROLE_PERMISSIONS.get(role, set())
    return permissions


def _unauthorized(message: str = "Not authenticated") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "unauthorized", "message": message},
        headers={"WWW-Authenticate": "Bearer"},
    )


def resolve_user_from_token(credentials: HTTPAuthorizationCredentials | None, db: Session) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()
    try:
        payload = decode_token(credentials.credentials)
    except Exception as exc:  # noqa: BLE001 - jwt raises several subclasses
        raise _unauthorized("Invalid or expired token") from exc

    if payload.get("type") != "access":
        raise _unauthorized("Access token required")

    auth_session = db.scalar(
        select(AuthSession).where(
            AuthSession.token_jti == payload.get("jti"), AuthSession.revoked_at.is_(None)
        )
    )
    if auth_session is None:
        raise _unauthorized("Session revoked")

    try:
        user_id = UUID(str(payload["sub"]))
    except (ValueError, KeyError) as exc:
        raise _unauthorized("Invalid token subject") from exc
    user = db.get(User, user_id)
    if user is None or not user.is_active or user.deleted_at is not None:
        raise _unauthorized("Account unavailable")
    return user


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    return resolve_user_from_token(credentials, db)


def require_permissions(*required: Permission):
    required_values = {p.value for p in required}

    def dependency(user: User = Depends(get_current_user)) -> User:
        if not required_values.issubset(set(user.permission_keys())):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "forbidden", "message": "Insufficient permissions", "required": sorted(required_values)},
            )
        return user

    return dependency


def require_any_permission(*required: Permission):
    required_values = {p.value for p in required}

    def dependency(user: User = Depends(get_current_user)) -> User:
        if not (required_values & set(user.permission_keys())):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "forbidden", "message": "Insufficient permissions", "required": sorted(required_values)},
            )
        return user

    return dependency
