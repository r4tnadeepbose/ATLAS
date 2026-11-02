import uuid
from datetime import UTC, datetime

from fastapi import Request
from sqlalchemy.orm import Session

from app.database.models.identity import AuditLog, User


def record_audit(
    db: Session,
    *,
    user: User | None,
    action: str,
    resource_type: str,
    resource_id: str | uuid.UUID | None = None,
    outcome: str = "success",
    details: dict | None = None,
    request: Request | None = None,
) -> AuditLog:
    entry = AuditLog(
        organization_id=user.organization_id if user else None,
        actor_user_id=user.id if user else None,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        outcome=outcome,
        ip_address=(request.client.host if request and request.client else None),
        user_agent=(request.headers.get("user-agent") if request else None),
        details=details or {},
        created_at=datetime.now(UTC),
    )
    db.add(entry)
    return entry
