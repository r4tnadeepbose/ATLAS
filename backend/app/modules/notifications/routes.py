import uuid

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import PageParams, get_db, get_org_id, page_params, paginate, page_response, serialize
from app.core.permissions import Permission, User, require_permissions
from app.database.models.ops import Notification, NotificationRule
from app.modules.notifications.service import emit

router = APIRouter(prefix="/notifications", tags=["Notification Center"])


class RuleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    event_key: str = Field(min_length=2, max_length=100)
    min_severity: str = "medium"
    channels: list[str] = Field(default_factory=lambda: ["in_app"])
    enabled: bool = True
    dedup_window_minutes: int = Field(default=30, ge=1, le=1440)
    config: dict = Field(default_factory=dict)


class TestNotification(BaseModel):
    subject: str = "ATLAS test notification"
    body: str = "This is a test notification generated from the ATLAS notification center."
    severity: str = "info"


@router.get("")
def list_notifications(
    params: PageParams = Depends(page_params),
    unread_only: bool = False,
    severity: str | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.NOTIFICATION_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(Notification).where(
        Notification.organization_id == org_id,
        (Notification.user_id == user.id) | (Notification.user_id.is_(None)),
    )
    if unread_only:
        stmt = stmt.where(Notification.read_at.is_(None))
    if severity:
        stmt = stmt.where(Notification.severity == severity)
    items, meta = paginate(
        db,
        stmt,
        params,
        Notification,
        search_fields=[Notification.subject, Notification.body, Notification.event_key],
        sortable={"created_at": Notification.created_at, "severity": Notification.severity},
        default_sort=Notification.created_at,
    )
    return page_response(items, meta)


@router.get("/unread-count")
def unread_count(
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.NOTIFICATION_READ)),
    db: Session = Depends(get_db),
) -> dict:
    count = db.scalar(
        select(func.count(Notification.id)).where(
            Notification.organization_id == org_id,
            (Notification.user_id == user.id) | (Notification.user_id.is_(None)),
            Notification.read_at.is_(None),
        )
    ) or 0
    return {"unread": count}


@router.post("/{notification_id}/read")
def mark_read(
    notification_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.NOTIFICATION_READ)),
    db: Session = Depends(get_db),
) -> dict:
    from datetime import UTC, datetime

    notification = db.get(Notification, notification_id)
    if notification is None or notification.organization_id != org_id:
        return {"status": "not_found"}
    notification.read_at = datetime.now(UTC)
    db.commit()
    return serialize(notification)


@router.post("/read-all")
def mark_all_read(
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.NOTIFICATION_READ)),
    db: Session = Depends(get_db),
) -> dict:
    from datetime import UTC, datetime

    notifications = db.scalars(
        select(Notification).where(
            Notification.organization_id == org_id,
            (Notification.user_id == user.id) | (Notification.user_id.is_(None)),
            Notification.read_at.is_(None),
        )
    ).all()
    for notification in notifications:
        notification.read_at = datetime.now(UTC)
    db.commit()
    return {"updated": len(notifications)}


@router.get("/rules")
def list_rules(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.NOTIFICATION_READ)),
    db: Session = Depends(get_db),
) -> dict:
    rules = db.scalars(select(NotificationRule).where(NotificationRule.organization_id == org_id).order_by(NotificationRule.event_key)).all()
    return {"items": [serialize(rule) for rule in rules]}


@router.post("/rules", status_code=201)
def create_rule(
    payload: RuleCreate,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.NOTIFICATION_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    rule = NotificationRule(organization_id=org_id, **payload.model_dump())
    db.add(rule)
    db.commit()
    return serialize(rule)


@router.patch("/rules/{rule_id}")
def update_rule(
    rule_id: uuid.UUID,
    payload: dict,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.NOTIFICATION_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    rule = db.get(NotificationRule, rule_id)
    if rule is None or rule.organization_id != org_id:
        from app.core.exceptions import NotFoundError

        raise NotFoundError("Rule not found")
    for field in ("name", "min_severity", "channels", "enabled", "dedup_window_minutes", "config"):
        if field in payload:
            setattr(rule, field, payload[field])
    db.commit()
    return serialize(rule)


@router.post("/test")
def send_test(
    payload: TestNotification,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.NOTIFICATION_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    notification = emit(
        db,
        organization_id=org_id,
        event_key="test",
        subject=payload.subject,
        body=payload.body,
        severity=payload.severity,
        user_id=user.id,
        metadata={"test": True},
    )
    db.commit()
    return {"status": "sent", "id": str(notification.id) if notification else None}
