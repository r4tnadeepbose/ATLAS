import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models.ops import Notification, NotificationRule
from app.core.logging import get_logger

logger = get_logger("notifications")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def emit(
    db: Session,
    *,
    organization_id: uuid.UUID,
    event_key: str,
    subject: str,
    body: str,
    severity: str = "info",
    user_id: uuid.UUID | None = None,
    dedup_key: str | None = None,
    metadata: dict | None = None,
) -> Notification | None:
    """Create notifications for an event.

    Deduplication is applied per organization + dedup key within the rule's
    window so repeated scans do not create alert storms.
    """
    rules = db.scalars(
        select(NotificationRule).where(
            NotificationRule.organization_id == organization_id,
            NotificationRule.event_key == event_key,
            NotificationRule.enabled.is_(True),
        )
    ).all()
    if rules:
        window = max(rule.dedup_window_minutes for rule in rules)
        if SEVERITY_ORDER.get(severity, 0) < min(SEVERITY_ORDER.get(rule.min_severity, 1) for rule in rules):
            return None
    else:
        window = 30

    if dedup_key:
        cutoff = datetime.now(UTC) - timedelta(minutes=window)
        existing = db.scalar(
            select(Notification.id).where(
                Notification.organization_id == organization_id,
                Notification.dedup_key == dedup_key,
                Notification.created_at >= cutoff,
            )
        )
        if existing:
            return None

    channels = sorted({channel for rule in rules for channel in (rule.channels or [])}) or ["in_app"]
    notification = None
    for channel in channels:
        notification = Notification(
            organization_id=organization_id,
            user_id=user_id,
            channel=channel,
            event_key=event_key,
            subject=subject[:300],
            body=body,
            severity=severity,
            status="sent" if channel == "in_app" else "pending",
            sent_at=datetime.now(UTC) if channel == "in_app" else None,
            dedup_key=dedup_key,
            metadata_json=metadata or {},
        )
        db.add(notification)
        if channel != "in_app":
            # External delivery is performed by the notification worker when
            # SMTP / Slack / Teams / webhook credentials are configured.
            logger.info("queued external notification channel=%s event=%s", channel, event_key)
    return notification
