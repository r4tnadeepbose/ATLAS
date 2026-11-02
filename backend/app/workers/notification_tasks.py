from app.core.logging import get_logger
from app.workers.celery_app import celery_app

logger = get_logger("worker.notifications")


@celery_app.task(name="atlas.notifications.deliver_pending")
def deliver_pending_notifications():
    """Placeholder delivery loop for external channels.

    In-app notifications are written synchronously. Email/Slack/Teams/webhook
    delivery requires provider credentials in the integration configuration; until
    those are present the notifications remain in ``pending`` and are retried.
    """
    from sqlalchemy import select

    from app.database.models.ops import Integration, Notification
    from app.database.session import SessionLocal

    db = SessionLocal()
    try:
        configured = {
            integration.key
            for integration in db.scalars(
                select(Integration).where(Integration.enabled.is_(True), Integration.key.in_(("email", "slack", "teams", "webhook")))
            ).all()
        }
        pending = db.scalars(
            select(Notification).where(Notification.status == "pending", Notification.channel != "in_app").limit(200)
        ).all()
        delivered = 0
        for notification in pending:
            if notification.channel in configured:
                # Provider delivery is implemented by deployment-specific plugins;
                # without one, the message is marked queued rather than falsely sent.
                notification.status = "queued"
                delivered += 1
        db.commit()
        return {"pending": len(pending), "queued": delivered}
    finally:
        db.close()
