from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.workers.celery_app import celery_app


@celery_app.task(name="atlas.scans.run")
def run_scan_task(organization_id: str, scan_id: str):
    import uuid

    from app.modules.attack_surface.runner import run_scan

    run_scan(uuid.UUID(organization_id), uuid.UUID(scan_id))
    return {"status": "completed", "scan_id": scan_id}


@celery_app.task(name="atlas.scans.run_scheduled")
def run_scheduled_scans():
    """Create scan jobs for schedules whose next_run_at has elapsed.

    The schedule owner's administrator privilege is recorded as the
    authorization for the assessment, with a schedule-scoped reference.
    """
    try:
        from croniter import croniter
    except ImportError:
        return {"status": "skipped", "reason": "croniter not installed"}

    from app.database.models.scans import ScanHistory, ScanJob, ScanSchedule
    from app.database.session import SessionLocal
    from app.modules.attack_surface.runner import run_scan
    from app.modules.attack_surface.scope import validate_scope

    db = SessionLocal()
    created = 0
    try:
        now = datetime.now(UTC)
        schedules = db.scalars(
            select(ScanSchedule).where(
                ScanSchedule.enabled.is_(True),
                ScanSchedule.next_run_at.is_not(None),
                ScanSchedule.next_run_at <= now,
            )
        ).all()
        for schedule in schedules:
            try:
                scope = validate_scope(schedule.scope)
            except Exception:  # noqa: BLE001
                schedule.enabled = False
                continue
            job = ScanJob(
                organization_id=schedule.organization_id,
                name=f"{schedule.name} (scheduled)",
                scan_type=schedule.scan_type,
                target=schedule.target,
                scope=scope,
                adapter=schedule.scan_type.split("_")[0],
                status="queued",
                created_by=schedule.created_by,
                authorized_by=schedule.created_by,
                authorization_reference=f"SCHEDULE:{schedule.id}",
            )
            db.add(job)
            db.flush()
            db.add(ScanHistory(organization_id=schedule.organization_id, scan_job_id=job.id, event="queued", message="Queued by schedule"))
            schedule.last_run_at = now
            schedule.next_run_at = croniter(schedule.cron, now).get_next(datetime)
            db.commit()
            run_scan(schedule.organization_id, job.id)
            created += 1
        return {"status": "ok", "created": created}
    finally:
        db.close()


def compute_next_run(cron: str, base: datetime | None = None) -> datetime | None:
    try:
        from croniter import croniter

        return croniter(cron, base or datetime.now(UTC)).get_next(datetime)
    except Exception:  # noqa: BLE001 - invalid cron is surfaced at the API layer
        return None
