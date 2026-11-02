import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import PageParams, get_db, get_org_id, page_params, paginate, page_response, serialize
from app.config import settings
from app.core.audit import record_audit
from app.core.exceptions import ConflictError, ValidationError
from app.core.permissions import Permission, User, require_permissions
from app.core.tenancy import scoped_get
from app.database.models.scans import ScanHistory, ScanJob, ScanLog, ScanResult, ScanSchedule
from app.modules.attack_surface import runner
from app.modules.attack_surface.scope import validate_scope

router = APIRouter(prefix="/scans", tags=["Attack Surface"])


class ScanCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    scan_type: str = Field(pattern="^(subdomain_enumeration|http_probe|port_scan|vulnerability_scan|full_recon)$")
    target: str = Field(min_length=3, max_length=500)
    scope: dict = Field(default_factory=dict)
    options: dict = Field(default_factory=dict)
    authorization_reference: str | None = Field(default=None, max_length=200)


class ScheduleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    scan_type: str = Field(pattern="^(subdomain_enumeration|http_probe|port_scan|vulnerability_scan|full_recon)$")
    target: str = Field(min_length=3, max_length=500)
    cron: str = Field(min_length=5, max_length=80)
    scope: dict = Field(default_factory=dict)
    enabled: bool = True


@router.get("/tools")
def scan_tools(_: User = Depends(require_permissions(Permission.SCAN_READ))) -> dict:
    from app.integrations.grype.adapter import GrypeAdapter
    from app.integrations.nmap.adapter import NmapAdapter
    from app.integrations.nuclei.adapter import NucleiAdapter
    from app.integrations.subfinder.adapter import HttpxAdapter, SubfinderAdapter
    from app.integrations.syft.adapter import SyftAdapter
    from app.integrations.trivy.adapter import TrivyAdapter
    from app.integrations.zap.adapter import ZapAdapter

    adapters = [SyftAdapter(), GrypeAdapter(), TrivyAdapter(), SubfinderAdapter(), HttpxAdapter(), NmapAdapter(), NucleiAdapter(), ZapAdapter()]
    return {"items": [adapter.availability() for adapter in adapters]}


@router.get("/dashboard")
def scan_dashboard(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SCAN_READ)),
    db: Session = Depends(get_db),
) -> dict:
    status_rows = db.execute(
        select(ScanJob.status, func.count(ScanJob.id)).where(ScanJob.organization_id == org_id).group_by(ScanJob.status)
    ).all()
    type_rows = db.execute(
        select(ScanJob.scan_type, func.count(ScanJob.id)).where(ScanJob.organization_id == org_id).group_by(ScanJob.scan_type)
    ).all()
    recent = db.scalars(select(ScanJob).where(ScanJob.organization_id == org_id).order_by(ScanJob.created_at.desc()).limit(8)).all()
    return {
        "by_status": [{"name": row[0], "value": row[1]} for row in status_rows],
        "by_type": [{"name": row[0], "value": row[1]} for row in type_rows],
        "recent": [serialize(job) for job in recent],
        "active": sum(count for status, count in status_rows if status in {"queued", "running"}),
    }


@router.get("")
def list_scans(
    params: PageParams = Depends(page_params),
    status: str | None = None,
    scan_type: str | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SCAN_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(ScanJob).where(ScanJob.organization_id == org_id)
    if status:
        stmt = stmt.where(ScanJob.status == status)
    if scan_type:
        stmt = stmt.where(ScanJob.scan_type == scan_type)
    items, meta = paginate(
        db,
        stmt,
        params,
        ScanJob,
        search_fields=[ScanJob.name, ScanJob.target, ScanJob.adapter],
        sortable={"created_at": ScanJob.created_at, "status": ScanJob.status, "progress": ScanJob.progress},
        default_sort=ScanJob.created_at,
    )
    return page_response(items, meta)


@router.post("", status_code=202)
def create_scan(
    payload: ScanCreate,
    background: BackgroundTasks,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.SCAN_RUN)),
    db: Session = Depends(get_db),
) -> dict:
    scope = validate_scope(payload.scope)
    from app.modules.attack_surface.scope import authorize_target

    authorize_target(payload.target, scope)
    if settings.require_scan_authorization and not payload.authorization_reference:
        raise ValidationError("An authorization reference is required for active assessments")
    active = db.scalar(
        select(ScanJob.id).where(
            ScanJob.organization_id == org_id,
            ScanJob.target == payload.target,
            ScanJob.status.in_(("queued", "running")),
        )
    )
    if active:
        raise ConflictError("An active scan already exists for this target")
    job = ScanJob(
        organization_id=org_id,
        name=payload.name,
        scan_type=payload.scan_type,
        target=payload.target,
        scope=scope,
        options=payload.options,
        adapter=payload.scan_type.split("_")[0],
        status="queued",
        created_by=user.id,
        authorized_by=user.id if payload.authorization_reference else None,
        authorization_reference=payload.authorization_reference,
    )
    db.add(job)
    db.flush()
    db.add(ScanHistory(organization_id=org_id, scan_job_id=job.id, event="queued", message=f"Queued by {user.email}"))
    record_audit(db, user=user, action="scan.queued", resource_type="scan", resource_id=job.id, details={"target": payload.target, "type": payload.scan_type}, request=request)
    db.commit()
    background.add_task(runner.run_scan, org_id, job.id)
    return serialize(job)


@router.get("/{scan_id}")
def get_scan(
    scan_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SCAN_READ)),
    db: Session = Depends(get_db),
) -> dict:
    job = scoped_get(db, ScanJob, scan_id, org_id)
    results = db.scalars(select(ScanResult).where(ScanResult.scan_job_id == job.id).order_by(ScanResult.created_at.desc()).limit(200)).all()
    logs = db.scalars(select(ScanLog).where(ScanLog.scan_job_id == job.id).order_by(ScanLog.created_at.desc()).limit(200)).all()
    history = db.scalars(select(ScanHistory).where(ScanHistory.scan_job_id == job.id).order_by(ScanHistory.created_at.desc())).all()
    return {
        **serialize(job),
        "results": [serialize(result) for result in results],
        "logs": [serialize(entry) for entry in reversed(logs)],
        "history": [serialize(entry) for entry in history],
    }


@router.post("/{scan_id}/cancel")
def cancel_scan(
    scan_id: uuid.UUID,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.SCAN_RUN)),
    db: Session = Depends(get_db),
) -> dict:
    job = scoped_get(db, ScanJob, scan_id, org_id)
    if job.status not in {"queued", "running"}:
        raise ConflictError("Only queued or running scans can be cancelled")
    job.cancellation_requested = True
    if job.status == "queued":
        job.status = "cancelled"
        job.finished_at = datetime.now(UTC)
    record_audit(db, user=user, action="scan.cancelled", resource_type="scan", resource_id=job.id, request=request)
    db.commit()
    return serialize(job)


@router.get("/{scan_id}/results")
def scan_results(
    scan_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SCAN_READ)),
    db: Session = Depends(get_db),
) -> dict:
    scoped_get(db, ScanJob, scan_id, org_id)
    results = db.scalars(select(ScanResult).where(ScanResult.scan_job_id == scan_id).limit(500)).all()
    return {"items": [serialize(result) for result in results]}


@router.get("/{scan_id}/logs")
def scan_logs(
    scan_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SCAN_READ)),
    db: Session = Depends(get_db),
) -> dict:
    scoped_get(db, ScanJob, scan_id, org_id)
    logs = db.scalars(select(ScanLog).where(ScanLog.scan_job_id == scan_id).order_by(ScanLog.created_at)).all()
    return {"items": [serialize(entry) for entry in logs]}


schedule_router = APIRouter(prefix="/scan-schedules", tags=["Scan Schedules"])


@schedule_router.get("")
def list_schedules(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SCAN_READ)),
    db: Session = Depends(get_db),
) -> dict:
    schedules = db.scalars(select(ScanSchedule).where(ScanSchedule.organization_id == org_id).order_by(ScanSchedule.created_at.desc())).all()
    return {"items": [serialize(schedule) for schedule in schedules]}


@schedule_router.post("", status_code=201)
def create_schedule(
    payload: ScheduleCreate,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.SCAN_ADMIN)),
    db: Session = Depends(get_db),
) -> dict:
    scope = validate_scope(payload.scope)
    from app.modules.attack_surface.scope import authorize_target
    from app.workers.scan_tasks import compute_next_run

    authorize_target(payload.target, scope)
    next_run = compute_next_run(payload.cron)
    if next_run is None:
        raise ValidationError("Invalid cron expression")
    schedule = ScanSchedule(
        organization_id=org_id,
        name=payload.name,
        scan_type=payload.scan_type,
        target=payload.target,
        cron=payload.cron,
        scope=scope,
        enabled=payload.enabled,
        next_run_at=next_run,
        created_by=user.id,
    )
    db.add(schedule)
    db.commit()
    return serialize(schedule)


@schedule_router.patch("/{schedule_id}")
def update_schedule(
    schedule_id: uuid.UUID,
    payload: dict,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SCAN_ADMIN)),
    db: Session = Depends(get_db),
) -> dict:
    schedule = scoped_get(db, ScanSchedule, schedule_id, org_id)
    for field in ("name", "cron", "enabled"):
        if field in payload:
            setattr(schedule, field, payload[field])
    db.commit()
    return serialize(schedule)


@schedule_router.delete("/{schedule_id}")
def delete_schedule(
    schedule_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SCAN_ADMIN)),
    db: Session = Depends(get_db),
) -> dict:
    schedule = scoped_get(db, ScanSchedule, schedule_id, org_id)
    db.delete(schedule)
    db.commit()
    return {"status": "deleted"}
