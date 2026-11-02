import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import PageParams, get_db, get_org_id, page_params, paginate, page_response, serialize
from app.core.audit import record_audit
from app.core.exceptions import NotFoundError
from app.core.permissions import Permission, User, require_permissions
from app.core.tenancy import scoped_get
from app.database.models.findings import Finding
from app.database.models.identity import User as UserModel
from app.database.models.risk import RemediationTask, RiskAssessment, RiskException, RiskScore
from app.modules.risk_engine import service

router = APIRouter(prefix="/risks", tags=["Risk Management"])
remediation_router = APIRouter(prefix="/remediation-tasks", tags=["Remediation"])


class AcceptRiskRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)
    expires_at: datetime | None = None


class AssignRiskRequest(BaseModel):
    responsible_team: str | None = None
    remediation_deadline: datetime | None = None
    business_impact: str | None = None


class ExceptionRequest(BaseModel):
    assessment_id: uuid.UUID | None = None
    reason: str = Field(min_length=5, max_length=2000)
    scope: str = "asset"
    expires_at: datetime | None = None


class RemediationCreate(BaseModel):
    finding_id: uuid.UUID | None = None
    title: str = Field(min_length=3, max_length=300)
    description: str | None = None
    assigned_to: uuid.UUID | None = None
    priority: str = "medium"
    due_at: datetime | None = None


class RemediationUpdate(BaseModel):
    status: str | None = None
    assigned_to: uuid.UUID | None = None
    due_at: datetime | None = None
    evidence: str | None = None


@router.get("")
def list_risks(
    params: PageParams = Depends(page_params),
    severity: str | None = None,
    status: str | None = None,
    business_unit: str | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.RISK_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(RiskAssessment).where(RiskAssessment.organization_id == org_id)
    if severity:
        stmt = stmt.where(RiskAssessment.severity == severity)
    if status:
        stmt = stmt.where(RiskAssessment.status == status)
    if business_unit:
        stmt = stmt.where(RiskAssessment.business_unit == business_unit)
    items, meta = paginate(
        db,
        stmt,
        params,
        RiskAssessment,
        search_fields=[RiskAssessment.business_unit, RiskAssessment.responsible_team, RiskAssessment.business_impact],
        sortable={"score": RiskAssessment.score, "created_at": RiskAssessment.created_at, "severity": RiskAssessment.severity},
        default_sort=RiskAssessment.score,
    )
    findings = {
        finding.id: finding
        for finding in db.scalars(select(Finding).where(Finding.organization_id == org_id, Finding.id.in_([item.finding_id for item in items if item.finding_id]))).all()
    }
    return {
        "items": [
            {
                **serialize(item),
                "finding_ref": findings[item.finding_id].finding_ref if item.finding_id in findings else None,
                "finding_title": findings[item.finding_id].title if item.finding_id in findings else None,
                "status_finding": findings[item.finding_id].status if item.finding_id in findings else None,
            }
            for item in items
        ],
        "pagination": meta,
    }


@router.get("/summary")
def risk_summary(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.RISK_READ)),
    db: Session = Depends(get_db),
) -> dict:
    assessments = db.scalars(select(RiskAssessment).where(RiskAssessment.organization_id == org_id)).all()
    by_severity: dict[str, int] = {}
    for assessment in assessments:
        by_severity[assessment.severity] = by_severity.get(assessment.severity, 0) + 1
    by_unit = sorted(
        [
            {"name": row[0] or "unassigned", "value": round(float(row[1] or 0), 1), "count": row[2]}
            for row in db.execute(
                select(RiskAssessment.business_unit, func.avg(RiskAssessment.score), func.count(RiskAssessment.id))
                .where(RiskAssessment.organization_id == org_id)
                .group_by(RiskAssessment.business_unit)
            ).all()
        ],
        key=lambda item: item["value"],
        reverse=True,
    )
    return {
        "total": len(assessments),
        "average_score": round(sum(item.score for item in assessments) / len(assessments), 1) if assessments else 0,
        "by_severity": [{"name": key, "value": value} for key, value in by_severity.items()],
        "by_business_unit": by_unit,
        "accepted": len([item for item in assessments if item.status == "accepted"]),
        "critically_exposed": len([item for item in assessments if item.score >= 85]),
        "model": {"version": "atlas-risk-v1", "documentation": "/docs/security-model#risk-scoring"},
    }


@router.post("/recompute")
def recompute(
    request: Request,
    finding_id: uuid.UUID | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.RISK_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    updated = service.recompute_assessments(db, org_id, finding_id)
    record_audit(db, user=user, action="risk.recomputed", resource_type="risk_assessment", details={"assessments": updated}, request=request)
    db.commit()
    return {"updated": updated}


@router.get("/exceptions")
def list_exceptions(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.RISK_READ)),
    db: Session = Depends(get_db),
) -> dict:
    exceptions = db.scalars(select(RiskException).where(RiskException.organization_id == org_id).order_by(RiskException.created_at.desc())).all()
    return {"items": [serialize(item) for item in exceptions]}


@router.post("/exceptions", status_code=201)
def create_exception(
    payload: ExceptionRequest,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.RISK_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    if payload.assessment_id:
        scoped_get(db, RiskAssessment, payload.assessment_id, org_id)
    exception = RiskException(
        organization_id=org_id,
        assessment_id=payload.assessment_id,
        reason=payload.reason,
        scope=payload.scope,
        requested_by=user.id,
        approved_by=user.id if user.is_super_admin else None,
        expires_at=payload.expires_at,
        status="approved" if user.is_super_admin else "pending",
    )
    db.add(exception)
    db.commit()
    return serialize(exception)


@router.get("/{assessment_id}")
def get_risk(
    assessment_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.RISK_READ)),
    db: Session = Depends(get_db),
) -> dict:
    assessment = scoped_get(db, RiskAssessment, assessment_id, org_id)
    scores = db.scalars(select(RiskScore).where(RiskScore.assessment_id == assessment.id).order_by(RiskScore.created_at.desc()).limit(20)).all()
    finding = db.get(Finding, assessment.finding_id) if assessment.finding_id else None
    exceptions = db.scalars(select(RiskException).where(RiskException.assessment_id == assessment.id)).all()
    return {
        **serialize(assessment),
        "finding": serialize(finding) if finding else None,
        "score_history": [serialize(score) for score in scores],
        "exceptions": [serialize(item) for item in exceptions],
        "model_documentation": "atlas-risk-v1: severity + exposure + criticality + exploitation + sensitivity + age",
    }


@router.post("/{assessment_id}/accept")
def accept_risk(
    assessment_id: uuid.UUID,
    payload: AcceptRiskRequest,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.RISK_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    assessment = scoped_get(db, RiskAssessment, assessment_id, org_id)
    assessment.status = "accepted"
    assessment.accepted_by = user.id
    assessment.accepted_at = datetime.now(UTC)
    db.add(
        RiskException(
            organization_id=org_id,
            assessment_id=assessment.id,
            reason=payload.reason,
            scope="assessment",
            requested_by=user.id,
            approved_by=user.id,
            expires_at=payload.expires_at,
            status="approved",
        )
    )
    if assessment.finding_id:
        finding = db.get(Finding, assessment.finding_id)
        if finding:
            finding.status = "risk_accepted"
    record_audit(db, user=user, action="risk.accepted", resource_type="risk_assessment", resource_id=assessment.id, details={"reason": payload.reason}, request=request)
    db.commit()
    return serialize(assessment)


@router.patch("/{assessment_id}")
def assign_risk(
    assessment_id: uuid.UUID,
    payload: AssignRiskRequest,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.RISK_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    assessment = scoped_get(db, RiskAssessment, assessment_id, org_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(assessment, field, value)
    db.commit()
    return serialize(assessment)


@remediation_router.get("")
def list_tasks(
    params: PageParams = Depends(page_params),
    status: str | None = None,
    assigned_to: uuid.UUID | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.RISK_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(RemediationTask).where(RemediationTask.organization_id == org_id)
    if status:
        stmt = stmt.where(RemediationTask.status == status)
    if assigned_to:
        stmt = stmt.where(RemediationTask.assigned_to == assigned_to)
    items, meta = paginate(
        db,
        stmt,
        params,
        RemediationTask,
        search_fields=[RemediationTask.title, RemediationTask.description],
        sortable={"due_at": RemediationTask.due_at, "priority": RemediationTask.priority, "created_at": RemediationTask.created_at},
        default_sort=RemediationTask.created_at,
    )
    return page_response(items, meta)


@remediation_router.post("", status_code=201)
def create_task(
    payload: RemediationCreate,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.RISK_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    if payload.finding_id:
        scoped_get(db, Finding, payload.finding_id, org_id)
    task = RemediationTask(organization_id=org_id, **payload.model_dump())
    db.add(task)
    db.commit()
    return serialize(task)


@remediation_router.patch("/{task_id}")
def update_task(
    task_id: uuid.UUID,
    payload: RemediationUpdate,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.RISK_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    task = scoped_get(db, RemediationTask, task_id, org_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(task, field, value)
    if payload.status == "completed":
        task.completed_at = datetime.now(UTC)
        if task.finding_id:
            finding = db.get(Finding, task.finding_id)
            if finding and finding.status not in {"resolved", "closed"}:
                finding.status = "resolved"
                finding.resolved_at = datetime.now(UTC)
    db.commit()
    return serialize(task)
