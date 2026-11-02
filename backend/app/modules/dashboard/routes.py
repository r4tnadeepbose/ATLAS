from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, get_org_id
from app.core.permissions import Permission, User, require_permissions
from app.core.time import iso
from app.database.models.findings import Finding
from app.database.models.ops import BackgroundJob
from app.database.models.risk import RemediationTask, RiskAssessment
from app.modules.dashboard import service

router = APIRouter(prefix="/dashboard", tags=["ATLAS Command"])


@router.get("/overview")
def overview(
    org_id=Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.DASHBOARD_READ)),
    db: Session = Depends(get_db),
) -> dict:
    return service.overview(db, org_id)


@router.get("/vulnerabilities")
def vulnerabilities(
    org_id=Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.DASHBOARD_READ)),
    db: Session = Depends(get_db),
) -> dict:
    return service.vulnerability_dashboard(db, org_id)


@router.get("/risk-trends")
def risk_trends(
    org_id=Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.DASHBOARD_READ)),
    db: Session = Depends(get_db),
) -> dict:
    return {
        **service.risk_trends(db, org_id),
        "posture": service.posture_trend(db, org_id),
        "discovery": service.discovery_timeline(db, org_id),
        "exposure": service.exposure_distribution(db, org_id),
        "business_units": service.risk_by_business_unit(db, org_id),
        "api_security": service.api_security_distribution(db, org_id),
        "remediation": service.remediation_progress(db, org_id),
    }


@router.get("/activity")
def activity(
    limit: int = 20,
    org_id=Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.DASHBOARD_READ)),
    db: Session = Depends(get_db),
) -> dict:
    return {"items": service.recent_activity(db, org_id, limit)}


@router.get("/executive")
def executive(
    org_id=Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.EXECUTIVE_READ)),
    db: Session = Depends(get_db),
) -> dict:
    data = service.overview(db, org_id)
    assessments = db.scalars(
        select(RiskAssessment).where(RiskAssessment.organization_id == org_id).order_by(RiskAssessment.score.desc()).limit(10)
    ).all()
    tasks = db.scalars(
        select(RemediationTask).where(RemediationTask.organization_id == org_id).limit(1000)
    ).all()
    all_assessments = db.scalars(select(RiskAssessment).where(RiskAssessment.organization_id == org_id)).all()
    risk_scores = [assessment.score for assessment in all_assessments if assessment.status != "closed"]
    risk_by_unit = [
        {"name": row[0] or "Unassigned", "average": round(float(row[1] or 0), 1), "count": row[2]}
        for row in db.execute(
            select(RiskAssessment.business_unit, func.avg(RiskAssessment.score), func.count(RiskAssessment.id))
            .where(RiskAssessment.organization_id == org_id, RiskAssessment.status != "closed")
            .group_by(RiskAssessment.business_unit)
        ).all()
    ]
    task_breakdown: dict[str, int] = {}
    for task in tasks:
        task_breakdown[task.status] = task_breakdown.get(task.status, 0) + 1

    finding_ids = [assessment.finding_id for assessment in assessments if assessment.finding_id]
    linked_findings = {
        finding.id: finding
        for finding in db.scalars(
            select(Finding).where(Finding.organization_id == org_id, Finding.id.in_(finding_ids))
        ).all()
    }
    return {
        **data,
        "average_risk": round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0,
        "remediation": [{"name": key, "value": value} for key, value in sorted(task_breakdown.items())],
        "top_risks": [
            {
                "id": str(assessment.id),
                "score": assessment.score,
                "severity": assessment.severity,
                "title": assessment.business_impact
                or (linked_findings[assessment.finding_id].title if assessment.finding_id in linked_findings else None)
                or "Asset-level risk",
                "finding_ref": linked_findings[assessment.finding_id].finding_ref if assessment.finding_id in linked_findings else None,
                "business_impact": assessment.business_impact,
                "business_unit": assessment.business_unit,
                "status": assessment.status,
            }
            for assessment in assessments
        ],
        "remediation_open": len([task for task in tasks if task.status != "completed"]),
        "posture_trend": service.posture_trend(db, org_id),
        "business_units": service.risk_by_business_unit(db, org_id),
        "risk_by_unit": risk_by_unit,
        "top_services": service.top_vulnerable_services(db, org_id),
        "risk_trends": service.risk_trends(db, org_id)["items"],
    }


@router.get("/background-jobs")
def background_jobs(
    org_id=Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.DASHBOARD_READ)),
    db: Session = Depends(get_db),
) -> dict:
    jobs = db.scalars(
        select(BackgroundJob).where(BackgroundJob.organization_id == org_id).order_by(BackgroundJob.created_at.desc()).limit(20)
    ).all()
    return {
        "items": [
            {
                "id": str(job.id),
                "job_type": job.job_type,
                "status": job.status,
                "progress": job.progress,
                "created_at": iso(job.created_at),
            }
            for job in jobs
        ]
    }
