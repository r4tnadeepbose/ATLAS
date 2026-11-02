import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.api.dependencies import PageParams, get_db, get_org_id, page_params, paginate, page_response, serialize
from app.core.audit import record_audit
from app.core.exceptions import NotFoundError
from app.core.permissions import Permission, User, require_permissions
from app.core.tenancy import scoped_get
from app.database.models.findings import (
    Finding,
    FindingAssignment,
    FindingComment,
    FindingEvidence,
    FindingException,
    FindingStatusHistory,
)
from app.database.models.identity import User as UserModel
from app.database.models.infrastructure import Asset, Microservice
from app.database.models.sbom import VulnerabilityRecord
from app.modules.risk_engine.scoring import compute_finding_risk, sla_due

router = APIRouter(prefix="/findings", tags=["Vulnerability Management"])
vuln_router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Intelligence"])

VALID_STATUSES = {"open", "triaged", "in_progress", "assigned", "resolved", "risk_accepted", "false_positive", "closed"}


class FindingUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None
    assigned_to: uuid.UUID | None = None
    remediation: str | None = None
    note: str | None = None


class CommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class EvidenceCreate(BaseModel):
    kind: str = "text"
    content: str = Field(min_length=1, max_length=20000)
    location: str | None = None


class AssignRequest(BaseModel):
    assignee_id: uuid.UUID
    note: str | None = None


class ExceptionRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)
    scope: str = "finding"
    expires_at: datetime | None = None


def _filters(stmt, **kwargs):
    if kwargs.get("severity"):
        stmt = stmt.where(Finding.severity == kwargs["severity"])
    if kwargs.get("status"):
        stmt = stmt.where(Finding.status == kwargs["status"])
    if kwargs.get("category"):
        stmt = stmt.where(Finding.category == kwargs["category"])
    if kwargs.get("source_module"):
        stmt = stmt.where(Finding.source_module == kwargs["source_module"])
    if kwargs.get("asset_id"):
        stmt = stmt.where(Finding.asset_id == kwargs["asset_id"])
    if kwargs.get("microservice_id"):
        stmt = stmt.where(Finding.microservice_id == kwargs["microservice_id"])
    if kwargs.get("assigned_to"):
        stmt = stmt.where(Finding.assigned_to == kwargs["assigned_to"])
    if kwargs.get("business_unit"):
        stmt = stmt.where(Finding.business_unit == kwargs["business_unit"])
    if kwargs.get("environment_id"):
        stmt = stmt.where(Finding.environment_id == kwargs["environment_id"])
    if kwargs.get("open_only"):
        stmt = stmt.where(Finding.status.in_(("open", "triaged", "in_progress", "assigned")))
    return stmt


@router.get("")
def list_findings(
    params: PageParams = Depends(page_params),
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    source_module: str | None = None,
    asset_id: uuid.UUID | None = None,
    microservice_id: uuid.UUID | None = None,
    assigned_to: uuid.UUID | None = None,
    business_unit: str | None = None,
    environment_id: uuid.UUID | None = None,
    open_only: bool = False,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.FINDING_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(Finding).where(Finding.organization_id == org_id, Finding.deleted_at.is_(None))
    stmt = _filters(
        stmt,
        severity=severity,
        status=status,
        category=category,
        source_module=source_module,
        asset_id=asset_id,
        microservice_id=microservice_id,
        assigned_to=assigned_to,
        business_unit=business_unit,
        environment_id=environment_id,
        open_only=open_only,
    )
    items, meta = paginate(
        db,
        stmt,
        params,
        Finding,
        search_fields=[Finding.title, Finding.finding_ref, Finding.cve_id, Finding.business_unit, Finding.location],
        sortable={"risk_score": Finding.risk_score, "severity": Finding.severity, "first_seen": Finding.first_seen, "status": Finding.status},
        default_sort=Finding.risk_score,
    )
    assets = {asset.id: asset.name for asset in db.scalars(select(Asset).where(Asset.organization_id == org_id)).all()}
    services = {
        service.id: service.name for service in db.scalars(select(Microservice).where(Microservice.organization_id == org_id)).all()
    }
    return {
        "items": [
            {
                **serialize(item),
                "asset_name": assets.get(item.asset_id),
                "microservice_name": services.get(item.microservice_id),
            }
            for item in items
        ],
        "pagination": meta,
    }


@router.get("/summary")
def findings_summary(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.FINDING_READ)),
    db: Session = Depends(get_db),
) -> dict:
    by_severity = dict(
        db.execute(
            select(Finding.severity, func.count(Finding.id)).where(Finding.organization_id == org_id, Finding.deleted_at.is_(None)).group_by(Finding.severity)
        ).all()
    )
    by_status = dict(
        db.execute(
            select(Finding.status, func.count(Finding.id)).where(Finding.organization_id == org_id, Finding.deleted_at.is_(None)).group_by(Finding.status)
        ).all()
    )
    by_category = dict(
        db.execute(
            select(Finding.category, func.count(Finding.id)).where(Finding.organization_id == org_id, Finding.deleted_at.is_(None)).group_by(Finding.category)
        ).all()
    )
    overdue = db.scalar(
        select(func.count(Finding.id)).where(
            Finding.organization_id == org_id,
            Finding.deleted_at.is_(None),
            Finding.status.in_(("open", "triaged", "in_progress", "assigned")),
            Finding.sla_due_at < datetime.now(UTC),
        )
    ) or 0
    return {
        "by_severity": [{"name": key, "value": value} for key, value in by_severity.items()],
        "by_status": [{"name": key, "value": value} for key, value in by_status.items()],
        "by_category": [{"name": key, "value": value} for key, value in by_category.items()],
        "total": sum(by_severity.values()),
        "overdue": overdue,
        "unassigned": db.scalar(
            select(func.count(Finding.id)).where(
                Finding.organization_id == org_id,
                Finding.deleted_at.is_(None),
                Finding.assigned_to.is_(None),
                Finding.status.in_(("open", "triaged", "in_progress")),
            )
        ) or 0,
    }


@router.get("/{finding_id}")
def get_finding(
    finding_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.FINDING_READ)),
    db: Session = Depends(get_db),
) -> dict:
    finding = scoped_get(db, Finding, finding_id, org_id)
    evidence = db.scalars(select(FindingEvidence).where(FindingEvidence.finding_id == finding.id)).all()
    comments = db.scalars(select(FindingComment).where(FindingComment.finding_id == finding.id).order_by(FindingComment.created_at)).all()
    history = db.scalars(select(FindingStatusHistory).where(FindingStatusHistory.finding_id == finding.id).order_by(FindingStatusHistory.created_at)).all()
    assignments = db.scalars(select(FindingAssignment).where(FindingAssignment.finding_id == finding.id).order_by(FindingAssignment.created_at.desc())).all()
    exceptions = db.scalars(select(FindingException).where(FindingException.finding_id == finding.id).order_by(FindingException.created_at.desc())).all()
    asset = db.get(Asset, finding.asset_id) if finding.asset_id else None
    service = db.get(Microservice, finding.microservice_id) if finding.microservice_id else None
    vulnerability = db.get(VulnerabilityRecord, finding.vulnerability_id) if finding.vulnerability_id else None
    assignee = db.get(UserModel, finding.assigned_to) if finding.assigned_to else None
    from app.database.models.ops import AiTriageResult

    triage = db.scalars(
        select(AiTriageResult).where(AiTriageResult.finding_id == finding.id).order_by(AiTriageResult.created_at.desc()).limit(5)
    ).all()
    return {
        **serialize(finding),
        "asset": {"id": str(asset.id), "name": asset.name, "domain": asset.domain, "exposure": asset.exposure} if asset else None,
        "microservice": {"id": str(service.id), "name": service.name, "business_unit": service.business_unit} if service else None,
        "vulnerability": serialize(vulnerability) if vulnerability else None,
        "assignee": {"id": str(assignee.id), "full_name": assignee.full_name, "email": assignee.email} if assignee else None,
        "evidence": [serialize(item) for item in evidence],
        "comments": [serialize(item) for item in comments],
        "history": [serialize(item) for item in history],
        "assignments": [serialize(item) for item in assignments],
        "exceptions": [serialize(item) for item in exceptions],
        "ai_triage": [serialize(item) for item in triage],
    }


@router.patch("/{finding_id}")
def update_finding(
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.FINDING_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    finding = scoped_get(db, Finding, finding_id, org_id)
    if payload.status is not None and payload.status not in VALID_STATUSES:
        from app.core.exceptions import ValidationError

        raise ValidationError("Unsupported status", details={"allowed": sorted(VALID_STATUSES)})
    if payload.status and payload.status != finding.status:
        previous = finding.status
        finding.status = payload.status
        if payload.status in {"resolved", "closed"}:
            finding.resolved_at = datetime.now(UTC)
        elif previous in {"resolved", "closed"}:
            finding.resolved_at = None
        db.add(
            FindingStatusHistory(
                organization_id=org_id,
                finding_id=finding.id,
                from_status=previous,
                to_status=payload.status,
                changed_by=user.id,
                note=payload.note,
            )
        )
    if payload.severity:
        finding.severity = payload.severity
        finding.sla_due_at = sla_due(payload.severity, finding.first_seen)
    if payload.assigned_to is not None:
        assignee = db.get(UserModel, payload.assigned_to)
        if assignee is None or assignee.organization_id != org_id:
            raise NotFoundError("Assignee not found")
        finding.assigned_to = payload.assigned_to
    if payload.remediation is not None:
        finding.remediation = payload.remediation
    if payload.status == "false_positive" and payload.note:
        finding.confidence = 0.2

    severity = finding.severity
    asset = db.get(Asset, finding.asset_id) if finding.asset_id else None
    service = db.get(Microservice, finding.microservice_id) if finding.microservice_id else None
    risk, _band, _factors = compute_finding_risk(
        severity=severity,
        exposure=finding.exposure,
        criticality=(asset.criticality if asset else None) or (service.criticality if service else "medium"),
        known_exploited=finding.exploitability == "known_exploited",
        exploit_available=finding.exploitability == "exploit_available",
        first_seen=finding.first_seen,
        remediation_available=bool(finding.remediation),
        cvss_score=finding.cvss_score,
    )
    finding.risk_score = risk
    record_audit(db, user=user, action="finding.updated", resource_type="finding", resource_id=finding.id, details=payload.model_dump(exclude_unset=True), request=request)
    db.commit()
    _refresh_targets(db, finding)
    return serialize(finding)


def _refresh_targets(db: Session, finding: Finding) -> None:
    if finding.asset_id:
        asset = db.get(Asset, finding.asset_id)
        if asset:
            scores = db.execute(
                select(Finding.risk_score).where(
                    Finding.asset_id == asset.id,
                    Finding.status.in_(("open", "triaged", "in_progress", "assigned")),
                    Finding.deleted_at.is_(None),
                )
            ).scalars().all()
            asset.risk_score = round(sum(scores) / len(scores), 1) if scores else 0.0
    if finding.microservice_id:
        service = db.get(Microservice, finding.microservice_id)
        if service:
            scores = db.execute(
                select(Finding.risk_score).where(
                    Finding.microservice_id == service.id,
                    Finding.status.in_(("open", "triaged", "in_progress", "assigned")),
                    Finding.deleted_at.is_(None),
                )
            ).scalars().all()
            service.risk_score = round(sum(scores) / len(scores), 1) if scores else 0.0
            service.risk_level = "critical" if service.risk_score >= 85 else "high" if service.risk_score >= 65 else "medium" if service.risk_score >= 40 else "low"
    db.commit()


@router.post("/{finding_id}/comments", status_code=201)
def add_comment(
    finding_id: uuid.UUID,
    payload: CommentCreate,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.FINDING_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    scoped_get(db, Finding, finding_id, org_id)
    comment = FindingComment(organization_id=org_id, finding_id=finding_id, author_id=user.id, body=payload.body)
    db.add(comment)
    db.commit()
    return serialize(comment)


@router.post("/{finding_id}/evidence", status_code=201)
def add_evidence(
    finding_id: uuid.UUID,
    payload: EvidenceCreate,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.FINDING_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    scoped_get(db, Finding, finding_id, org_id)
    evidence = FindingEvidence(
        organization_id=org_id,
        finding_id=finding_id,
        kind=payload.kind,
        content=payload.content,
        location=payload.location,
        redacted=True,
    )
    db.add(evidence)
    db.commit()
    return serialize(evidence)


@router.post("/{finding_id}/assign")
def assign_finding(
    finding_id: uuid.UUID,
    payload: AssignRequest,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.FINDING_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    finding = scoped_get(db, Finding, finding_id, org_id)
    assignee = db.get(UserModel, payload.assignee_id)
    if assignee is None or assignee.organization_id != org_id:
        raise NotFoundError("Assignee not found")
    finding.assigned_to = assignee.id
    if finding.status == "open":
        finding.status = "assigned"
    db.add(
        FindingAssignment(
            organization_id=org_id,
            finding_id=finding.id,
            assignee_id=assignee.id,
            assigned_by=user.id,
            note=payload.note,
        )
    )
    db.add(
        FindingStatusHistory(
            organization_id=org_id,
            finding_id=finding.id,
            from_status="open",
            to_status="assigned",
            changed_by=user.id,
            note=f"Assigned to {assignee.full_name}",
        )
    )
    db.commit()
    return serialize(finding)


@router.post("/{finding_id}/exception")
def request_exception(
    finding_id: uuid.UUID,
    payload: ExceptionRequest,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.FINDING_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    scoped_get(db, Finding, finding_id, org_id)
    exception = FindingException(
        organization_id=org_id,
        finding_id=finding_id,
        reason=payload.reason,
        scope=payload.scope,
        approved_by=user.id if user.is_super_admin else None,
        expires_at=payload.expires_at,
        status="approved" if user.is_super_admin else "pending",
    )
    db.add(exception)
    db.commit()
    return serialize(exception)


@vuln_router.get("")
def list_vulnerabilities(
    params: PageParams = Depends(page_params),
    severity: str | None = None,
    source: str | None = None,
    exploited: bool | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.FINDING_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(VulnerabilityRecord)
    if severity:
        stmt = stmt.where(VulnerabilityRecord.severity == severity)
    if source:
        stmt = stmt.where(VulnerabilityRecord.source == source)
    if exploited is not None:
        stmt = stmt.where(VulnerabilityRecord.known_exploited == exploited)
    items, meta = paginate(
        db,
        stmt,
        params,
        VulnerabilityRecord,
        search_fields=[VulnerabilityRecord.identifier, VulnerabilityRecord.cve_id, VulnerabilityRecord.title],
        sortable={"cvss_score": VulnerabilityRecord.cvss_score, "published_at": VulnerabilityRecord.published_at, "severity": VulnerabilityRecord.severity},
        default_sort=VulnerabilityRecord.published_at,
    )
    return page_response(items, meta)


@vuln_router.get("/{vulnerability_id}")
def get_vulnerability(
    vulnerability_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.FINDING_READ)),
    db: Session = Depends(get_db),
) -> dict:
    vulnerability = db.get(VulnerabilityRecord, vulnerability_id)
    if vulnerability is None:
        raise NotFoundError("Vulnerability not found")
    affected = db.scalars(
        select(Finding).where(Finding.organization_id == org_id, Finding.vulnerability_id == vulnerability.id).limit(100)
    ).all()
    return {**serialize(vulnerability), "affected_findings": [serialize(item) for item in affected]}


@vuln_router.post("/lookup/{identifier}")
def lookup_vulnerability(
    identifier: str,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.FINDING_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    from app.integrations.osv.adapter import OsvAdapter

    raw = OsvAdapter().get(identifier)
    from app.modules.sbom.service import _upsert_vulnerability

    record = _upsert_vulnerability(db, raw)
    db.commit()
    return serialize(record)
