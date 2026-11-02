from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models.findings import Finding
from app.database.models.infrastructure import Asset, Microservice
from app.database.models.risk import RemediationTask, RiskAssessment, RiskScore
from app.modules.risk_engine.scoring import compute_finding_risk, sla_due


def recompute_assessments(db: Session, organization_id: uuid.UUID, finding_id: uuid.UUID | None = None) -> int:
    stmt = select(Finding).where(Finding.organization_id == organization_id, Finding.deleted_at.is_(None))
    if finding_id:
        stmt = stmt.where(Finding.id == finding_id)
    else:
        stmt = stmt.where(Finding.status.in_(("open", "triaged", "in_progress", "assigned")))
    findings = db.scalars(stmt).all()
    updated = 0
    service_ids: set[uuid.UUID] = set()
    asset_ids: set[uuid.UUID] = set()
    for finding in findings:
        asset = db.get(Asset, finding.asset_id) if finding.asset_id else None
        service = db.get(Microservice, finding.microservice_id) if finding.microservice_id else None
        score, severity, factors = compute_finding_risk(
            severity=finding.severity,
            exposure=finding.exposure,
            criticality=(asset.criticality if asset else None) or (service.criticality if service else "medium"),
            known_exploited=finding.exploitability == "known_exploited",
            exploit_available=finding.exploitability == "exploit_available",
            sensitive_data=finding.category == "sensitive_data",
            first_seen=finding.first_seen,
            remediation_available=bool(finding.remediation),
            cvss_score=finding.cvss_score,
        )
        finding.risk_score = score
        assessment = db.scalar(
            select(RiskAssessment).where(
                RiskAssessment.organization_id == organization_id,
                RiskAssessment.finding_id == finding.id,
            )
        )
        if assessment is None:
            assessment = RiskAssessment(
                organization_id=organization_id,
                finding_id=finding.id,
                asset_id=finding.asset_id,
                microservice_id=finding.microservice_id,
                business_unit=finding.business_unit,
                responsible_team=(service.name if service else None),
                remediation_deadline=sla_due(finding.severity, finding.first_seen),
                rationale={"factors": factors, "policy": "atlas-risk-v1"},
            )
            db.add(assessment)
            db.flush()
        assessment.score = score
        assessment.severity = severity
        assessment.business_unit = finding.business_unit or (service.business_unit if service else None)
        assessment.rationale = {"factors": factors, "policy": "atlas-risk-v1", "explanation": _explain(factors)}
        assessment.remediation_deadline = sla_due(finding.severity, finding.first_seen)
        db.add(RiskScore(organization_id=organization_id, assessment_id=assessment.id, factors=factors, score=score, computed_at=datetime.now(UTC)))
        if finding.status in {"resolved", "closed", "false_positive"}:
            assessment.status = "closed"
        if not db.scalar(select(RemediationTask.id).where(RemediationTask.finding_id == finding.id)):
            db.add(
                RemediationTask(
                    organization_id=organization_id,
                    finding_id=finding.id,
                    title=f"Remediate {finding.finding_ref}: {finding.title}"[:300],
                    description=finding.remediation,
                    assigned_to=finding.assigned_to,
                    priority=finding.severity,
                    due_at=sla_due(finding.severity, finding.first_seen),
                    status="open",
                )
            )
        updated += 1
        if finding.microservice_id:
            service_ids.add(finding.microservice_id)
        if finding.asset_id:
            asset_ids.add(finding.asset_id)
    db.flush()

    for service_id in service_ids:
        service = db.get(Microservice, service_id)
        if service is None:
            continue
        scores = db.execute(
            select(Finding.risk_score).where(
                Finding.microservice_id == service_id,
                Finding.status.in_(("open", "triaged", "in_progress", "assigned")),
                Finding.deleted_at.is_(None),
            )
        ).scalars().all()
        service.risk_score = round(sum(scores) / len(scores), 1) if scores else 0.0
        service.risk_level = (
            "critical" if service.risk_score >= 85 else "high" if service.risk_score >= 65 else "medium" if service.risk_score >= 40 else "low"
        )
        service.last_assessed_at = datetime.now(UTC)
        service.security_posture = "at_risk" if scores else "healthy"
    for asset_id in asset_ids:
        asset = db.get(Asset, asset_id)
        if asset is None:
            continue
        scores = db.execute(
            select(Finding.risk_score).where(
                Finding.asset_id == asset_id,
                Finding.status.in_(("open", "triaged", "in_progress", "assigned")),
                Finding.deleted_at.is_(None),
            )
        ).scalars().all()
        asset.risk_score = round(sum(scores) / len(scores), 1) if scores else 0.0

    db.commit()
    return updated


def _explain(factors: dict) -> str:
    return " + ".join(f"{key.replace('_', ' ')} {value:+g}" for key, value in factors.items()) + " (clamped to 0-100)"
