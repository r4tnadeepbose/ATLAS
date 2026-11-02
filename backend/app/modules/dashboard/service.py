import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.core.time import iso
from app.database.models.api_inventory import Api
from app.database.models.findings import Finding
from app.database.models.identity import AuditLog
from app.database.models.infrastructure import Asset, Microservice
from app.database.models.ops import Notification
from app.database.models.risk import RemediationTask, RiskAssessment
from app.database.models.sbom import (
    ComponentVulnerability,
    SbomDocument,
    VulnerabilityRecord,
)
from app.database.models.scans import ScanJob
from app.modules.risk_engine.scoring import posture_from_findings

OPEN_STATUSES = ("open", "triaged", "in_progress", "assigned", "accepted")
RESOLVED_STATUSES = ("resolved", "closed")
SEVERITIES = ("critical", "high", "medium", "low", "info")


def _count(db: Session, stmt) -> int:
    return int(db.scalar(stmt) or 0)


def overview(db: Session, org_id: uuid.UUID) -> dict:
    now = datetime.now(UTC)
    week_ago = now - timedelta(days=7)

    severity_rows = db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.organization_id == org_id, Finding.deleted_at.is_(None))
        .group_by(Finding.severity)
    ).all()
    severity_counts = {sev: 0 for sev in SEVERITIES}
    severity_counts.update({row[0]: row[1] for row in severity_rows})

    status_rows = db.execute(
        select(Finding.status, func.count(Finding.id))
        .where(Finding.organization_id == org_id, Finding.deleted_at.is_(None))
        .group_by(Finding.status)
    ).all()
    status_counts = {row[0]: row[1] for row in status_rows}

    open_count = sum(count for status, count in status_counts.items() if status in OPEN_STATUSES)
    resolved_count = sum(count for status, count in status_counts.items() if status in RESOLVED_STATUSES)

    all_open = db.scalars(
        select(Finding).where(
            Finding.organization_id == org_id,
            Finding.deleted_at.is_(None),
            Finding.status.in_(OPEN_STATUSES),
        )
    ).all()
    posture = posture_from_findings(all_open)

    microservice_total = _count(
        db, select(func.count(Microservice.id)).where(Microservice.organization_id == org_id, Microservice.status == "active", Microservice.deleted_at.is_(None))
    )
    sbom_services = _count(
        db,
        select(func.count(func.distinct(SbomDocument.microservice_id))).where(
            SbomDocument.organization_id == org_id, SbomDocument.microservice_id.is_not(None)
        ),
    )
    sbom_coverage = round((sbom_services / microservice_total) * 100, 1) if microservice_total else 0.0

    asset_total = _count(db, select(func.count(Asset.id)).where(Asset.organization_id == org_id, Asset.deleted_at.is_(None)))
    api_total = _count(db, select(func.count(Api.id)).where(Api.organization_id == org_id, Api.deleted_at.is_(None)))
    active_scans = _count(
        db, select(func.count(ScanJob.id)).where(ScanJob.organization_id == org_id, ScanJob.status.in_(("queued", "running")))
    )
    new_assets = _count(
        db, select(func.count(Asset.id)).where(Asset.organization_id == org_id, Asset.first_seen >= week_ago, Asset.deleted_at.is_(None))
    )
    recent_cves = _count(
        db,
        select(func.count(VulnerabilityRecord.id)).where(VulnerabilityRecord.created_at >= week_ago),
    )

    resolved_recent = db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.organization_id == org_id, Finding.resolved_at.is_not(None), Finding.resolved_at >= week_ago)
        .group_by(Finding.severity)
    ).all()
    resolved_week = sum(row[1] for row in resolved_recent)
    created_week = _count(
        db, select(func.count(Finding.id)).where(Finding.organization_id == org_id, Finding.first_seen >= week_ago)
    )

    # MTTD measures intelligence-ingestion → finding-generation latency, so the
    # reference is when the vulnerability record entered ATLAS (created_at), not
    # its original publication date.
    mttd_rows = db.execute(
        select(Finding.first_seen, VulnerabilityRecord.created_at)
        .join(VulnerabilityRecord, Finding.vulnerability_id == VulnerabilityRecord.id)
        .where(Finding.organization_id == org_id, Finding.first_seen.is_not(None), VulnerabilityRecord.created_at.is_not(None))
        .limit(500)
    ).all()
    mttd_values = []
    for first_seen, published in mttd_rows:
        if first_seen and published:
            a = first_seen if first_seen.tzinfo else first_seen.replace(tzinfo=UTC)
            b = published if published.tzinfo else published.replace(tzinfo=UTC)
            delta = (a - b).total_seconds() / 60
            if delta >= 0:
                mttd_values.append(delta)
    mttr_rows = db.execute(
        select(Finding.first_seen, Finding.resolved_at)
        .where(Finding.organization_id == org_id, Finding.resolved_at.is_not(None), Finding.first_seen.is_not(None))
        .limit(500)
    ).all()
    mttr_values = []
    for first_seen, resolved in mttr_rows:
        if first_seen and resolved:
            a = resolved if resolved.tzinfo else resolved.replace(tzinfo=UTC)
            b = first_seen if first_seen.tzinfo else first_seen.replace(tzinfo=UTC)
            mttr_values.append((a - b).total_seconds() / 3600)

    return {
        "counts": {
            "assets": asset_total,
            "microservices": microservice_total,
            "apis": api_total,
            "findings": sum(severity_counts.values()),
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "informational": severity_counts.get("info", 0),
            "unresolved": open_count,
            "resolved": resolved_count,
            "sbom_documents": _count(
                db, select(func.count(SbomDocument.id)).where(SbomDocument.organization_id == org_id)
            ),
            "posture_score": posture,
            "active_scans": active_scans,
            "open_incidents": _count(
                db,
                select(func.count(Finding.id)).where(
                    Finding.organization_id == org_id,
                    Finding.severity.in_(("critical", "high")),
                    Finding.status.in_(OPEN_STATUSES),
                ),
            ),
            "new_assets_7d": new_assets,
            "recent_cves_7d": recent_cves,
            "mttd_minutes": round(sum(mttd_values) / len(mttd_values), 1) if mttd_values else None,
            "mttr_hours": round(sum(mttr_values) / len(mttr_values), 1) if mttr_values else None,
            "sbom_coverage": sbom_coverage,
            "findings_created_7d": created_week,
            "findings_resolved_7d": resolved_week,
        },
        "severity_distribution": [{"severity": sev, "count": severity_counts.get(sev, 0)} for sev in SEVERITIES],
        "status_distribution": [{"status": status, "count": count} for status, count in sorted(status_counts.items())],
    }


def posture_trend(db: Session, org_id: uuid.UUID, weeks: int = 12) -> list[dict]:
    now = datetime.now(UTC)
    points = []
    for offset in range(weeks - 1, -1, -1):
        window_end = now - timedelta(weeks=offset)
        window_start = window_end - timedelta(weeks=1)
        findings = db.scalars(
            select(Finding).where(
                Finding.organization_id == org_id,
                Finding.deleted_at.is_(None),
                Finding.first_seen < window_end,
            )
        ).all()
        open_at = [f for f in findings if not (f.resolved_at and (f.resolved_at if f.resolved_at.tzinfo else f.resolved_at.replace(tzinfo=UTC)) < window_end)]
        points.append(
            {
                "week": window_start.date().isoformat(),
                "posture": posture_from_findings(open_at),
                "open_findings": len(open_at),
                "new_findings": len([f for f in findings if f.first_seen and (f.first_seen if f.first_seen.tzinfo else f.first_seen.replace(tzinfo=UTC)) >= window_start]),
            }
        )
    return points


def discovery_timeline(db: Session, org_id: uuid.UUID, days: int = 30) -> list[dict]:
    since = datetime.now(UTC) - timedelta(days=days)
    rows = db.execute(
        select(func.date(Finding.first_seen), Finding.severity, func.count(Finding.id))
        .where(Finding.organization_id == org_id, Finding.first_seen >= since)
        .group_by(func.date(Finding.first_seen), Finding.severity)
    ).all()
    buckets: dict[str, dict] = {}
    for day, severity, count in rows:
        key = str(day)
        buckets.setdefault(key, {"date": key, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
        buckets[key][severity] = buckets[key].get(severity, 0) + count
    return [buckets[key] for key in sorted(buckets)]


def exposure_distribution(db: Session, org_id: uuid.UUID) -> list[dict]:
    rows = db.execute(
        select(Asset.exposure, func.count(Asset.id))
        .where(Asset.organization_id == org_id, Asset.deleted_at.is_(None))
        .group_by(Asset.exposure)
    ).all()
    return [{"name": row[0] or "unknown", "value": row[1]} for row in rows]


def risk_by_business_unit(db: Session, org_id: uuid.UUID) -> list[dict]:
    rows = db.execute(
        select(Finding.business_unit, Finding.severity, func.count(Finding.id))
        .where(Finding.organization_id == org_id, Finding.business_unit.is_not(None), Finding.deleted_at.is_(None))
        .group_by(Finding.business_unit, Finding.severity)
    ).all()
    units: dict[str, dict] = {}
    for unit, severity, count in rows:
        entry = units.setdefault(unit, {"business_unit": unit, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0})
        entry[severity] = entry.get(severity, 0) + count
        entry["total"] += count
    return sorted(units.values(), key=lambda item: item["total"], reverse=True)


def top_vulnerable_services(db: Session, org_id: uuid.UUID, limit: int = 8) -> list[dict]:
    rows = db.execute(
        select(
            Microservice.id,
            Microservice.name,
            Microservice.business_unit,
            Microservice.criticality,
            Microservice.risk_score,
            func.count(Finding.id),
            func.sum(case((Finding.severity == "critical", 1), else_=0)),
        )
        .join(Finding, Finding.microservice_id == Microservice.id)
        .where(
            Microservice.organization_id == org_id,
            Microservice.deleted_at.is_(None),
            Finding.deleted_at.is_(None),
            Finding.status.in_(OPEN_STATUSES),
            Finding.risk_score > 0,
        )
        .group_by(Microservice.id, Microservice.name, Microservice.business_unit, Microservice.criticality, Microservice.risk_score)
        .order_by(func.count(Finding.id).desc())
        .limit(limit)
    ).all()
    return [
        {
            "id": str(row[0]),
            "name": row[1],
            "business_unit": row[2],
            "criticality": row[3],
            "risk_score": row[4],
            "open_findings": row[5],
            "critical_findings": int(row[6] or 0),
        }
        for row in rows
    ]


def api_security_distribution(db: Session, org_id: uuid.UUID) -> list[dict]:
    rows = db.execute(
        select(Api.security_status, func.count(Api.id))
        .where(Api.organization_id == org_id, Api.deleted_at.is_(None))
        .group_by(Api.security_status)
    ).all()
    return [{"name": row[0] or "unreviewed", "value": row[1]} for row in rows]


def remediation_progress(db: Session, org_id: uuid.UUID) -> list[dict]:
    rows = db.execute(
        select(RemediationTask.status, func.count(RemediationTask.id))
        .where(RemediationTask.organization_id == org_id)
        .group_by(RemediationTask.status)
    ).all()
    return [{"name": row[0], "value": row[1]} for row in rows]


def recent_activity(db: Session, org_id: uuid.UUID, limit: int = 20) -> list[dict]:
    events = []
    findings = db.scalars(
        select(Finding).where(Finding.organization_id == org_id, Finding.deleted_at.is_(None)).order_by(Finding.created_at.desc()).limit(limit)
    ).all()
    for finding in findings:
        events.append(
            {
                "type": "finding",
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "timestamp": iso(finding.created_at),
                "reference": finding.finding_ref,
                "link": f"/vulnerabilities/{finding.id}",
            }
        )
    audits = db.scalars(
        select(AuditLog)
        .where(
            AuditLog.organization_id == org_id,
            AuditLog.action.notin_(("auth.login", "auth.logout", "auth.refresh")),
        )
        .order_by(AuditLog.created_at.desc())
        .limit(max(4, limit // 3))
    ).all()
    for entry in audits:
        events.append(
            {
                "type": "audit",
                "title": entry.action.replace(".", " ").replace("_", " ").title(),
                "severity": "info",
                "status": entry.outcome,
                "timestamp": iso(entry.created_at),
                "reference": entry.resource_type,
                "link": None,
            }
        )
    events.sort(key=lambda item: item["timestamp"] or "", reverse=True)
    return events[:limit]


def vulnerability_dashboard(db: Session, org_id: uuid.UUID) -> dict:
    severities = dict(
        db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.organization_id == org_id, Finding.category.like("%dependency%"), Finding.deleted_at.is_(None))
            .group_by(Finding.severity)
        ).all()
    )
    components = _count(
        db,
        select(func.count(func.distinct(ComponentVulnerability.component_id))).where(ComponentVulnerability.organization_id == org_id),
    )
    top_components = db.execute(
        select(ComponentVulnerability.component_id, func.count(ComponentVulnerability.id))
        .where(ComponentVulnerability.organization_id == org_id)
        .group_by(ComponentVulnerability.component_id)
        .order_by(func.count(ComponentVulnerability.id).desc())
        .limit(10)
    ).all()
    from app.database.models.sbom import SbomComponent

    names = []
    for component_id, count in top_components:
        component = db.get(SbomComponent, component_id)
        names.append(
            {
                "component": component.name if component else "unknown",
                "version": component.version if component else None,
                "vulnerabilities": count,
            }
        )
    return {
        "dependency_findings_by_severity": [{"name": key, "value": value} for key, value in severities.items()],
        "vulnerable_components": components,
        "top_vulnerable_components": names,
    }


def risk_trends(db: Session, org_id: uuid.UUID) -> dict:
    rows = db.execute(
        select(func.date(RiskAssessment.created_at), func.avg(RiskAssessment.score))
        .where(RiskAssessment.organization_id == org_id)
        .group_by(func.date(RiskAssessment.created_at))
        .order_by(func.date(RiskAssessment.created_at))
    ).all()
    return {"items": [{"date": str(row[0]), "average_score": round(float(row[1] or 0), 1)} for row in rows]}
