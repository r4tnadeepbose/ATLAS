"""SBOM ingestion and vulnerability correlation."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core.exceptions import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.core.refs import next_ref
from app.database.models.findings import Finding, FindingStatusHistory
from app.database.models.infrastructure import Asset, Microservice
from app.database.models.sbom import (
    ComponentRelationship,
    ComponentVulnerability,
    SbomComponent,
    SbomDocument,
    SbomScanHistory,
    VulnerabilityRecord,
)
from app.modules.notifications.service import emit
from app.modules.risk_engine.scoring import compute_finding_risk, sla_due
from app.modules.sbom.matching import (
    first_fixed_version,
    is_affected,
    parse_osv_timestamp,
    query_osv,
    severity_from_osv,
)
from app.modules.sbom.parsers import ParsedSbom, parse_sbom

logger = get_logger("sbom")


def ingest_sbom(
    db: Session,
    *,
    organization_id: uuid.UUID,
    uploaded_by: uuid.UUID | None,
    filename: str,
    content: bytes,
    microservice_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    version_label: str | None = None,
    source: str = "upload",
) -> SbomDocument:
    if len(content) == 0:
        raise ValidationError("SBOM file is empty")
    if len(content) > settings.max_upload_mb * 1024 * 1024:
        raise ValidationError(f"SBOM exceeds the {settings.max_upload_mb}MB upload limit")
    if microservice_id:
        service = db.get(Microservice, microservice_id)
        if service is None or service.organization_id != organization_id:
            raise NotFoundError("Microservice not found")
    if asset_id:
        asset = db.get(Asset, asset_id)
        if asset is None or asset.organization_id != organization_id:
            raise NotFoundError("Asset not found")

    parsed = parse_sbom(content, filename)
    checksum = hashlib.sha256(content).hexdigest()

    document = SbomDocument(
        organization_id=organization_id,
        name=parsed.name or filename,
        microservice_id=microservice_id,
        asset_id=asset_id,
        format=parsed.format,
        spec_version=parsed.spec_version,
        source=source,
        file_name=filename[:300],
        checksum=checksum,
        size_bytes=len(content),
        component_count=len(parsed.components),
        status="parsed",
        version_label=version_label,
        uploaded_by=uploaded_by,
        metadata_json={"parser": parsed.metadata, "storage": "not_retained"},
    )
    db.add(document)
    db.flush()

    by_uid: dict[str, SbomComponent] = {}
    for parsed_component in parsed.components:
        component = SbomComponent(
            organization_id=organization_id,
            sbom_id=document.id,
            component_uid=parsed_component.uid[:200],
            name=parsed_component.name[:250],
            version=(parsed_component.version or None),
            ecosystem=parsed_component.ecosystem,
            purl=parsed_component.purl,
            cpe=parsed_component.cpe,
            supplier=(parsed_component.supplier or None),
            license=(parsed_component.license or None),
            component_type=parsed_component.component_type,
            is_direct=parsed_component.is_direct,
        )
        db.add(component)
        by_uid[parsed_component.uid] = component
    db.flush()

    for parsed_component in parsed.components:
        parent = by_uid.get(parsed_component.uid)
        for child_uid in parsed_component.depends_on:
            child = by_uid.get(child_uid)
            if parent and child:
                db.add(
                    ComponentRelationship(
                        organization_id=organization_id,
                        sbom_id=document.id,
                        parent_component_id=parent.id,
                        child_component_id=child.id,
                        relationship_type="depends_on",
                    )
                )
    db.commit()
    return document


def _upsert_vulnerability(db: Session, raw: dict) -> VulnerabilityRecord:
    identifier = raw.get("id") or raw.get("cve_id") or "UNKNOWN"
    aliases = raw.get("aliases") or []
    cve_id = next((alias for alias in aliases if str(alias).startswith("CVE-")), None)
    if not cve_id and str(identifier).startswith("CVE-"):
        cve_id = identifier
    existing = db.scalar(
        select(VulnerabilityRecord).where(
            VulnerabilityRecord.source == "osv", VulnerabilityRecord.identifier == identifier
        )
    )
    affected = raw.get("affected") or []
    severity, score, vector = severity_from_osv(raw)
    values = {
        "cve_id": cve_id,
        "osv_id": identifier if str(identifier).startswith(("GHSA-", "OSV-", "PYSEC-", "RUSTSEC-")) else None,
        "title": (raw.get("summary") or identifier)[:300],
        "description": raw.get("details"),
        "cvss_score": score,
        "cvss_vector": vector,
        "severity": severity,
        "published_at": parse_osv_timestamp(raw.get("published")),
        "modified_at": parse_osv_timestamp(raw.get("modified")),
        "known_exploited": bool((raw.get("database_specific") or {}).get("known_exploited")),
        "source": "osv",
        "affected_packages": affected,
        "fixed_versions": [v for v in [first_fixed_version(affected)] if v],
        "references": [{"url": ref.get("url"), "type": ref.get("type")} for ref in raw.get("references") or []],
        "remediation": f"Upgrade to {first_fixed_version(affected)}" if first_fixed_version(affected) else "Apply the vendor advisory guidance.",
        "raw": {"aliases": aliases, "database_specific": raw.get("database_specific", {})},
    }
    if existing is None:
        existing = VulnerabilityRecord(identifier=identifier, **values)
        db.add(existing)
        db.flush()
    else:
        for key, value in values.items():
            setattr(existing, key, value)
    return existing


def correlate(
    db: Session,
    sbom: SbomDocument,
    *,
    use_online: bool = True,
) -> dict:
    if sbom.status == "analyzing":
        return {"status": "already_running"}
    sbom.status = "analyzing"
    history = SbomScanHistory(
        organization_id=sbom.organization_id,
        sbom_id=sbom.id,
        scan_type="analysis",
        status="running",
        started_at=datetime.now(UTC),
        triggered_by=sbom.uploaded_by,
    )
    db.add(history)
    db.commit()

    components = db.scalars(select(SbomComponent).where(SbomComponent.sbom_id == sbom.id)).all()
    online_matches: dict[str, list[dict]] = {}
    online_error = None
    if use_online:
        try:
            online_matches = asyncio.run(
                query_osv([(component.purl, component.version) for component in components])
            )
        except Exception as exc:  # noqa: BLE001 - degrade to offline correlation
            logger.warning("OSV correlation unavailable: %s", exc)
            online_error = str(exc)

    records: dict[uuid.UUID, VulnerabilityRecord] = {}
    for purl, vulns in online_matches.items():
        for raw in vulns:
            record = _upsert_vulnerability(db, raw)
            records[record.id] = record
    db.flush()

    offline_records = db.scalars(select(VulnerabilityRecord)).all()
    matched = 0
    created_findings = 0
    for component in components:
        matched_records: list[tuple[VulnerabilityRecord, dict]] = []
        for record in offline_records:
            for entry in record.affected_packages or []:
                package = entry.get("package") or {}
                same_purl = component.purl and package.get("purl") and package.get("purl") == component.purl
                same_name = (
                    (package.get("name") or "").lower() == component.name.lower()
                    and (package.get("ecosystem") or "").lower() == (component.ecosystem or "").lower()
                )
                if not (same_purl or same_name):
                    continue
                if is_affected(component.version, [entry]):
                    matched_records.append((record, entry))
                    break
        for record, entry in matched_records:
            existing_link = db.scalar(
                select(ComponentVulnerability).where(
                    ComponentVulnerability.component_id == component.id,
                    ComponentVulnerability.vulnerability_id == record.id,
                )
            )
            if existing_link is None:
                db.add(
                    ComponentVulnerability(
                        organization_id=sbom.organization_id,
                        component_id=component.id,
                        vulnerability_id=record.id,
                        sbom_id=sbom.id,
                        affected_version=component.version,
                        fixed_version=first_fixed_version([entry]),
                        status="open",
                        source=record.source,
                        matched_at=datetime.now(UTC),
                    )
                )
            matched += 1
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}
        component_vulns = [record for record, _ in matched_records]
        component.vulnerability_count = len(matched_records)
        component.highest_severity = max(
            (record.severity for record in component_vulns), key=lambda sev: severity_rank.get(sev, 0), default=None
        )

    db.commit()

    asset = db.get(Asset, sbom.asset_id) if sbom.asset_id else None
    service = db.get(Microservice, sbom.microservice_id) if sbom.microservice_id else None
    criticality = (asset.criticality if asset else None) or (service.criticality if service else "medium")
    exposure = (asset.exposure if asset else "internal") or "internal"

    links = db.scalars(
        select(ComponentVulnerability).where(ComponentVulnerability.sbom_id == sbom.id)
    ).all()
    for link in links:
        component = db.get(SbomComponent, link.component_id)
        record = db.get(VulnerabilityRecord, link.vulnerability_id)
        if component is None or record is None:
            continue
        dedup = f"dependency:{sbom.microservice_id or sbom.asset_id or 'unlinked'}:{component.name}@{component.version}:{record.cve_id or record.identifier}"
        finding = db.scalar(
            select(Finding).where(Finding.organization_id == sbom.organization_id, Finding.dedup_key == dedup)
        )
        first_seen = datetime.now(UTC)
        risk_score, risk_band, factors = compute_finding_risk(
            severity=record.severity,
            exposure=exposure,
            criticality=criticality,
            known_exploited=bool(record.known_exploited),
            exploit_available=bool(record.exploit_available),
            first_seen=first_seen,
            remediation_available=bool(link.fixed_version),
            cvss_score=record.cvss_score,
        )
        if finding is None:
            finding = Finding(
                organization_id=sbom.organization_id,
                finding_ref=next_ref(db, Finding, "finding_ref", "FND", sbom.organization_id),
                title=f"{record.cve_id or record.identifier} in {component.name} {component.version or ''}".strip(),
                description=record.description or record.title,
                category="dependency",
                source_module="sbom",
                severity=record.severity,
                cvss_score=record.cvss_score,
                status="open",
                asset_id=sbom.asset_id,
                microservice_id=sbom.microservice_id,
                component_id=component.id,
                vulnerability_id=record.id,
                cve_id=record.cve_id,
                business_unit=(service.business_unit if service else None) or (asset.business_unit if asset else None),
                environment_id=(service.environment_id if service else None) or (asset.environment_id if asset else None),
                exposure=exposure,
                exploitability="known_exploited" if record.known_exploited else ("exploit_available" if record.exploit_available else "unknown"),
                confidence=0.9,
                risk_score=risk_score,
                dedup_key=dedup,
                remediation=record.remediation,
                first_seen=first_seen,
                last_seen=first_seen,
                sla_due_at=sla_due(record.severity, first_seen),
                tags=[component.ecosystem or "unknown"],
            )
            db.add(finding)
            db.flush()
            db.add(
                FindingStatusHistory(
                    organization_id=sbom.organization_id,
                    finding_id=finding.id,
                    to_status="open",
                    note="Created by SBOM correlation",
                )
            )
            created_findings += 1
            if record.severity in {"critical", "high"}:
                emit(
                    db,
                    organization_id=sbom.organization_id,
                    event_key="vulnerable_dependency",
                    subject=f"{record.severity.upper()}: {component.name} vulnerability detected",
                    body=f"{record.cve_id or record.identifier} affects {component.name} {component.version or ''} in {service.name if service else 'an unlinked SBOM'}.",
                    severity=record.severity,
                    dedup_key=dedup,
                    metadata={"finding_id": str(finding.id)},
                )
        else:
            finding.last_seen = first_seen
            finding.risk_score = risk_score
            finding.severity = record.severity
            finding.cvss_score = record.cvss_score
            if finding.status == "resolved":
                finding.status = "open"
                finding.resolved_at = None
        link.status = "open"

    sbom.vulnerability_count = matched
    sbom.status = "analyzed"
    sbom.analyzed_at = datetime.now(UTC)
    history.status = "completed"
    history.completed_at = datetime.now(UTC)
    history.components_processed = len(components)
    history.findings_count = created_findings
    history.details = {"matched_vulnerabilities": matched, "created_findings": created_findings, "online_error": online_error}

    _refresh_linked_risk(db, sbom.organization_id, sbom.microservice_id, sbom.asset_id)
    db.commit()
    return {
        "status": "completed",
        "components": len(components),
        "matched_vulnerabilities": matched,
        "created_findings": created_findings,
        "online_error": online_error,
    }


def _refresh_linked_risk(db: Session, org_id: uuid.UUID, service_id: uuid.UUID | None, asset_id: uuid.UUID | None) -> None:
    from sqlalchemy import func

    if service_id:
        service = db.get(Microservice, service_id)
        if service:
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
    if asset_id:
        asset = db.get(Asset, asset_id)
        if asset:
            scores = db.execute(
                select(Finding.risk_score).where(
                    Finding.asset_id == asset_id,
                    Finding.status.in_(("open", "triaged", "in_progress", "assigned")),
                    Finding.deleted_at.is_(None),
                )
            ).scalars().all()
            asset.risk_score = round(sum(scores) / len(scores), 1) if scores else 0.0


def analyze_in_background(organization_id: uuid.UUID, sbom_id: uuid.UUID, use_online: bool) -> None:
    from app.database.session import SessionLocal

    db = SessionLocal()
    try:
        sbom = db.get(SbomDocument, sbom_id)
        if sbom is None or sbom.organization_id != organization_id:
            return
        correlate(db, sbom, use_online=use_online)
    except Exception as exc:  # noqa: BLE001 - background job must record failure
        db.rollback()
        sbom = db.get(SbomDocument, sbom_id)
        if sbom:
            sbom.status = "failed"
            sbom.error_message = str(exc)[:1000]
            db.commit()
        logger.exception("SBOM analysis failed for %s: %s", sbom_id, exc)
    finally:
        db.close()
