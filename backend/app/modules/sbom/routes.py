import csv
import io
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, Query, Request, UploadFile
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import PageParams, get_db, get_org_id, page_params, paginate, page_response, serialize
from app.core.audit import record_audit
from app.core.exceptions import NotFoundError, ValidationError
from app.core.permissions import Permission, User, require_permissions
from app.core.tenancy import scoped_get
from app.core.time import iso
from app.database.models.findings import Finding
from app.database.models.infrastructure import Microservice
from app.database.models.sbom import (
    ComponentVulnerability,
    SbomComponent,
    SbomDocument,
    SbomScanHistory,
    VulnerabilityRecord,
)
from app.modules.sbom import service

router = APIRouter(prefix="/sbom", tags=["SBOM Intelligence"])


class GenerateRequest(BaseModel):
    target: str
    microservice_id: uuid.UUID | None = None
    source_type: str = "image"


@router.get("")
def list_sboms(
    params: PageParams = Depends(page_params),
    microservice_id: uuid.UUID | None = None,
    status: str | None = None,
    format: str | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SBOM_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(SbomDocument).where(SbomDocument.organization_id == org_id)
    if microservice_id:
        stmt = stmt.where(SbomDocument.microservice_id == microservice_id)
    if status:
        stmt = stmt.where(SbomDocument.status == status)
    if format:
        stmt = stmt.where(SbomDocument.format == format)
    items, meta = paginate(
        db,
        stmt,
        params,
        SbomDocument,
        search_fields=[SbomDocument.name, SbomDocument.file_name, SbomDocument.version_label],
        sortable={"created_at": SbomDocument.created_at, "component_count": SbomDocument.component_count, "vulnerability_count": SbomDocument.vulnerability_count},
        default_sort=SbomDocument.created_at,
    )
    services = {service.id: service.name for service in db.scalars(select(Microservice).where(Microservice.organization_id == org_id)).all()}
    return {
        "items": [{**serialize(item), "microservice_name": services.get(item.microservice_id)} for item in items],
        "pagination": meta,
    }


@router.get("/dashboard")
def sbom_dashboard(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SBOM_READ)),
    db: Session = Depends(get_db),
) -> dict:
    docs = db.scalars(select(SbomDocument).where(SbomDocument.organization_id == org_id)).all()
    components_total = db.scalar(select(func.count(SbomComponent.id)).where(SbomComponent.organization_id == org_id)) or 0
    vulnerable_components = db.scalar(
        select(func.count(func.distinct(ComponentVulnerability.component_id))).where(ComponentVulnerability.organization_id == org_id)
    ) or 0
    severity_rows = db.execute(
        select(VulnerabilityRecord.severity, func.count(ComponentVulnerability.id))
        .join(ComponentVulnerability, ComponentVulnerability.vulnerability_id == VulnerabilityRecord.id)
        .where(ComponentVulnerability.organization_id == org_id)
        .group_by(VulnerabilityRecord.severity)
    ).all()
    critical_deps = db.scalar(
        select(func.count(func.distinct(ComponentVulnerability.component_id)))
        .join(VulnerabilityRecord, ComponentVulnerability.vulnerability_id == VulnerabilityRecord.id)
        .where(ComponentVulnerability.organization_id == org_id, VulnerabilityRecord.severity == "critical")
    ) or 0
    recent = sorted(docs, key=lambda d: d.created_at or datetime.min.replace(tzinfo=UTC), reverse=True)[:8]
    license_concerns = db.scalar(
        select(func.count(SbomComponent.id)).where(
            SbomComponent.organization_id == org_id,
            SbomComponent.license.is_not(None),
            SbomComponent.license.notin_(["MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC", "MPL-2.0", "0BSD"]),
        )
    ) or 0
    return {
        "documents": len(docs),
        "components": components_total,
        "vulnerable_components": vulnerable_components,
        "critical_dependencies": critical_deps,
        "license_concerns": license_concerns,
        "severity_distribution": [{"name": row[0], "value": row[1]} for row in severity_rows],
        "recent_scans": [serialize(doc) for doc in recent],
        "formats": [
            {"name": row[0], "value": row[1]}
            for row in db.execute(
                select(SbomDocument.format, func.count(SbomDocument.id)).where(SbomDocument.organization_id == org_id).group_by(SbomDocument.format)
            ).all()
        ],
    }


@router.get("/compare")
def compare_sboms(
    left: uuid.UUID,
    right: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SBOM_READ)),
    db: Session = Depends(get_db),
) -> dict:
    left_doc = scoped_get(db, SbomDocument, left, org_id)
    right_doc = scoped_get(db, SbomDocument, right, org_id)

    def component_map(sbom_id):
        return {
            f"{component.name}@{component.version}": component
            for component in db.scalars(select(SbomComponent).where(SbomComponent.sbom_id == sbom_id)).all()
        }

    left_components = component_map(left_doc.id)
    right_components = component_map(right_doc.id)
    added = sorted(set(right_components) - set(left_components))
    removed = sorted(set(left_components) - set(right_components))
    changed = sorted(
        key
        for key in set(left_components) & set(right_components)
        if (left_components[key].version or "") != (right_components[key].version or "")
    )
    return {
        "left": {"id": str(left_doc.id), "name": left_doc.name, "version": left_doc.version_label, "created_at": iso(left_doc.created_at)},
        "right": {"id": str(right_doc.id), "name": right_doc.name, "version": right_doc.version_label, "created_at": iso(right_doc.created_at)},
        "added": added,
        "removed": removed,
        "changed": changed,
        "summary": {"added": len(added), "removed": len(removed), "changed": len(changed)},
    }


@router.post("/generate", status_code=202)
def generate_sbom(
    payload: GenerateRequest,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.SBOM_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    from app.integrations.syft.adapter import SyftAdapter

    adapter = SyftAdapter()
    availability = adapter.availability()
    if not availability["available"]:
        raise ValidationError(
            "Syft is not installed on this host. Install Syft or upload a pre-generated SBOM.",
            details={"adapter": "syft", "hint": "https://github.com/anchore/syft"},
        )
    if payload.microservice_id:
        scoped_get(db, Microservice, payload.microservice_id, org_id)
    record_audit(db, user=user, action="sbom.generate_requested", resource_type="sbom", details={"target": payload.target}, request=request)
    db.commit()
    result = adapter.generate(payload.target)
    if not result["ok"]:
        raise ValidationError(result.get("error") or "Syft generation failed")
    document = service.ingest_sbom(
        db,
        organization_id=org_id,
        uploaded_by=user.id,
        filename=f"{payload.target.replace('/', '_')}.cdx.json",
        content=result["content"],
        microservice_id=payload.microservice_id,
        source="syft",
        version_label=datetime.now(UTC).strftime("%Y%m%d%H%M"),
    )
    record_audit(db, user=user, action="sbom.generated", resource_type="sbom", resource_id=document.id, request=request)
    db.commit()
    return {"id": str(document.id), "status": document.status, "components": document.component_count}


@router.post("/upload", status_code=201)
def upload_sbom(
    background: BackgroundTasks,
    request: Request,
    file: UploadFile = File(...),
    microservice_id: uuid.UUID | None = Form(None),
    asset_id: uuid.UUID | None = Form(None),
    version_label: str | None = Form(None),
    analyze: bool = Form(True),
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.SBOM_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    content = file.file.read()
    document = service.ingest_sbom(
        db,
        organization_id=org_id,
        uploaded_by=user.id,
        filename=file.filename or "sbom.json",
        content=content,
        microservice_id=microservice_id,
        asset_id=asset_id,
        version_label=version_label,
    )
    record_audit(db, user=user, action="sbom.uploaded", resource_type="sbom", resource_id=document.id, details={"format": document.format}, request=request)
    db.commit()
    if analyze:
        document.status = "queued"
        db.commit()
        background.add_task(service.analyze_in_background, org_id, document.id, True)
    return serialize(document)


@router.get("/{sbom_id}")
def get_sbom(
    sbom_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SBOM_READ)),
    db: Session = Depends(get_db),
) -> dict:
    document = scoped_get(db, SbomDocument, sbom_id, org_id)
    components = db.scalars(
        select(SbomComponent).where(SbomComponent.sbom_id == document.id).order_by(SbomComponent.vulnerability_count.desc()).limit(200)
    ).all()
    links = db.scalars(select(ComponentVulnerability).where(ComponentVulnerability.sbom_id == document.id)).all()
    vulns = []
    for link in links[:200]:
        record = db.get(VulnerabilityRecord, link.vulnerability_id)
        component = db.get(SbomComponent, link.component_id)
        if record and component:
            vulns.append({**serialize(record), "component": component.name, "component_version": component.version, "fixed_version": link.fixed_version, "link_status": link.status})
    history = db.scalars(select(SbomScanHistory).where(SbomScanHistory.sbom_id == document.id).order_by(SbomScanHistory.created_at.desc())).all()
    return {
        **serialize(document),
        "components": [serialize(component) for component in components],
        "vulnerabilities": vulns,
        "scan_history": [serialize(entry) for entry in history],
    }


@router.get("/{sbom_id}/components")
def list_components(
    sbom_id: uuid.UUID,
    params: PageParams = Depends(page_params),
    vulnerable_only: bool = False,
    ecosystem: str | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SBOM_READ)),
    db: Session = Depends(get_db),
) -> dict:
    scoped_get(db, SbomDocument, sbom_id, org_id)
    stmt = select(SbomComponent).where(SbomComponent.sbom_id == sbom_id)
    if vulnerable_only:
        stmt = stmt.where(SbomComponent.vulnerability_count > 0)
    if ecosystem:
        stmt = stmt.where(SbomComponent.ecosystem == ecosystem)
    items, meta = paginate(
        db,
        stmt,
        params,
        SbomComponent,
        search_fields=[SbomComponent.name, SbomComponent.purl, SbomComponent.supplier],
        sortable={"name": SbomComponent.name, "vulnerability_count": SbomComponent.vulnerability_count},
        default_sort=SbomComponent.vulnerability_count,
    )
    return page_response(items, meta)


@router.get("/{sbom_id}/vulnerabilities")
def list_vulnerabilities(
    sbom_id: uuid.UUID,
    params: PageParams = Depends(page_params),
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SBOM_READ)),
    db: Session = Depends(get_db),
) -> dict:
    scoped_get(db, SbomDocument, sbom_id, org_id)
    stmt = (
        select(ComponentVulnerability, VulnerabilityRecord, SbomComponent)
        .join(VulnerabilityRecord, ComponentVulnerability.vulnerability_id == VulnerabilityRecord.id)
        .join(SbomComponent, ComponentVulnerability.component_id == SbomComponent.id)
        .where(ComponentVulnerability.sbom_id == sbom_id)
        .order_by(VulnerabilityRecord.cvss_score.desc())
    )
    rows = db.execute(stmt.limit(500)).all()
    return {
        "items": [
            {
                "id": str(link.id),
                **serialize(record),
                "component": component.name,
                "component_version": component.version,
                "fixed_version": link.fixed_version,
                "link_status": link.status,
            }
            for link, record, component in rows
        ]
    }


@router.get("/{sbom_id}/export")
def export_components(
    sbom_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SBOM_READ)),
    db: Session = Depends(get_db),
) -> dict:
    from fastapi.responses import StreamingResponse

    scoped_get(db, SbomDocument, sbom_id, org_id)
    components = db.scalars(select(SbomComponent).where(SbomComponent.sbom_id == sbom_id)).all()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["name", "version", "ecosystem", "purl", "license", "vulnerabilities", "highest_severity"])
    for component in components:
        writer.writerow([component.name, component.version or "", component.ecosystem or "", component.purl or "", component.license or "", component.vulnerability_count, component.highest_severity or ""])
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="atlas-sbom-{sbom_id}.csv"'},
    )


@router.post("/{sbom_id}/analyze", status_code=202)
def analyze_sbom(
    sbom_id: uuid.UUID,
    background: BackgroundTasks,
    online: bool = Query(True),
    request: Request = None,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.SBOM_ANALYZE)),
    db: Session = Depends(get_db),
) -> dict:
    document = scoped_get(db, SbomDocument, sbom_id, org_id)
    document.status = "queued"
    record_audit(db, user=user, action="sbom.analysis_requested", resource_type="sbom", resource_id=document.id, request=request)
    db.commit()
    background.add_task(service.analyze_in_background, org_id, document.id, online)
    return {"id": str(document.id), "status": "queued"}


@router.delete("/{sbom_id}")
def delete_sbom(
    sbom_id: uuid.UUID,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.SBOM_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    document = scoped_get(db, SbomDocument, sbom_id, org_id)
    record_audit(db, user=user, action="sbom.deleted", resource_type="sbom", resource_id=document.id, request=request)
    db.delete(document)
    db.commit()
    return {"status": "deleted"}
