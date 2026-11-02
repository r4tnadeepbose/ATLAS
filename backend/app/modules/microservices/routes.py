import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import PageParams, get_db, get_org_id, page_params, paginate, page_response, serialize
from app.core.audit import record_audit
from app.core.exceptions import ValidationError
from app.core.permissions import Permission, User, require_permissions
from app.core.refs import next_ref
from app.core.tenancy import scoped_get
from app.database.models.findings import Finding
from app.database.models.infrastructure import Environment, Microservice, ServiceDependency

router = APIRouter(prefix="/microservices", tags=["Microservice Intelligence"])


class ServiceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    description: str | None = None
    repository_url: str | None = None
    owner_user_id: uuid.UUID | None = None
    team_id: uuid.UUID | None = None
    business_unit: str | None = None
    environment_id: uuid.UUID | None = None
    deployment_location: str | None = None
    version: str | None = None
    language: str | None = None
    tech_stack: list[str] = Field(default_factory=list)
    criticality: str = "medium"
    status: str = "active"
    tags: list[str] = Field(default_factory=list)


class ServiceUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    repository_url: str | None = None
    owner_user_id: uuid.UUID | None = None
    business_unit: str | None = None
    environment_id: uuid.UUID | None = None
    version: str | None = None
    language: str | None = None
    tech_stack: list[str] | None = None
    criticality: str | None = None
    status: str | None = None


class DependencyCreate(BaseModel):
    target_service_id: uuid.UUID | None = None
    target_external: str | None = None
    dependency_type: str = "http"


@router.get("")
def list_services(
    params: PageParams = Depends(page_params),
    environment_id: uuid.UUID | None = None,
    business_unit: str | None = None,
    criticality: str | None = None,
    status: str | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SERVICE_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(Microservice).where(Microservice.organization_id == org_id, Microservice.deleted_at.is_(None))
    if environment_id:
        stmt = stmt.where(Microservice.environment_id == environment_id)
    if business_unit:
        stmt = stmt.where(Microservice.business_unit == business_unit)
    if criticality:
        stmt = stmt.where(Microservice.criticality == criticality)
    if status:
        stmt = stmt.where(Microservice.status == status)
    items, meta = paginate(
        db,
        stmt,
        params,
        Microservice,
        search_fields=[Microservice.name, Microservice.service_ref, Microservice.business_unit, Microservice.language],
        sortable={
            "name": Microservice.name,
            "risk_score": Microservice.risk_score,
            "risk_level": Microservice.risk_level,
            "last_assessed_at": Microservice.last_assessed_at,
        },
        default_sort=Microservice.risk_score,
    )
    env_names = {env.id: env.name for env in db.scalars(select(Environment).where(Environment.organization_id == org_id)).all()}
    return {
        "items": [
            {
                **serialize(item),
                "environment_name": env_names.get(item.environment_id),
                "open_findings": db.scalar(
                    select(func.count(Finding.id)).where(
                        Finding.microservice_id == item.id,
                        Finding.status.in_(("open", "triaged", "in_progress", "assigned")),
                    )
                )
                or 0,
            }
            for item in items
        ],
        "pagination": meta,
    }


@router.get("/summary")
def summary(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SERVICE_READ)),
    db: Session = Depends(get_db),
) -> dict:
    services = db.scalars(select(Microservice).where(Microservice.organization_id == org_id, Microservice.deleted_at.is_(None))).all()
    dependencies = db.scalar(select(func.count(ServiceDependency.id)).where(ServiceDependency.organization_id == org_id)) or 0
    return {
        "total": len(services),
        "by_criticality": [
            {"name": key, "value": len([s for s in services if s.criticality == key])}
            for key in ("critical", "high", "medium", "low")
        ],
        "by_business_unit": sorted(
            [
                {"name": unit, "value": count}
                for unit, count in (
                    db.execute(
                        select(Microservice.business_unit, func.count(Microservice.id))
                        .where(Microservice.organization_id == org_id, Microservice.deleted_at.is_(None))
                        .group_by(Microservice.business_unit)
                    ).all()
                )
                if unit
            ],
            key=lambda item: item["value"],
            reverse=True,
        ),
        "dependencies": dependencies,
        "high_risk": [
            serialize(service)
            for service in [s for s in sorted(services, key=lambda s: s.risk_score or 0, reverse=True) if (s.risk_score or 0) > 0][:6]
        ],
    }


@router.post("", status_code=201)
def create_service(
    payload: ServiceCreate,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.SERVICE_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    service = Microservice(
        organization_id=org_id,
        service_ref=next_ref(db, Microservice, "service_ref", "SVC", org_id),
        **payload.model_dump(),
    )
    db.add(service)
    db.flush()
    record_audit(db, user=user, action="microservice.created", resource_type="microservice", resource_id=service.id, request=request)
    db.commit()
    return serialize(service)


@router.get("/{service_id}")
def get_service(
    service_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SERVICE_READ)),
    db: Session = Depends(get_db),
) -> dict:
    service = scoped_get(db, Microservice, service_id, org_id)
    deps = db.scalars(select(ServiceDependency).where(ServiceDependency.source_service_id == service.id)).all()
    dependents = db.scalars(select(ServiceDependency).where(ServiceDependency.target_service_id == service.id)).all()
    findings = db.scalars(
        select(Finding).where(Finding.microservice_id == service.id, Finding.deleted_at.is_(None)).order_by(Finding.risk_score.desc()).limit(50)
    ).all()
    from app.database.models.sbom import SbomDocument

    sboms = db.scalars(select(SbomDocument).where(SbomDocument.microservice_id == service.id)).all()
    from app.database.models.api_inventory import Api

    apis = db.scalars(select(Api).where(Api.service_id == service.id, Api.deleted_at.is_(None))).all()
    return {
        **serialize(service),
        "dependencies": [serialize(dep) for dep in deps],
        "dependents": [serialize(dep) for dep in dependents],
        "findings": [serialize(finding) for finding in findings],
        "sboms": [serialize(sbom) for sbom in sboms],
        "apis": [serialize(api) for api in apis],
    }


@router.patch("/{service_id}")
def update_service(
    service_id: uuid.UUID,
    payload: ServiceUpdate,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.SERVICE_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    service = scoped_get(db, Microservice, service_id, org_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(service, field, value)
    record_audit(db, user=user, action="microservice.updated", resource_type="microservice", resource_id=service.id, request=request)
    db.commit()
    return serialize(service)


@router.delete("/{service_id}")
def delete_service(
    service_id: uuid.UUID,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.SERVICE_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    service = scoped_get(db, Microservice, service_id, org_id)
    service.deleted_at = datetime.now(UTC)
    record_audit(db, user=user, action="microservice.deleted", resource_type="microservice", resource_id=service.id, request=request)
    db.commit()
    return {"status": "deleted"}


@router.post("/{service_id}/dependencies", status_code=201)
def add_dependency(
    service_id: uuid.UUID,
    payload: DependencyCreate,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.SERVICE_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    service = scoped_get(db, Microservice, service_id, org_id)
    if not payload.target_service_id and not payload.target_external:
        raise ValidationError("Provide a target service or an external dependency")
    if payload.target_service_id:
        scoped_get(db, Microservice, payload.target_service_id, org_id)
    dependency = ServiceDependency(
        organization_id=org_id,
        source_service_id=service.id,
        target_service_id=payload.target_service_id,
        target_external=payload.target_external,
        dependency_type=payload.dependency_type,
    )
    db.add(dependency)
    db.commit()
    return serialize(dependency)


@router.get("/{service_id}/dependencies")
def service_dependencies(
    service_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SERVICE_READ)),
    db: Session = Depends(get_db),
) -> dict:
    scoped_get(db, Microservice, service_id, org_id)
    deps = db.scalars(select(ServiceDependency).where(ServiceDependency.organization_id == org_id, ServiceDependency.source_service_id == service_id)).all()
    return {"items": [serialize(dep) for dep in deps]}


@router.get("/graph/relationship-map", include_in_schema=True)
def relationship_map(
    environment_id: uuid.UUID | None = None,
    business_unit: str | None = None,
    risk_level: str | None = None,
    language: str | None = None,
    exposure: str | None = None,
    vulnerability_status: str | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SERVICE_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(Microservice).where(Microservice.organization_id == org_id, Microservice.deleted_at.is_(None))
    if environment_id:
        stmt = stmt.where(Microservice.environment_id == environment_id)
    if business_unit:
        stmt = stmt.where(Microservice.business_unit == business_unit)
    if risk_level:
        stmt = stmt.where(Microservice.risk_level == risk_level)
    if language:
        stmt = stmt.where(Microservice.language == language)
    services = db.scalars(stmt).all()
    service_ids = {service.id for service in services}
    service_id_strs = {str(sid) for sid in service_ids}

    findings_counts = dict(
        db.execute(
            select(Finding.microservice_id, func.count(Finding.id))
            .where(Finding.organization_id == org_id, Finding.status.in_(("open", "triaged", "in_progress", "assigned")))
            .group_by(Finding.microservice_id)
        ).all()
    )

    nodes = []
    for service in services:
        if vulnerability_status == "vulnerable" and findings_counts.get(service.id, 0) == 0:
            continue
        if vulnerability_status == "clean" and findings_counts.get(service.id, 0) > 0:
            continue
        nodes.append(
            {
                "id": str(service.id),
                "label": service.name,
                "criticality": service.criticality,
                "risk_score": service.risk_score,
                "risk_level": service.risk_level,
                "business_unit": service.business_unit,
                "language": service.language,
                "environment_id": str(service.environment_id) if service.environment_id else None,
                "open_findings": findings_counts.get(service.id, 0),
            }
        )

    deps = db.scalars(select(ServiceDependency).where(ServiceDependency.organization_id == org_id)).all()
    edges = []
    external_nodes: dict[str, dict] = {}
    for dep in deps:
        if str(dep.source_service_id) not in service_id_strs:
            continue
        if dep.target_service_id:
            if str(dep.target_service_id) not in service_id_strs:
                continue
            edges.append(
                {
                    "id": str(dep.id),
                    "source": str(dep.source_service_id),
                    "target": str(dep.target_service_id),
                    "type": dep.dependency_type,
                }
            )
        elif dep.target_external:
            key = f"ext:{dep.target_external}"
            external_nodes[key] = {"id": key, "label": dep.target_external, "external": True, "risk_score": 0, "open_findings": 0}
            edges.append({"id": str(dep.id), "source": str(dep.source_service_id), "target": key, "type": dep.dependency_type})
    return {"nodes": nodes + list(external_nodes.values()), "edges": edges, "filters": {"exposure": exposure}}
