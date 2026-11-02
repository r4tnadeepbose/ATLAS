import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import PageParams, get_db, get_org_id, page_params, paginate, page_response, serialize
from app.core.audit import record_audit
from app.core.exceptions import ConflictError, NotFoundError
from app.core.permissions import Permission, User, require_permissions
from app.core.refs import next_ref
from app.core.tenancy import scoped_get
from app.database.models.findings import Finding
from app.database.models.infrastructure import (
    Asset,
    AssetRelationship,
    Certificate,
    Environment,
    Microservice,
    NetworkService,
    Technology,
)
from app.modules.dashboard.service import OPEN_STATUSES

router = APIRouter(prefix="/assets", tags=["Asset Intelligence"])
env_router = APIRouter(prefix="/environments", tags=["Environments"])


class AssetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    domain: str | None = None
    subdomain: str | None = None
    ip_address: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = "https"
    url: str | None = None
    http_status: int | None = None
    hosting_provider: str | None = None
    business_unit: str | None = None
    environment_id: uuid.UUID | None = None
    criticality: str = "medium"
    exposure: str = "internal"
    status: str = "active"
    source: str = "manual"
    tags: list[str] = Field(default_factory=list)
    technology_summary: list[str] = Field(default_factory=list)
    description: str | None = None


class AssetUpdate(BaseModel):
    name: str | None = None
    domain: str | None = None
    ip_address: str | None = None
    port: int | None = None
    http_status: int | None = None
    business_unit: str | None = None
    environment_id: uuid.UUID | None = None
    criticality: str | None = None
    exposure: str | None = None
    status: str | None = None
    tags: list[str] | None = None
    description: str | None = None


class RelationshipCreate(BaseModel):
    target_asset_id: uuid.UUID
    relationship_type: str = "connects_to"


class EnvironmentCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    key: str = Field(min_length=2, max_length=60, pattern="^[a-z0-9-]+$")
    description: str | None = None
    is_production: bool = False


@router.get("")
def list_assets(
    params: PageParams = Depends(page_params),
    exposure: str | None = None,
    criticality: str | None = None,
    environment_id: uuid.UUID | None = None,
    business_unit: str | None = None,
    status: str | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.ASSET_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(Asset).where(Asset.organization_id == org_id, Asset.deleted_at.is_(None))
    if exposure:
        stmt = stmt.where(Asset.exposure == exposure)
    if criticality:
        stmt = stmt.where(Asset.criticality == criticality)
    if environment_id:
        stmt = stmt.where(Asset.environment_id == environment_id)
    if business_unit:
        stmt = stmt.where(Asset.business_unit == business_unit)
    if status:
        stmt = stmt.where(Asset.status == status)
    items, meta = paginate(
        db,
        stmt,
        params,
        Asset,
        search_fields=[Asset.name, Asset.domain, Asset.ip_address, Asset.asset_ref, Asset.business_unit],
        sortable={"name": Asset.name, "risk_score": Asset.risk_score, "last_seen": Asset.last_seen, "created_at": Asset.created_at},
        default_sort=Asset.risk_score,
    )
    return page_response(items, meta)


@router.get("/summary")
def asset_summary(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.ASSET_READ)),
    db: Session = Depends(get_db),
) -> dict:
    total = db.scalar(select(func.count(Asset.id)).where(Asset.organization_id == org_id, Asset.deleted_at.is_(None))) or 0
    by_exposure = dict(
        db.execute(
            select(Asset.exposure, func.count(Asset.id)).where(Asset.organization_id == org_id, Asset.deleted_at.is_(None)).group_by(Asset.exposure)
        ).all()
    )
    by_criticality = dict(
        db.execute(
            select(Asset.criticality, func.count(Asset.id)).where(Asset.organization_id == org_id, Asset.deleted_at.is_(None)).group_by(Asset.criticality)
        ).all()
    )
    by_source = dict(
        db.execute(
            select(Asset.source, func.count(Asset.id)).where(Asset.organization_id == org_id, Asset.deleted_at.is_(None)).group_by(Asset.source)
        ).all()
    )
    recent = db.scalars(
        select(Asset).where(Asset.organization_id == org_id, Asset.deleted_at.is_(None)).order_by(Asset.first_seen.desc()).limit(6)
    ).all()
    return {
        "total": total,
        "by_exposure": [{"name": k or "unknown", "value": v} for k, v in by_exposure.items()],
        "by_criticality": [{"name": k or "unknown", "value": v} for k, v in by_criticality.items()],
        "by_source": [{"name": k, "value": v} for k, v in by_source.items()],
        "recent": [serialize(asset) for asset in recent],
    }


@router.post("", status_code=201)
def create_asset(
    payload: AssetCreate,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.ASSET_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    if payload.domain and db.scalar(
        select(Asset).where(Asset.organization_id == org_id, Asset.domain == payload.domain, Asset.deleted_at.is_(None))
    ):
        raise ConflictError("An asset with that domain already exists")
    asset = Asset(
        organization_id=org_id,
        asset_ref=next_ref(db, Asset, "asset_ref", "AST", org_id),
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        **payload.model_dump(),
    )
    db.add(asset)
    db.flush()
    record_audit(db, user=user, action="asset.created", resource_type="asset", resource_id=asset.id, details={"name": asset.name}, request=request)
    db.commit()
    return serialize(asset)


@router.get("/discovered")
def discovered_assets(
    days: int = Query(30, ge=1, le=365),
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.ASSET_READ)),
    db: Session = Depends(get_db),
) -> dict:
    from datetime import timedelta

    since = datetime.now(UTC) - timedelta(days=days)
    assets = db.scalars(
        select(Asset)
        .where(Asset.organization_id == org_id, Asset.deleted_at.is_(None), Asset.first_seen >= since)
        .order_by(Asset.first_seen.desc())
        .limit(200)
    ).all()
    return {"items": [serialize(asset) for asset in assets]}


@router.get("/{asset_id}")
def get_asset(
    asset_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.ASSET_READ)),
    db: Session = Depends(get_db),
) -> dict:
    asset = scoped_get(db, Asset, asset_id, org_id)
    services = db.scalars(select(NetworkService).where(NetworkService.asset_id == asset.id)).all()
    technologies = db.scalars(select(Technology).where(Technology.asset_id == asset.id)).all()
    certificates = db.scalars(select(Certificate).where(Certificate.asset_id == asset.id)).all()
    relationships = db.scalars(
        select(AssetRelationship).where(
            AssetRelationship.organization_id == org_id,
            (AssetRelationship.source_asset_id == asset.id) | (AssetRelationship.target_asset_id == asset.id),
        )
    ).all()
    findings = db.execute(
        select(Finding, Microservice.name)
        .outerjoin(Microservice, Finding.microservice_id == Microservice.id)
        .where(Finding.asset_id == asset.id, Finding.deleted_at.is_(None))
        .order_by(Finding.risk_score.desc())
        .limit(50)
    ).all()
    linked_services = db.scalars(
        select(Microservice).where(Microservice.organization_id == org_id).limit(100)
    ).all()
    return {
        **serialize(asset),
        "network_services": [serialize(item) for item in services],
        "technologies": [serialize(item) for item in technologies],
        "certificates": [serialize(item) for item in certificates],
        "relationships": [serialize(item) for item in relationships],
        "findings": [
            {**serialize(finding), "service_name": service_name, "detail_url": f"/vulnerabilities/{finding.id}"}
            for finding, service_name in findings
        ],
        "linked_microservices": [
            serialize(service) for service in linked_services if service.name and service.name.split("-")[0] in (asset.subdomain or asset.name or "").lower()
        ],
    }


@router.patch("/{asset_id}")
def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.ASSET_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    asset = scoped_get(db, Asset, asset_id, org_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(asset, field, value)
    asset.last_seen = datetime.now(UTC)
    record_audit(db, user=user, action="asset.updated", resource_type="asset", resource_id=asset.id, request=request)
    db.commit()
    return serialize(asset)


@router.delete("/{asset_id}")
def delete_asset(
    asset_id: uuid.UUID,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.ASSET_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    asset = scoped_get(db, Asset, asset_id, org_id)
    asset.deleted_at = datetime.now(UTC)
    record_audit(db, user=user, action="asset.deleted", resource_type="asset", resource_id=asset.id, request=request)
    db.commit()
    return {"status": "deleted"}


@router.post("/{asset_id}/relationships", status_code=201)
def add_relationship(
    asset_id: uuid.UUID,
    payload: RelationshipCreate,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.ASSET_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    asset = scoped_get(db, Asset, asset_id, org_id)
    target = scoped_get(db, Asset, payload.target_asset_id, org_id)
    relationship = AssetRelationship(
        organization_id=org_id,
        source_asset_id=asset.id,
        target_asset_id=target.id,
        relationship_type=payload.relationship_type,
    )
    db.add(relationship)
    db.commit()
    return serialize(relationship)


@env_router.get("")
def list_environments(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.ASSET_READ)),
    db: Session = Depends(get_db),
) -> dict:
    environments = db.scalars(select(Environment).where(Environment.organization_id == org_id).order_by(Environment.name)).all()
    return {"items": [serialize(env) for env in environments]}


@env_router.post("", status_code=201)
def create_environment(
    payload: EnvironmentCreate,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.ASSET_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    if db.scalar(select(Environment).where(Environment.organization_id == org_id, Environment.key == payload.key)):
        raise ConflictError("Environment key already exists")
    environment = Environment(organization_id=org_id, **payload.model_dump())
    db.add(environment)
    db.commit()
    return serialize(environment)
