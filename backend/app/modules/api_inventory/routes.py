import csv
import io
import uuid

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import PageParams, get_db, get_org_id, page_params, paginate, page_response, serialize
from app.core.audit import record_audit
from app.core.exceptions import ConflictError, NotFoundError
from app.core.permissions import Permission, User, require_permissions
from app.core.tenancy import scoped_get
from app.database.models.api_inventory import Api, ApiEndpoint, ApiSecurityFinding, ApiSpecification
from app.modules.api_inventory import service

router = APIRouter(prefix="/apis", tags=["API Inventory"])


class ApiCreate(BaseModel):
    name: str = Field(min_length=2, max_length=250)
    base_url: str | None = None
    service_id: uuid.UUID | None = None
    environment_id: uuid.UUID | None = None
    version: str | None = None
    auth_type: str = "unknown"
    content_type: str = "application/json"
    data_sensitivity: str = "internal"
    exposure: str = "internal"
    description: str | None = None


class ApiUpdate(BaseModel):
    name: str | None = None
    base_url: str | None = None
    auth_type: str | None = None
    authorization_model: str | None = None
    data_sensitivity: str | None = None
    exposure: str | None = None
    status: str | None = None
    deprecated: bool | None = None
    description: str | None = None


@router.get("")
def list_apis(
    params: PageParams = Depends(page_params),
    auth_type: str | None = None,
    exposure: str | None = None,
    data_sensitivity: str | None = None,
    security_status: str | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.API_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(Api).where(Api.organization_id == org_id, Api.deleted_at.is_(None))
    if auth_type:
        stmt = stmt.where(Api.auth_type == auth_type)
    if exposure:
        stmt = stmt.where(Api.exposure == exposure)
    if data_sensitivity:
        stmt = stmt.where(Api.data_sensitivity == data_sensitivity)
    if security_status:
        stmt = stmt.where(Api.security_status == security_status)
    items, meta = paginate(
        db,
        stmt,
        params,
        Api,
        search_fields=[Api.name, Api.base_url, Api.api_ref, Api.version],
        sortable={"name": Api.name, "created_at": Api.created_at, "last_observed": Api.last_observed},
        default_sort=Api.created_at,
    )
    return {
        "items": [
            {
                **serialize(item),
                "endpoint_count": db.scalar(select(func.count(ApiEndpoint.id)).where(ApiEndpoint.api_id == item.id)) or 0,
                "security_findings": db.scalar(select(func.count(ApiSecurityFinding.id)).where(ApiSecurityFinding.api_id == item.id, ApiSecurityFinding.status == "open")) or 0,
            }
            for item in items
        ],
        "pagination": meta,
    }


@router.get("/dashboard")
def api_dashboard(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.API_READ)),
    db: Session = Depends(get_db),
) -> dict:
    apis = db.scalars(select(Api).where(Api.organization_id == org_id, Api.deleted_at.is_(None))).all()
    total = len(apis)
    endpoints = db.scalar(select(func.count(ApiEndpoint.id)).where(ApiEndpoint.organization_id == org_id)) or 0
    checks = db.execute(
        select(ApiSecurityFinding.check_key, func.count(ApiSecurityFinding.id))
        .where(ApiSecurityFinding.organization_id == org_id, ApiSecurityFinding.status == "open")
        .group_by(ApiSecurityFinding.check_key)
    ).all()
    return {
        "total": total,
        "endpoints": endpoints,
        "public": len([api for api in apis if api.exposure == "public"]),
        "internal": len([api for api in apis if api.exposure == "internal"]),
        "unauthenticated": len([api for api in apis if api.auth_type in {"none", "unknown"}]),
        "sensitive": len([api for api in apis if api.data_sensitivity in {"high", "critical", "pii"}]),
        "deprecated": len([api for api in apis if api.deprecated]),
        "needs_review": len([api for api in apis if api.security_status in {"unreviewed", "issues_found"}]),
        "checks": [{"name": row[0], "value": row[1]} for row in sorted(checks, key=lambda item: item[1], reverse=True)],
        "by_auth": [
            {"name": row[0], "value": row[1]}
            for row in db.execute(select(Api.auth_type, func.count(Api.id)).where(Api.organization_id == org_id, Api.deleted_at.is_(None)).group_by(Api.auth_type)).all()
        ],
    }


@router.post("", status_code=201)
def create_api(
    payload: ApiCreate,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.API_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    from app.core.refs import next_ref

    api = Api(organization_id=org_id, api_ref=next_ref(db, Api, "api_ref", "API", org_id), tags=[], **payload.model_dump())
    db.add(api)
    record_audit(db, user=user, action="api.created", resource_type="api", resource_id=api.id, request=request)
    db.commit()
    return serialize(api)


@router.post("/import", status_code=201)
def import_api(
    request: Request,
    file: UploadFile = File(...),
    name: str | None = Form(None),
    service_id: uuid.UUID | None = Form(None),
    environment_id: uuid.UUID | None = Form(None),
    base_url: str | None = Form(None),
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.API_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    content = file.file.read()
    if len(content) > 5 * 1024 * 1024:
        raise ConflictError("Specification exceeds the 5MB limit")
    api, specification = service.import_specification(
        db,
        organization_id=org_id,
        uploaded_by=user.id,
        name=name or file.filename or "Imported API",
        content=content.decode("utf-8", errors="replace"),
        filename=file.filename or "openapi.json",
        microservice_id=service_id,
        environment_id=environment_id,
        base_url_override=base_url,
    )
    record_audit(db, user=user, action="api.imported", resource_type="api", resource_id=api.id, details={"endpoints": specification.endpoint_count}, request=request)
    db.commit()
    return {**serialize(api), "endpoints_imported": specification.endpoint_count}


@router.get("/{api_id}")
def get_api(
    api_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.API_READ)),
    db: Session = Depends(get_db),
) -> dict:
    api = scoped_get(db, Api, api_id, org_id)
    endpoints = db.scalars(select(ApiEndpoint).where(ApiEndpoint.api_id == api.id).order_by(ApiEndpoint.path)).all()
    findings = db.scalars(select(ApiSecurityFinding).where(ApiSecurityFinding.api_id == api.id).order_by(ApiSecurityFinding.severity)).all()
    specs = db.scalars(select(ApiSpecification).where(ApiSpecification.api_id == api.id)).all()
    return {
        **serialize(api),
        "endpoints": [serialize(endpoint) for endpoint in endpoints],
        "security_findings": [serialize(finding) for finding in findings],
        "specifications": [serialize(spec, exclude={"content"}) for spec in specs],
    }


@router.patch("/{api_id}")
def update_api(
    api_id: uuid.UUID,
    payload: ApiUpdate,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.API_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    api = scoped_get(db, Api, api_id, org_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(api, field, value)
    db.commit()
    return serialize(api)


@router.post("/{api_id}/checks")
def rerun_checks(
    api_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.API_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    api = scoped_get(db, Api, api_id, org_id)
    created = service.run_security_checks(db, api)
    return {"status": "completed", "new_findings": created}


@router.get("/{api_id}/export")
def export_api(
    api_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.API_READ)),
    db: Session = Depends(get_db),
):
    from fastapi.responses import StreamingResponse

    api = scoped_get(db, Api, api_id, org_id)
    endpoints = db.scalars(select(ApiEndpoint).where(ApiEndpoint.api_id == api.id)).all()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["method", "path", "summary", "auth_required", "deprecated", "data_sensitivity"])
    for endpoint in endpoints:
        writer.writerow([endpoint.method, endpoint.path, endpoint.summary or "", endpoint.auth_required, endpoint.deprecated, endpoint.data_sensitivity])
    buffer.seek(0)
    return StreamingResponse(iter([buffer.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="atlas-api-{api.api_ref}.csv"'})
