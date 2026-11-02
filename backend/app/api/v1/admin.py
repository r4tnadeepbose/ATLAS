import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import PageParams, get_db, get_org_id, page_params, paginate, page_response, serialize
from app.config import settings
from app.core.audit import record_audit
from app.core.exceptions import NotFoundError
from app.core.permissions import ROLE_LABELS, ROLE_PERMISSIONS, Permission, User, require_permissions
from app.core.tenancy import scoped_get
from app.core.time import iso
from app.database.models.identity import AuditLog, Permission as PermissionModel, Role, RolePermission
from app.database.models.ops import BackgroundJob, Integration, SystemSetting

integration_router = APIRouter(prefix="/integrations", tags=["Integrations"])
settings_router = APIRouter(prefix="/settings", tags=["System Configuration"])
admin_router = APIRouter(prefix="/admin", tags=["Administration"])
rbac_router = APIRouter(prefix="/rbac", tags=["RBAC"])

SECRET_HINTS = ("key", "token", "secret", "password", "webhook")


class IntegrationUpdate(BaseModel):
    enabled: bool | None = None
    config: dict | None = None
    name: str | None = None


class SettingUpdate(BaseModel):
    key: str
    value: dict
    description: str | None = None


def _mask(config: dict) -> dict:
    return {
        key: ("********" if any(hint in key.lower() for hint in SECRET_HINTS) and value else value)
        for key, value in (config or {}).items()
    }


def _available_integrations() -> list[dict]:
    from app.integrations.gitleaks.adapter import GitleaksAdapter
    from app.integrations.grype.adapter import GrypeAdapter
    from app.integrations.nmap.adapter import NmapAdapter
    from app.integrations.nuclei.adapter import NucleiAdapter
    from app.integrations.nvd.adapter import NvdAdapter
    from app.integrations.osv.adapter import OsvAdapter
    from app.integrations.subfinder.adapter import HttpxAdapter, SubfinderAdapter
    from app.integrations.syft.adapter import SyftAdapter
    from app.integrations.trivy.adapter import TrivyAdapter
    from app.integrations.zap.adapter import ZapAdapter

    tool_adapters = [SyftAdapter(), GrypeAdapter(), TrivyAdapter(), SubfinderAdapter(), HttpxAdapter(), NmapAdapter(), NucleiAdapter(), ZapAdapter(), GitleaksAdapter()]
    items = []
    for adapter in tool_adapters:
        meta = adapter.availability()
        items.append(
            {
                "key": adapter.key,
                "name": adapter.key.title(),
                "category": adapter.category,
                "capabilities": adapter.capabilities,
                "status": "available" if meta["available"] else "unavailable",
                "version": meta["version"],
                "managed": True,
            }
        )
    for adapter in (OsvAdapter(), NvdAdapter()):
        items.append(
            {
                "key": adapter.key,
                "name": adapter.key.upper(),
                "category": adapter.category,
                "capabilities": ["vulnerability_intelligence"],
                "status": "configured",
                "version": None,
                "managed": True,
            }
        )
    items.append(
        {
            "key": "ai_provider",
            "name": "AI Provider",
            "category": "ai",
            "capabilities": ["triage"],
            "status": "configured" if settings.ai_provider != "none" else "heuristic_only",
            "version": settings.ai_provider,
            "managed": True,
        }
    )
    for key, name in (("email", "Email (SMTP)"), ("slack", "Slack"), ("teams", "Microsoft Teams"), ("webhook", "Webhooks")):
        items.append(
            {
                "key": key,
                "name": name,
                "category": "notification",
                "capabilities": ["notifications"],
                "status": "unconfigured",
                "version": None,
                "managed": False,
            }
        )
    return items


def ensure_integration_rows(db: Session, organization_id: uuid.UUID) -> None:
    existing = {row.key for row in db.scalars(select(Integration).where(Integration.organization_id == organization_id)).all()}
    for meta in _available_integrations():
        if meta["key"] in existing:
            continue
        db.add(
            Integration(
                organization_id=organization_id,
                key=meta["key"],
                name=meta["name"],
                category=meta["category"],
                enabled=meta["key"] in {"osv", "nvd"},
                status=meta["status"],
                capabilities=meta["capabilities"],
            )
        )
    db.commit()


@integration_router.get("")
def list_integrations(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.INTEGRATION_READ)),
    db: Session = Depends(get_db),
) -> dict:
    ensure_integration_rows(db, org_id)
    rows = {row.key: row for row in db.scalars(select(Integration).where(Integration.organization_id == org_id)).all()}
    live = {meta["key"]: meta for meta in _available_integrations()}
    items = []
    for key, meta in live.items():
        row = rows.get(key)
        items.append(
            {
                **meta,
                "id": str(row.id) if row else None,
                "enabled": row.enabled if row else False,
                "config": _mask(row.config if row else {}),
                "last_checked_at": iso(row.last_checked_at),
                "last_error": row.last_error if row else None,
            }
        )
    return {"items": items}


@integration_router.patch("/{integration_id}")
def update_integration(
    integration_id: uuid.UUID,
    payload: IntegrationUpdate,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.INTEGRATION_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    integration = scoped_get(db, Integration, integration_id, org_id)
    if payload.enabled is not None:
        integration.enabled = payload.enabled
    if payload.config is not None:
        integration.config = {**integration.config, **payload.config}
    if payload.name:
        integration.name = payload.name
    integration.status = "configured" if integration.enabled else "disabled"
    record_audit(db, user=user, action="integration.updated", resource_type="integration", resource_id=integration.id, details={"enabled": integration.enabled}, request=request)
    db.commit()
    return {**serialize(integration), "config": _mask(integration.config)}


@integration_router.post("/{integration_id}/test")
def test_integration(
    integration_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.INTEGRATION_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    integration = scoped_get(db, Integration, integration_id, org_id)
    live = {meta["key"]: meta for meta in _available_integrations()}
    meta = live.get(integration.key)
    ok = meta is not None and meta["status"] in {"available", "configured"}
    integration.last_checked_at = datetime.now(UTC)
    integration.last_error = None if ok else "Binary or provider unavailable on this host"
    integration.status = "healthy" if ok else "unavailable"
    db.commit()
    return {"key": integration.key, "ok": ok, "status": integration.status, "error": integration.last_error}


@settings_router.get("")
def list_settings(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.SETTINGS_READ)),
    db: Session = Depends(get_db),
) -> dict:
    rows = db.scalars(select(SystemSetting).where(SystemSetting.organization_id == org_id).order_by(SystemSetting.key)).all()
    return {
        "items": [serialize(row) for row in rows],
        "runtime": {
            "environment": settings.app_env,
            "demo_mode": settings.is_demo,
            "ai_provider": settings.ai_provider,
            "oidc_enabled": settings.oidc_enabled,
            "require_scan_authorization": settings.require_scan_authorization,
            "max_upload_mb": settings.max_upload_mb,
            "rate_limit_per_minute": settings.rate_limit_per_minute,
            "celery_eager": settings.celery_always_eager,
        },
    }


@settings_router.put("")
def upsert_setting(
    payload: SettingUpdate,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.SETTINGS_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    setting = db.scalar(select(SystemSetting).where(SystemSetting.organization_id == org_id, SystemSetting.key == payload.key))
    if setting is None:
        setting = SystemSetting(organization_id=org_id, key=payload.key, value=payload.value, description=payload.description, updated_by=user.id)
        db.add(setting)
    else:
        setting.value = payload.value
        setting.description = payload.description or setting.description
        setting.updated_by = user.id
    record_audit(db, user=user, action="settings.updated", resource_type="system_setting", resource_id=payload.key, request=request)
    db.commit()
    return serialize(setting)


@rbac_router.get("")
def rbac_catalog(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.USER_READ)),
    db: Session = Depends(get_db),
) -> dict:
    roles = db.scalars(select(Role).where((Role.organization_id == org_id) | (Role.organization_id.is_(None)))).all()
    permissions = db.scalars(select(PermissionModel).order_by(PermissionModel.category, PermissionModel.key)).all()
    return {
        "roles": [
            {
                "key": role.key,
                "name": ROLE_LABELS.get(role.key, role.name),
                "is_system": role.is_system,
                "permissions": sorted(ROLE_PERMISSIONS.get(role.key, set())),
            }
            for role in roles
        ],
        "permission_catalog": [serialize(permission) for permission in permissions],
        "enforcement": "Backend permission dependencies enforce every protected endpoint; UI visibility is not authorization.",
    }


@admin_router.get("/audit-logs")
def audit_logs(
    params: PageParams = Depends(page_params),
    action: str | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.AUDIT_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(AuditLog).where(AuditLog.organization_id == org_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    items, meta = paginate(
        db,
        stmt,
        params,
        AuditLog,
        search_fields=[AuditLog.action, AuditLog.resource_type, AuditLog.resource_id],
        sortable={"created_at": AuditLog.created_at, "action": AuditLog.action},
        default_sort=AuditLog.created_at,
    )
    return page_response(items, meta)


@admin_router.get("/background-jobs")
def background_jobs(
    params: PageParams = Depends(page_params),
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.AUDIT_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(BackgroundJob).where(BackgroundJob.organization_id == org_id)
    items, meta = paginate(
        db,
        stmt,
        params,
        BackgroundJob,
        search_fields=[BackgroundJob.job_type, BackgroundJob.status],
        sortable={"created_at": BackgroundJob.created_at, "status": BackgroundJob.status},
        default_sort=BackgroundJob.created_at,
    )
    return page_response(items, meta)


@admin_router.get("/metrics")
def metrics(
    _: User = Depends(require_permissions(Permission.SETTINGS_READ)),
) -> dict:
    from app.core.metrics import snapshot

    return snapshot()
