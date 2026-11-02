import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import PageParams, get_db, get_org_id, page_params, paginate, page_response, serialize
from app.config import settings
from app.core.audit import record_audit
from app.core.exceptions import NotFoundError
from app.core.permissions import Permission, User, require_permissions
from app.core.tenancy import scoped_get
from app.database.models.findings import Finding
from app.database.models.ops import AiAnalysisHistory, AiModelConfiguration, AiPromptVersion
from app.modules.ai_triage import service

router = APIRouter(prefix="/triage", tags=["AI Triage"])


class AnalyzeRequest(BaseModel):
    finding_id: uuid.UUID


class BatchRequest(BaseModel):
    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=20)


class ModelConfigRequest(BaseModel):
    provider: str = Field(pattern="^(none|openai|anthropic|ollama|openai_compatible)$")
    model: str
    base_url: str | None = None
    max_tokens: int = 1600
    temperature: float = 0.2
    is_default: bool = True
    enabled: bool = True


@router.get("/queue")
def triage_queue(
    params: PageParams = Depends(page_params),
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.FINDING_TRIAGE)),
    db: Session = Depends(get_db),
) -> dict:
    triaged_ids = select(AiAnalysisHistory.finding_id).where(
        AiAnalysisHistory.organization_id == org_id, AiAnalysisHistory.finding_id.is_not(None)
    )
    stmt = (
        select(Finding)
        .where(
            Finding.organization_id == org_id,
            Finding.deleted_at.is_(None),
            Finding.status.in_(("open", "triaged", "in_progress", "assigned")),
            Finding.id.notin_(triaged_ids),
        )
        .order_by(Finding.risk_score.desc())
    )
    items, meta = paginate(
        db,
        stmt,
        params,
        Finding,
        search_fields=[Finding.title, Finding.finding_ref, Finding.cve_id],
        sortable={"risk_score": Finding.risk_score, "first_seen": Finding.first_seen},
        default_sort=Finding.risk_score,
    )
    from app.database.models.infrastructure import Asset, Microservice

    assets = {asset.id: asset.name for asset in db.scalars(select(Asset).where(Asset.organization_id == org_id)).all()}
    services = {service.id: service.name for service in db.scalars(select(Microservice).where(Microservice.organization_id == org_id)).all()}
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


@router.get("/results")
def list_results(
    params: PageParams = Depends(page_params),
    provider: str | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.FINDING_READ)),
    db: Session = Depends(get_db),
) -> dict:
    from app.database.models.ops import AiTriageResult

    stmt = select(AiTriageResult).where(AiTriageResult.organization_id == org_id)
    if provider:
        stmt = stmt.where(AiTriageResult.provider == provider)
    items, meta = paginate(
        db,
        stmt,
        params,
        AiTriageResult,
        search_fields=[AiTriageResult.summary],
        sortable={"created_at": AiTriageResult.created_at, "confidence": AiTriageResult.confidence},
        default_sort=AiTriageResult.created_at,
    )
    findings = {
        finding.id: finding for finding in db.scalars(select(Finding).where(Finding.organization_id == org_id, Finding.id.in_([item.finding_id for item in items]))).all()
    }
    return {
        "items": [
            {
                **serialize(item),
                "finding_title": findings[item.finding_id].title if item.finding_id in findings else None,
                "finding_ref": findings[item.finding_id].finding_ref if item.finding_id in findings else None,
                "finding_severity": findings[item.finding_id].severity if item.finding_id in findings else None,
            }
            for item in items
        ],
        "pagination": meta,
    }


@router.get("/dashboard")
def triage_dashboard(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.FINDING_READ)),
    db: Session = Depends(get_db),
) -> dict:
    from app.database.models.ops import AiTriageResult

    results = db.scalars(select(AiTriageResult).where(AiTriageResult.organization_id == org_id)).all()
    triaged_findings = {result.finding_id for result in results}
    open_findings = db.scalar(
        select(func.count(Finding.id)).where(
            Finding.organization_id == org_id,
            Finding.deleted_at.is_(None),
            Finding.status.in_(("open", "triaged", "in_progress", "assigned")),
        )
    ) or 0
    by_provider = dict(
        db.execute(
            select(AiTriageResult.provider, func.count(AiTriageResult.id))
            .where(AiTriageResult.organization_id == org_id)
            .group_by(AiTriageResult.provider)
        ).all()
    )
    return {
        "open_findings": open_findings,
        "triaged": len(triaged_findings & {finding.id for finding in db.scalars(select(Finding).where(Finding.organization_id == org_id)).all()}),
        "pending": max(0, open_findings - len(triaged_findings)),
        "by_provider": [{"name": key, "value": value} for key, value in by_provider.items()],
        "average_confidence": round(sum(result.confidence for result in results) / len(results), 2) if results else 0,
        "configured_provider": settings.ai_provider,
        "recent": [serialize(result) for result in sorted(results, key=lambda r: r.created_at or datetime.min.replace(tzinfo=UTC), reverse=True)[:6]],
    }


@router.post("/analyze")
def analyze(
    payload: AnalyzeRequest,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.FINDING_TRIAGE)),
    db: Session = Depends(get_db),
) -> dict:
    finding = scoped_get(db, Finding, payload.finding_id, org_id)
    service.ensure_prompt(db, org_id)
    config = service.resolve_provider_config(db, org_id)
    result = service.triage(db, organization_id=org_id, finding=finding, provider_config=config)
    record_audit(db, user=user, action="triage.analyzed", resource_type="finding", resource_id=finding.id, details={"provider": result["provider"]}, request=request)
    db.commit()
    return result


@router.post("/batch")
def analyze_batch(
    payload: BatchRequest,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.FINDING_TRIAGE)),
    db: Session = Depends(get_db),
) -> dict:
    service.ensure_prompt(db, org_id)
    config = service.resolve_provider_config(db, org_id)
    results = []
    for finding_id in payload.finding_ids:
        finding = scoped_get(db, Finding, finding_id, org_id)
        results.append(service.triage(db, organization_id=org_id, finding=finding, provider_config=config))
    return {"items": results}


@router.get("/config")
def get_config(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.FINDING_READ)),
    db: Session = Depends(get_db),
) -> dict:
    configs = db.scalars(select(AiModelConfiguration).where(AiModelConfiguration.organization_id == org_id)).all()
    prompts = db.scalars(select(AiPromptVersion).where(AiPromptVersion.organization_id == org_id)).all()
    return {
        "environment_provider": settings.ai_provider,
        "environment_model": settings.ai_model,
        "configurations": [serialize(config) for config in configs],
        "prompts": [serialize(prompt, exclude={"template"}) for prompt in prompts],
        "advisory_notice": "AI output is advisory only. It never modifies findings, executes remediation, or closes findings.",
    }


@router.post("/config", status_code=201)
def create_config(
    payload: ModelConfigRequest,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.SETTINGS_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    if payload.is_default:
        for existing in db.scalars(select(AiModelConfiguration).where(AiModelConfiguration.organization_id == org_id)).all():
            existing.is_default = False
    config = AiModelConfiguration(
        organization_id=org_id,
        provider=payload.provider,
        model=payload.model,
        base_url=payload.base_url,
        max_tokens=payload.max_tokens,
        temperature=payload.temperature,
        is_default=payload.is_default,
        enabled=payload.enabled,
    )
    db.add(config)
    db.commit()
    return serialize(config)


@router.get("/{triage_id}")
def get_result(
    triage_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.FINDING_READ)),
    db: Session = Depends(get_db),
) -> dict:
    from app.database.models.ops import AiTriageResult

    result = scoped_get(db, AiTriageResult, triage_id, org_id)
    history = db.scalars(select(AiAnalysisHistory).where(AiAnalysisHistory.triage_id == result.id)).all()
    return {**serialize(result), "history": [serialize(entry) for entry in history]}
