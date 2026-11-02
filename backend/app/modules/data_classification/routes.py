import uuid

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import PageParams, get_db, get_org_id, page_params, paginate, page_response, serialize
from app.core.audit import record_audit
from app.core.permissions import Permission, User, require_permissions
from app.core.tenancy import scoped_get
from app.database.models.classification import ClassificationRule, DataClassification, SensitiveDataFinding
from app.modules.data_classification import service

router = APIRouter(prefix="/classification", tags=["Data Classification"])


class AnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=200_000)
    source_label: str = Field(default="manual submission", max_length=300)
    asset_id: uuid.UUID | None = None
    microservice_id: uuid.UUID | None = None
    service_name: str | None = None


class RuleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    category: str = Field(min_length=2, max_length=80)
    detection_method: str = Field(default="regex", pattern="^(regex|entropy|pattern|structured|ai)$")
    pattern: str | None = None
    severity: str = "medium"
    confidence_weight: float = Field(default=0.8, ge=0, le=1)
    enabled: bool = True
    description: str | None = None


class RuleUpdate(BaseModel):
    name: str | None = None
    category: str | None = None
    pattern: str | None = None
    severity: str | None = None
    confidence_weight: float | None = None
    enabled: bool | None = None
    description: str | None = None


@router.get("")
def list_classifications(
    params: PageParams = Depends(page_params),
    category: str | None = None,
    risk: str | None = None,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.CLASSIFICATION_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(DataClassification).where(DataClassification.organization_id == org_id)
    if category:
        stmt = stmt.where(DataClassification.category == category)
    if risk:
        stmt = stmt.where(DataClassification.risk_classification == risk)
    items, meta = paginate(
        db,
        stmt,
        params,
        DataClassification,
        search_fields=[DataClassification.service_name, DataClassification.exposure_location, DataClassification.category],
        sortable={"created_at": DataClassification.created_at, "confidence": DataClassification.confidence},
        default_sort=DataClassification.created_at,
    )
    return page_response(items, meta)


@router.get("/dashboard")
def classification_dashboard(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.CLASSIFICATION_READ)),
    db: Session = Depends(get_db),
) -> dict:
    by_category = db.execute(
        select(DataClassification.category, func.count(DataClassification.id))
        .where(DataClassification.organization_id == org_id)
        .group_by(DataClassification.category)
    ).all()
    by_method = db.execute(
        select(DataClassification.detection_method, func.count(DataClassification.id))
        .where(DataClassification.organization_id == org_id)
        .group_by(DataClassification.detection_method)
    ).all()
    recent = db.scalars(
        select(DataClassification).where(DataClassification.organization_id == org_id).order_by(DataClassification.created_at.desc()).limit(10)
    ).all()
    return {
        "total": db.scalar(select(func.count(DataClassification.id)).where(DataClassification.organization_id == org_id)) or 0,
        "credentials": db.scalar(
            select(func.count(DataClassification.id)).where(
                DataClassification.organization_id == org_id,
                DataClassification.category.in_(("credentials", "api_keys", "access_tokens")),
            )
        ) or 0,
        "pii": db.scalar(select(func.count(DataClassification.id)).where(DataClassification.organization_id == org_id, DataClassification.category == "pii")) or 0,
        "by_category": [{"name": row[0], "value": row[1]} for row in by_category],
        "by_method": [{"name": row[0], "value": row[1]} for row in by_method],
        "recent": [serialize(item) for item in recent],
        "rules": db.scalar(select(func.count(ClassificationRule.id)).where(ClassificationRule.organization_id == org_id)) or 0,
    }


@router.post("/analyze")
def analyze(
    payload: AnalyzeRequest,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.CLASSIFICATION_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    result = service.analyze_text(
        db,
        organization_id=org_id,
        text=payload.text,
        source_label=payload.source_label,
        asset_id=payload.asset_id,
        microservice_id=payload.microservice_id,
        service_name=payload.service_name,
    )
    record_audit(db, user=user, action="classification.analyzed", resource_type="data_classification", details={"detections": result["detections"]}, request=request)
    db.commit()
    return result


@router.get("/rules")
def list_rules(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.CLASSIFICATION_READ)),
    db: Session = Depends(get_db),
) -> dict:
    rules = db.scalars(select(ClassificationRule).where(ClassificationRule.organization_id == org_id).order_by(ClassificationRule.category)).all()
    return {"items": [serialize(rule) for rule in rules]}


@router.post("/rules", status_code=201)
def create_rule(
    payload: RuleCreate,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.CLASSIFICATION_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    if payload.detection_method == "regex" and payload.pattern:
        import re

        try:
            re.compile(payload.pattern)
        except re.error as exc:
            from app.core.exceptions import ValidationError

            raise ValidationError(f"Invalid regex: {exc}") from exc
    rule = ClassificationRule(organization_id=org_id, **payload.model_dump())
    db.add(rule)
    db.commit()
    return serialize(rule)


@router.patch("/rules/{rule_id}")
def update_rule(
    rule_id: uuid.UUID,
    payload: RuleUpdate,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.CLASSIFICATION_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    rule = scoped_get(db, ClassificationRule, rule_id, org_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)
    db.commit()
    return serialize(rule)


@router.get("/{classification_id}")
def get_classification(
    classification_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.CLASSIFICATION_READ)),
    db: Session = Depends(get_db),
) -> dict:
    classification = scoped_get(db, DataClassification, classification_id, org_id)
    findings = db.scalars(select(SensitiveDataFinding).where(SensitiveDataFinding.classification_id == classification.id)).all()
    return {**serialize(classification), "detections": [serialize(finding) for finding in findings]}


@router.post("/seed-rules")
def seed_default_rules(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.CLASSIFICATION_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    created = service.seed_rules(db, org_id)
    return {"created": created}
