import uuid

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, get_org_id, serialize
from app.auth.schemas import OrganizationUpdateRequest, TeamCreateRequest
from app.core.audit import record_audit
from app.core.exceptions import ConflictError, NotFoundError
from app.core.permissions import Permission, get_current_user, require_permissions
from app.database.models.identity import AuditLog, Organization, Team, User

router = APIRouter(prefix="/organizations", tags=["Organizations"])


class EnvironmentCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    key: str = Field(min_length=2, max_length=60, pattern="^[a-z0-9-]+$")
    description: str | None = None
    is_production: bool = False


@router.get("/current")
def current_organization(
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    org = db.get(Organization, org_id)
    if org is None:
        raise NotFoundError("Organization not found")
    return {
        **serialize(org),
        "member_count": len(db.scalars(select(User).where(User.organization_id == org_id, User.deleted_at.is_(None))).all()),
    }


@router.patch("/current")
def update_organization(
    payload: OrganizationUpdateRequest,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.ORG_ADMIN)),
    db: Session = Depends(get_db),
) -> dict:
    org = db.get(Organization, org_id)
    if org is None:
        raise NotFoundError("Organization not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(org, field, value)
    record_audit(db, user=user, action="organization.updated", resource_type="organization", resource_id=org.id, request=request)
    db.commit()
    return serialize(org)


@router.get("/teams")
def list_teams(org_id: uuid.UUID = Depends(get_org_id), db: Session = Depends(get_db)) -> dict:
    teams = db.scalars(select(Team).where(Team.organization_id == org_id).order_by(Team.name)).all()
    return {"items": [serialize(team) for team in teams]}


@router.post("/teams", status_code=201)
def create_team(
    payload: TeamCreateRequest,
    request: Request,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.ORG_ADMIN)),
    db: Session = Depends(get_db),
) -> dict:
    slug = payload.name.lower().replace(" ", "-")[:80]
    if db.scalar(select(Team).where(Team.organization_id == org_id, Team.slug == slug)):
        raise ConflictError("A team with that name already exists")
    team = Team(
        organization_id=org_id,
        name=payload.name,
        slug=slug,
        description=payload.description,
        business_unit=payload.business_unit,
    )
    db.add(team)
    record_audit(db, user=user, action="team.created", resource_type="team", resource_id=team.id, request=request)
    db.commit()
    return serialize(team)


@router.get("/audit-logs")
def audit_logs(
    limit: int = 50,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.AUDIT_READ)),
    db: Session = Depends(get_db),
) -> dict:
    entries = db.scalars(
        select(AuditLog).where(AuditLog.organization_id == org_id).order_by(AuditLog.created_at.desc()).limit(min(limit, 200))
    ).all()
    return {"items": [serialize(entry) for entry in entries]}
