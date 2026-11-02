import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import PageParams, get_db, get_org_id, page_params, paginate, serialize
from app.auth import service
from app.auth.schemas import UserCreateRequest, UserUpdateRequest
from app.core.audit import record_audit
from app.core.exceptions import ConflictError, ForbiddenError, NotFoundError
from app.core.permissions import Permission, get_current_user, require_permissions
from app.database.models.identity import Role, User, UserRole

router = APIRouter(prefix="/users", tags=["User Management"])


@router.get("")
def list_users(
    params: PageParams = Depends(page_params),
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.USER_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(User).where(User.organization_id == org_id, User.deleted_at.is_(None))
    items, meta = paginate(
        db,
        stmt,
        params,
        User,
        search_fields=[User.email, User.full_name],
        sortable={"email": User.email, "full_name": User.full_name, "created_at": User.created_at},
        default_sort=User.created_at,
    )
    return {
        "items": [
            {
                **serialize(item, exclude={"hashed_password", "mfa_secret"}),
                "roles": item.role_keys(),
                "role_labels": item.role_keys(),
            }
            for item in items
        ],
        "pagination": meta,
    }


@router.post("", status_code=201)
def create_user(
    payload: UserCreateRequest,
    request: Request,
    user: User = Depends(require_permissions(Permission.USER_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    created = service.create_user(db, user.organization_id, payload)
    record_audit(
        db,
        user=user,
        action="user.created",
        resource_type="user",
        resource_id=created.id,
        details={"email": created.email, "role": payload.role},
        request=request,
    )
    db.commit()
    return {**serialize(created, exclude={"hashed_password", "mfa_secret"}), "roles": created.role_keys()}


@router.patch("/{user_id}")
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdateRequest,
    request: Request,
    actor: User = Depends(require_permissions(Permission.USER_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    target = db.get(User, user_id)
    if target is None or target.organization_id != actor.organization_id:
        raise NotFoundError("User not found")
    if target.id == actor.id and payload.is_active is False:
        raise ForbiddenError("You cannot deactivate your own account")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(target, field, value)
    record_audit(
        db, user=actor, action="user.updated", resource_type="user", resource_id=target.id, details=payload.model_dump(exclude_unset=True), request=request
    )
    db.commit()
    return {**serialize(target, exclude={"hashed_password", "mfa_secret"}), "roles": target.role_keys()}


@router.patch("/{user_id}/role")
def change_role(
    user_id: uuid.UUID,
    payload: dict,
    request: Request,
    actor: User = Depends(require_permissions(Permission.USER_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    role_key = payload.get("role")
    target = db.get(User, user_id)
    if target is None or target.organization_id != actor.organization_id:
        raise NotFoundError("User not found")
    if target.id == actor.id:
        raise ForbiddenError("You cannot change your own role")
    service.set_user_role(db, target, role_key)
    record_audit(
        db, user=actor, action="user.role_changed", resource_type="user", resource_id=target.id, details={"role": role_key}, request=request
    )
    db.commit()
    return {**serialize(target, exclude={"hashed_password", "mfa_secret"}), "roles": target.role_keys()}


@router.get("/roles/catalog")
def role_catalog(
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.USER_READ)),
    db: Session = Depends(get_db),
) -> dict:
    roles = db.scalars(
        select(Role).where((Role.organization_id == org_id) | (Role.organization_id.is_(None)))
    ).all()
    return {
        "items": [
            {
                **serialize(role),
                "permissions": sorted(
                    service.ROLE_PERMISSIONS.get(role.key, set())
                ),
            }
            for role in roles
        ]
    }


@router.get("/{user_id}")
def get_user(
    user_id: uuid.UUID,
    actor: User = Depends(require_permissions(Permission.USER_READ)),
    db: Session = Depends(get_db),
) -> dict:
    target = db.get(User, user_id)
    if target is None or target.organization_id != actor.organization_id:
        raise NotFoundError("User not found")
    return {**serialize(target, exclude={"hashed_password", "mfa_secret"}), "roles": target.role_keys()}
