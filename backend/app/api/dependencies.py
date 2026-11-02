import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from fastapi import Depends, Query
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.core.exceptions import ValidationError
from app.core.permissions import get_current_user
from app.core.time import iso
from app.database.models.identity import User
from app.database.session import get_db

__all__ = ["get_current_user", "get_db", "PageParams", "paginate", "get_org_id", "CurrentUser"]


@dataclass
class PageParams:
    page: int
    page_size: int
    q: str | None
    sort_by: str | None
    sort_dir: str


def page_params(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    q: str | None = Query(None, max_length=200),
    sort_by: str | None = Query(None, max_length=60),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
) -> PageParams:
    return PageParams(page=page, page_size=page_size, q=q, sort_by=sort_by, sort_dir=sort_dir)


def get_org_id(user: User = Depends(get_current_user)) -> uuid.UUID:
    return user.organization_id


CurrentUser = User


def paginate(
    db: Session,
    stmt: Select,
    params: PageParams,
    model: Any,
    *,
    search_fields: list[Any] | None = None,
    sortable: dict[str, Any] | None = None,
    default_sort: Any | None = None,
) -> tuple[list[Any], dict]:
    if params.q and search_fields:
        like = f"%{params.q.strip()}%"
        from sqlalchemy import or_

        stmt = stmt.where(or_(*[field.ilike(like) for field in search_fields]))

    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = db.scalar(count_stmt) or 0

    sort_column = None
    if params.sort_by:
        if not sortable or params.sort_by not in sortable:
            raise ValidationError(f"Unsupported sort field '{params.sort_by}'", details={"allowed": sorted((sortable or {}).keys())})
        sort_column = sortable[params.sort_by]
    elif default_sort is not None:
        sort_column = default_sort

    if sort_column is not None:
        stmt = stmt.order_by(sort_column.desc() if params.sort_dir == "desc" else sort_column.asc())

    stmt = stmt.offset((params.page - 1) * params.page_size).limit(params.page_size)
    items = list(db.scalars(stmt).unique())
    pages = (total + params.page_size - 1) // params.page_size if params.page_size else 0
    meta = {
        "page": params.page,
        "page_size": params.page_size,
        "total": total,
        "pages": pages,
        "has_next": params.page < pages,
        "has_prev": params.page > 1,
    }
    return items, meta


def serialize(obj: Any, *, exclude: set[str] | None = None, extra: dict | None = None) -> dict:
    if obj is None:
        return {}
    exclude = exclude or set()
    data: dict[str, Any] = {}
    for column in obj.__mapper__.columns:
        key = column.key
        if key in exclude:
            continue
        value = getattr(obj, key)
        if isinstance(value, uuid.UUID):
            value = str(value)
        elif isinstance(value, datetime):
            value = iso(value)
        data[key] = value
    if extra:
        data.update(extra)
    return data


def page_response(items: list[Any], meta: dict, *, exclude: set[str] | None = None) -> dict:
    return {"items": [serialize(item, exclude=exclude) for item in items], "pagination": meta}


def touch(obj: Any) -> None:
    obj.updated_at = datetime.utcnow()
