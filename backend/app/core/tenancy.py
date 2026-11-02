import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError


def scoped_get(db: Session, model: Any, object_id: uuid.UUID, organization_id: uuid.UUID) -> Any:
    obj = db.get(model, object_id)
    if obj is None or getattr(obj, "organization_id", None) != organization_id:
        raise NotFoundError(f"{model.__name__} not found")
    return obj


def scoped_query(model: Any, organization_id: uuid.UUID):
    return model.organization_id == organization_id
