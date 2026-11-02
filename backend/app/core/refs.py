import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session


def next_ref(db: Session, model, ref_field: str, prefix: str, org_id: uuid.UUID) -> str:
    column = getattr(model, ref_field)
    count = db.scalar(select(func.count(model.id)).where(model.organization_id == org_id)) or 0
    while True:
        count += 1
        candidate = f"{prefix}-{count:05d}"
        if db.scalar(select(model.id).where(model.organization_id == org_id, column == candidate)) is None:
            return candidate
