import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import PageParams, get_db, get_org_id, page_params, paginate, page_response, serialize
from app.core.audit import record_audit
from app.core.permissions import Permission, User, require_permissions
from app.database.models.ops import Report
from app.modules.reporting import service

router = APIRouter(prefix="/reports", tags=["Security Reports"])


class ReportCreate(BaseModel):
    report_type: str
    format: str = "json"


@router.get("")
def list_reports(
    params: PageParams = Depends(page_params),
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.REPORT_READ)),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(Report).where(Report.organization_id == org_id)
    items, meta = paginate(
        db,
        stmt,
        params,
        Report,
        search_fields=[Report.title, Report.report_type],
        sortable={"created_at": Report.created_at, "title": Report.title},
        default_sort=Report.created_at,
    )
    return page_response(items, meta)


@router.get("/types")
def report_types(_: User = Depends(require_permissions(Permission.REPORT_READ))) -> dict:
    return {"items": [{"key": key, "name": name} for key, name in service.REPORT_TYPES.items()]}


@router.post("", status_code=201)
def create_report(
    payload: ReportCreate,
    org_id: uuid.UUID = Depends(get_org_id),
    user: User = Depends(require_permissions(Permission.REPORT_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    if payload.format not in {"json", "csv", "pdf"}:
        from app.core.exceptions import ValidationError

        raise ValidationError("Format must be json, csv or pdf")
    report = service.build_report(db, org_id, payload.report_type)
    record = Report(
        organization_id=org_id,
        report_type=payload.report_type,
        title=report["title"],
        format=payload.format,
        status="completed",
        params={"format": payload.format},
        summary={"generated_at": report["generated_at"], "sections": list(report["data"].keys())},
        generated_by=user.id,
        generated_at=datetime.now(UTC),
    )
    db.add(record)
    db.commit()
    return serialize(record)


@router.get("/{report_id}/download")
def download_report(
    report_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.REPORT_READ)),
    db: Session = Depends(get_db),
) -> Response:
    record = db.get(Report, report_id)
    if record is None or record.organization_id != org_id:
        from app.core.exceptions import NotFoundError

        raise NotFoundError("Report not found")
    report = service.build_report(db, org_id, record.report_type)
    filename = f"atlas-{record.report_type}-{record.id}"
    if record.format == "csv":
        return Response(
            content=service.to_csv(report),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'},
        )
    if record.format == "pdf":
        return Response(
            content=service.to_pdf(report),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}.pdf"'},
        )
    return Response(content=__import__("json").dumps(report, indent=2), media_type="application/json")


@router.get("/{report_id}")
def get_report(
    report_id: uuid.UUID,
    org_id: uuid.UUID = Depends(get_org_id),
    _: User = Depends(require_permissions(Permission.REPORT_READ)),
    db: Session = Depends(get_db),
) -> dict:
    record = db.get(Report, report_id)
    if record is None or record.organization_id != org_id:
        from app.core.exceptions import NotFoundError

        raise NotFoundError("Report not found")
    return {**serialize(record), "content": service.build_report(db, org_id, record.report_type)["data"]}
