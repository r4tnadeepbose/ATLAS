import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin


class ScanJob(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "scan_jobs"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    scope: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    options: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    adapter: Mapped[str | None] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(30), default="queued", index=True, nullable=False)
    progress: Mapped[int] = mapped_column(default=0, nullable=False)
    current_step: Mapped[str | None] = mapped_column(String(200))
    findings_count: Mapped[int] = mapped_column(default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancellation_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    authorized_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    authorization_reference: Mapped[str | None] = mapped_column(String(200))


class ScanResult(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "scan_results"

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    tool: Mapped[str] = mapped_column(String(50), nullable=False)
    result_type: Mapped[str] = mapped_column(String(50), default="observation", nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    severity: Mapped[str | None] = mapped_column(String(30))
    target: Mapped[str | None] = mapped_column(String(500))


class ScanHistory(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "scan_history"

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    event: Mapped[str] = mapped_column(String(60), nullable=False)
    message: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class ScanSchedule(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "scan_schedules"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    cron: Mapped[str] = mapped_column(String(80), nullable=False)
    scope: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ScanLog(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "scan_logs"

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    level: Mapped[str] = mapped_column(String(20), default="info", nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
