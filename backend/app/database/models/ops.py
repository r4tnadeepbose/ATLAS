import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin


class AiTriageResult(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "ai_triage_results"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(30), default="completed", nullable=False)
    classification: Mapped[str | None] = mapped_column(String(120))
    summary: Mapped[str | None] = mapped_column(Text)
    technical_impact: Mapped[str | None] = mapped_column(Text)
    business_impact: Mapped[str | None] = mapped_column(Text)
    recommendation: Mapped[str | None] = mapped_column(Text)
    priority: Mapped[str] = mapped_column(String(30), default="medium", nullable=False)
    false_positive_likelihood: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    structured: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    prompt_version: Mapped[str | None] = mapped_column(String(30))
    tokens_input: Mapped[int] = mapped_column(default=0, nullable=False)
    tokens_output: Mapped[int] = mapped_column(default=0, nullable=False)
    latency_ms: Mapped[int] = mapped_column(default=0, nullable=False)
    advisory_only: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class AiAnalysisHistory(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "ai_analysis_history"

    triage_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("ai_triage_results.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    request_summary: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    response_summary: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    latency_ms: Mapped[int] = mapped_column(default=0, nullable=False)
    token_usage: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    outcome: Mapped[str] = mapped_column(String(30), default="success", nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)


class AiModelConfiguration(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "ai_model_configurations"

    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(120), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(400))
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    max_tokens: Mapped[int] = mapped_column(default=1600, nullable=False)
    temperature: Mapped[float] = mapped_column(Float, default=0.2, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)


class AiPromptVersion(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "ai_prompt_versions"
    __table_args__ = (UniqueConstraint("prompt_key", "version", name="uq_prompt_key_version"),)

    prompt_key: Mapped[str] = mapped_column(String(80), default="finding_triage", nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False)
    template: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class NotificationRule(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "notification_rules"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    event_key: Mapped[str] = mapped_column(String(100), nullable=False)
    min_severity: Mapped[str] = mapped_column(String(30), default="medium", nullable=False)
    channels: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    dedup_window_minutes: Mapped[int] = mapped_column(default=30, nullable=False)
    config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class Report(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "reports"

    report_type: Mapped[str] = mapped_column(String(60), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(250), nullable=False)
    format: Mapped[str] = mapped_column(String(20), default="json", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="completed", nullable=False)
    params: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    summary: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    generated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Integration(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "integrations"

    key: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(60), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="unconfigured", nullable=False)
    config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    capabilities: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)


class SystemSetting(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "system_settings"
    __table_args__ = (UniqueConstraint("organization_id", "key", name="uq_settings_org_key"),)

    key: Mapped[str] = mapped_column(String(120), nullable=False)
    value: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class BackgroundJob(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "background_jobs"

    job_type: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="queued", index=True, nullable=False)
    progress: Mapped[int] = mapped_column(default=0, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    result: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    celery_id: Mapped[str | None] = mapped_column(String(120))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Notification(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "notifications"

    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    channel: Mapped[str] = mapped_column(String(40), default="in_app", nullable=False)
    event_key: Mapped[str] = mapped_column(String(100), nullable=False)
    subject: Mapped[str] = mapped_column(String(300), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(30), default="info", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="pending", nullable=False)
    provider_message_id: Mapped[str | None] = mapped_column(String(200))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dedup_key: Mapped[str | None] = mapped_column(String(300), index=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
