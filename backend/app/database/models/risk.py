import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin


class RiskAssessment(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "risk_assessments"

    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    microservice_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("microservices.id", ondelete="SET NULL"), index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), index=True)
    score: Mapped[float] = mapped_column(Float, default=0.0, index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(30), default="info", nullable=False)
    business_impact: Mapped[str | None] = mapped_column(Text)
    business_unit: Mapped[str | None] = mapped_column(String(120), index=True)
    responsible_team: Mapped[str | None] = mapped_column(String(150))
    remediation_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(30), default="open", index=True, nullable=False)
    rationale: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    model_version: Mapped[str] = mapped_column(String(30), default="1.0", nullable=False)
    accepted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RiskScore(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "risk_scores"

    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("risk_assessments.id", ondelete="CASCADE"), index=True, nullable=False
    )
    factors: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    computed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RiskException(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "risk_exceptions"

    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("risk_assessments.id", ondelete="SET NULL"), index=True
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str] = mapped_column(String(200), default="asset", nullable=False)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approved_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(30), default="pending", nullable=False)


class RemediationTask(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "remediation_tasks"
    __table_args__ = (UniqueConstraint("finding_id", name="uq_remediation_finding"),)

    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    priority: Mapped[str] = mapped_column(String(30), default="medium", nullable=False)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(30), default="open", index=True, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence: Mapped[str | None] = mapped_column(Text)
