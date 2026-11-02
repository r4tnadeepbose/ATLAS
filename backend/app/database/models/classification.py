import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin


class ClassificationRule(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "classification_rules"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    detection_method: Mapped[str] = mapped_column(String(40), default="regex", nullable=False)
    pattern: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(30), default="medium", nullable=False)
    confidence_weight: Mapped[float] = mapped_column(Float, default=0.8, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)


class DataClassification(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "data_classifications"

    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    microservice_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("microservices.id", ondelete="SET NULL"), index=True
    )
    category: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    detection_method: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.7, nullable=False)
    exposure_location: Mapped[str | None] = mapped_column(String(500))
    service_name: Mapped[str | None] = mapped_column(String(200))
    risk_classification: Mapped[str] = mapped_column(String(30), default="medium", nullable=False)
    remediation: Mapped[str | None] = mapped_column(Text)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SensitiveDataFinding(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "sensitive_data_findings"

    classification_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("data_classifications.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("classification_rules.id", ondelete="SET NULL"))
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    redacted_sample: Mapped[str | None] = mapped_column(String(500))
    location: Mapped[str | None] = mapped_column(String(500))
    confidence: Mapped[float] = mapped_column(Float, default=0.7, nullable=False)
    severity: Mapped[str] = mapped_column(String(30), default="medium", nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
