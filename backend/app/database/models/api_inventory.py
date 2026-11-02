import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models.base import Base, SoftDeleteMixin, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin


class Api(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, TenantMixin, Base):
    __tablename__ = "apis"

    api_ref: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(500))
    service_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("microservices.id", ondelete="SET NULL"), index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    environment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("environments.id", ondelete="SET NULL"), index=True
    )
    version: Mapped[str | None] = mapped_column(String(40))
    auth_type: Mapped[str] = mapped_column(String(50), default="unknown", nullable=False)
    authorization_model: Mapped[str | None] = mapped_column(String(80))
    content_type: Mapped[str] = mapped_column(String(80), default="application/json", nullable=False)
    data_sensitivity: Mapped[str] = mapped_column(String(40), default="internal", nullable=False)
    exposure: Mapped[str] = mapped_column(String(30), default="internal", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="active", nullable=False)
    security_status: Mapped[str] = mapped_column(String(30), default="unreviewed", nullable=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_observed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    description: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)


class ApiEndpoint(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "api_endpoints"

    api_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("apis.id", ondelete="CASCADE"), index=True, nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str | None] = mapped_column(String(500))
    auth_required: Mapped[bool | None] = mapped_column(Boolean)
    data_sensitivity: Mapped[str] = mapped_column(String(40), default="internal", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="active", nullable=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    parameters: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    last_observed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ApiAuthentication(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "api_authentication"

    api_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("apis.id", ondelete="CASCADE"), index=True, nullable=False)
    scheme: Mapped[str] = mapped_column(String(80), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    enforced: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class ApiSpecification(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "api_specifications"

    api_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("apis.id", ondelete="SET NULL"), index=True)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    format: Mapped[str] = mapped_column(String(30), default="openapi", nullable=False)
    spec_version: Mapped[str | None] = mapped_column(String(30))
    content: Mapped[str] = mapped_column(Text, nullable=False)
    endpoint_count: Mapped[int] = mapped_column(default=0, nullable=False)
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ApiSecurityFinding(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "api_security_findings"

    api_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("apis.id", ondelete="CASCADE"), index=True, nullable=False)
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("api_endpoints.id", ondelete="SET NULL"))
    check_key: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="open", nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.7, nullable=False)
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
