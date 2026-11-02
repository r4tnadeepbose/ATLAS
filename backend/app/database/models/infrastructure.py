import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models.base import Base, SoftDeleteMixin, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin


class Environment(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "environments"
    __table_args__ = (UniqueConstraint("organization_id", "key", name="uq_environments_org_key"),)

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    key: Mapped[str] = mapped_column(String(60), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_production: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, TenantMixin, Base):
    __tablename__ = "assets"

    asset_ref: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    domain: Mapped[str | None] = mapped_column(String(255), index=True)
    subdomain: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(64), index=True)
    port: Mapped[int | None] = mapped_column()
    protocol: Mapped[str | None] = mapped_column(String(20))
    url: Mapped[str | None] = mapped_column(String(500))
    http_status: Mapped[int | None] = mapped_column()
    technology_summary: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    hosting_provider: Mapped[str | None] = mapped_column(String(150))
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    business_unit: Mapped[str | None] = mapped_column(String(120), index=True)
    environment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("environments.id", ondelete="SET NULL"), index=True
    )
    criticality: Mapped[str] = mapped_column(String(30), default="medium", nullable=False)
    exposure: Mapped[str] = mapped_column(String(30), default="internal", nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="active", nullable=False)
    source: Mapped[str] = mapped_column(String(60), default="manual", nullable=False)
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)


class AssetOwner(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "asset_owners"
    __table_args__ = (UniqueConstraint("asset_id", "user_id", name="uq_asset_owner"),)

    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    ownership_type: Mapped[str] = mapped_column(String(40), default="technical", nullable=False)


class Microservice(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, TenantMixin, Base):
    __tablename__ = "microservices"

    service_ref: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    repository_url: Mapped[str | None] = mapped_column(String(500))
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    team_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("teams.id", ondelete="SET NULL"))
    business_unit: Mapped[str | None] = mapped_column(String(120), index=True)
    environment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("environments.id", ondelete="SET NULL"), index=True
    )
    deployment_location: Mapped[str | None] = mapped_column(String(200))
    version: Mapped[str | None] = mapped_column(String(80))
    language: Mapped[str | None] = mapped_column(String(60))
    tech_stack: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    criticality: Mapped[str] = mapped_column(String(30), default="medium", nullable=False)
    security_posture: Mapped[str] = mapped_column(String(30), default="unknown", nullable=False)
    risk_level: Mapped[str] = mapped_column(String(30), default="medium", nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    last_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(30), default="active", nullable=False)
    tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)


class ServiceDependency(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "service_dependencies"
    __table_args__ = (
        UniqueConstraint("source_service_id", "target_service_id", "dependency_type", name="uq_service_dependency"),
    )

    source_service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("microservices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    target_service_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("microservices.id", ondelete="CASCADE"), index=True
    )
    target_external: Mapped[str | None] = mapped_column(String(255))
    dependency_type: Mapped[str] = mapped_column(String(40), default="http", nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class AssetRelationship(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "asset_relationships"

    source_asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    relationship_type: Mapped[str] = mapped_column(String(60), default="connects_to", nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class NetworkService(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "network_services"

    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False)
    port: Mapped[int] = mapped_column(nullable=False)
    protocol: Mapped[str] = mapped_column(String(20), default="tcp", nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(80))
    product: Mapped[str | None] = mapped_column(String(150))
    version: Mapped[str | None] = mapped_column(String(80))
    state: Mapped[str] = mapped_column(String(30), default="open", nullable=False)
    banner: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DiscoveredSubdomain(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "discovered_subdomains"

    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    subdomain: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(80), default="subfinder", nullable=False)
    resolved_ips: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="active", nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Technology(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "technologies"

    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    version: Mapped[str | None] = mapped_column(String(80))
    category: Mapped[str | None] = mapped_column(String(80))
    confidence: Mapped[float] = mapped_column(Float, default=0.8, nullable=False)


class Certificate(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "certificates"

    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    common_name: Mapped[str] = mapped_column(String(255), nullable=False)
    issuer: Mapped[str | None] = mapped_column(String(255))
    serial_number: Mapped[str | None] = mapped_column(String(120))
    fingerprint: Mapped[str | None] = mapped_column(String(200))
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(30), default="valid", nullable=False)
