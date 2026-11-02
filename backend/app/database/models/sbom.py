import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin


class SbomDocument(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "sbom_documents"

    name: Mapped[str] = mapped_column(String(250), nullable=False)
    microservice_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("microservices.id", ondelete="SET NULL"), index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    format: Mapped[str] = mapped_column(String(40), nullable=False)
    spec_version: Mapped[str | None] = mapped_column(String(30))
    source: Mapped[str] = mapped_column(String(60), default="upload", nullable=False)
    file_name: Mapped[str | None] = mapped_column(String(300))
    checksum: Mapped[str | None] = mapped_column(String(128), index=True)
    size_bytes: Mapped[int] = mapped_column(default=0, nullable=False)
    component_count: Mapped[int] = mapped_column(default=0, nullable=False)
    vulnerability_count: Mapped[int] = mapped_column(default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="uploaded", nullable=False)
    version_label: Mapped[str | None] = mapped_column(String(60))
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    storage_key: Mapped[str | None] = mapped_column(String(400))
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)


class SbomComponent(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "sbom_components"

    sbom_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sbom_documents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    component_uid: Mapped[str] = mapped_column(String(200), nullable=False)
    name: Mapped[str] = mapped_column(String(250), index=True, nullable=False)
    version: Mapped[str | None] = mapped_column(String(120), index=True)
    ecosystem: Mapped[str | None] = mapped_column(String(60), index=True)
    purl: Mapped[str | None] = mapped_column(String(400), index=True)
    cpe: Mapped[str | None] = mapped_column(String(400))
    supplier: Mapped[str | None] = mapped_column(String(250))
    license: Mapped[str | None] = mapped_column(String(250))
    component_type: Mapped[str] = mapped_column(String(50), default="library", nullable=False)
    is_direct: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    vulnerability_count: Mapped[int] = mapped_column(default=0, nullable=False)
    highest_severity: Mapped[str | None] = mapped_column(String(30))


class ComponentRelationship(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "component_relationships"

    sbom_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sbom_documents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    parent_component_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sbom_components.id", ondelete="CASCADE"), nullable=False
    )
    child_component_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sbom_components.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type: Mapped[str] = mapped_column(String(40), default="depends_on", nullable=False)


class VulnerabilityRecord(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "vulnerability_records"
    __table_args__ = (UniqueConstraint("source", "identifier", name="uq_vulnerability_source_identifier"),)

    identifier: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    cve_id: Mapped[str | None] = mapped_column(String(40), index=True)
    osv_id: Mapped[str | None] = mapped_column(String(80), index=True)
    title: Mapped[str | None] = mapped_column(String(300))
    description: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(30), default="unknown", nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exploit_available: Mapped[bool | None] = mapped_column(Boolean)
    known_exploited: Mapped[bool | None] = mapped_column(Boolean)
    source: Mapped[str] = mapped_column(String(40), default="osv", nullable=False)
    affected_packages: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    fixed_versions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    references: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    remediation: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class ComponentVulnerability(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "component_vulnerabilities"
    __table_args__ = (
        UniqueConstraint("component_id", "vulnerability_id", name="uq_component_vulnerability"),
    )

    component_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sbom_components.id", ondelete="CASCADE"), index=True, nullable=False
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vulnerability_records.id", ondelete="CASCADE"), index=True, nullable=False
    )
    sbom_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sbom_documents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    affected_version: Mapped[str | None] = mapped_column(String(120))
    fixed_version: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(30), default="open", nullable=False)
    match_confidence: Mapped[float] = mapped_column(Float, default=0.9, nullable=False)
    source: Mapped[str] = mapped_column(String(40), default="osv", nullable=False)
    matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SbomScanHistory(UUIDPrimaryKeyMixin, TimestampMixin, TenantMixin, Base):
    __tablename__ = "sbom_scan_history"

    sbom_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sbom_documents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_type: Mapped[str] = mapped_column(String(40), default="analysis", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="running", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    components_processed: Mapped[int] = mapped_column(default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(default=0, nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
