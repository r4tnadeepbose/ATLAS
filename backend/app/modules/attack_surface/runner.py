import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from urllib.parse import urlparse

from defusedxml import ElementTree as DefusedET
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.refs import next_ref
from app.database.models.findings import Finding, FindingStatusHistory
from app.database.models.infrastructure import Asset, DiscoveredSubdomain, NetworkService, Technology
from app.database.models.scans import ScanHistory, ScanJob, ScanLog, ScanResult
from app.integrations.base import AdapterError, AdapterUnavailable
from app.integrations.subfinder.adapter import HttpxAdapter, NmapAdapter, NucleiAdapter, SubfinderAdapter
from app.modules.attack_surface.scope import authorize_target
from app.modules.notifications.service import emit
from app.modules.risk_engine.scoring import compute_finding_risk, sla_due

logger = get_logger("attack_surface")


def _log(db: Session, job: ScanJob, message: str, level: str = "info", event: str | None = None) -> None:
    db.add(ScanLog(organization_id=job.organization_id, scan_job_id=job.id, level=level, message=message[:2000]))
    if event:
        db.add(
            ScanHistory(
                organization_id=job.organization_id,
                scan_job_id=job.id,
                event=event,
                message=message[:2000],
            )
        )


def _progress(db: Session, job: ScanJob, progress: int, step: str) -> None:
    job.progress = progress
    job.current_step = step
    db.commit()
    _log(db, job, f"{progress}% {step}", event="progress")
    db.commit()


def run_scan(organization_id: uuid.UUID, job_id: uuid.UUID) -> None:
    from app.database.session import SessionLocal

    db = SessionLocal()
    try:
        job = db.get(ScanJob, job_id)
        if job is None or job.organization_id != organization_id:
            return
        job.status = "running"
        job.started_at = datetime.now(UTC)
        job.progress = 1
        db.commit()
        _log(db, job, f"Scan started: {job.scan_type} against {job.target}", event="started")
        db.commit()

        scope = job.scope or {}
        host = authorize_target(job.target, scope)
        handlers = {
            "subdomain_enumeration": _run_subdomain,
            "http_probe": _run_http_probe,
            "port_scan": _run_port_scan,
            "vulnerability_scan": _run_vulnerability_scan,
            "full_recon": _run_full_recon,
        }
        handler = handlers.get(job.scan_type)
        if handler is None:
            raise AdapterError(f"Unsupported scan type '{job.scan_type}'")
        findings = handler(db, job, host, scope)

        job.findings_count = findings
        job.status = "completed"
        job.progress = 100
        job.current_step = "completed"
        job.finished_at = datetime.now(UTC)
        _log(db, job, f"Scan completed with {findings} new findings", event="completed")
        emit(
            db,
            organization_id=organization_id,
            event_key="assessment_completed",
            subject=f"Assessment completed: {job.name}",
            body=f"{job.scan_type} against {job.target} completed with {findings} new findings.",
            severity="info",
            dedup_key=f"scan-completed:{job.id}",
            metadata={"scan_id": str(job.id)},
        )
        db.commit()
    except AdapterUnavailable as exc:
        _fail(db, job_id, str(exc))
    except Exception as exc:  # noqa: BLE001 - job must record failure
        logger.exception("scan job %s failed", job_id)
        _fail(db, job_id, str(exc))
    finally:
        db.close()


def _fail(db: Session, job_id: uuid.UUID, message: str) -> None:
    db.rollback()
    job = db.get(ScanJob, job_id)
    if job is None:
        return
    job.status = "failed"
    job.error_message = message[:2000]
    job.finished_at = datetime.now(UTC)
    _log(db, job, f"Scan failed: {message}", level="error", event="failed")
    db.commit()


def _cancelled(db: Session, job: ScanJob) -> bool:
    db.refresh(job)
    return bool(job.cancellation_requested)


def _upsert_asset(db: Session, job: ScanJob, *, host: str, url: str | None = None, ip: str | None = None, status_code: int | None = None, title: str | None = None) -> Asset:
    asset = db.scalar(
        select(Asset).where(
            Asset.organization_id == job.organization_id,
            Asset.domain == host,
            Asset.deleted_at.is_(None),
        )
    )
    if asset is None:
        asset = Asset(
            organization_id=job.organization_id,
            asset_ref=next_ref(db, Asset, "asset_ref", "AST", job.organization_id),
            name=title or host,
            domain=host,
            subdomain=host,
            ip_address=ip,
            url=url,
            http_status=status_code,
            source=job.scan_type,
            exposure="public",
            status="active",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
        )
        db.add(asset)
        db.flush()
        emit(
            db,
            organization_id=job.organization_id,
            event_key="new_asset",
            subject=f"New external asset discovered: {host}",
            body=f"ATLAS discovered {url or host} during {job.name}.",
            severity="medium",
            dedup_key=f"asset:{asset.id}",
            metadata={"asset_id": str(asset.id)},
        )
    else:
        asset.last_seen = datetime.now(UTC)
        asset.url = url or asset.url
        asset.http_status = status_code or asset.http_status
    db.flush()
    return asset


def _run_subdomain(db: Session, job: ScanJob, host: str, scope: dict) -> int:
    _progress(db, job, 10, "Enumerating subdomains")
    adapter = SubfinderAdapter()
    availability = adapter.availability()
    if not availability["available"]:
        raise AdapterUnavailable("subfinder is not installed on this host")
    subdomains = adapter.enumerate(host)
    _progress(db, job, 50, f"Discovered {len(subdomains)} subdomains")
    created = 0
    for subdomain in subdomains:
        if _cancelled(db, job):
            return created
        authorize_target(subdomain, scope)
        existing = db.scalar(
            select(DiscoveredSubdomain).where(
                DiscoveredSubdomain.organization_id == job.organization_id,
                DiscoveredSubdomain.subdomain == subdomain,
            )
        )
        if existing is None:
            asset = _upsert_asset(db, job, host=subdomain)
            db.add(
                DiscoveredSubdomain(
                    organization_id=job.organization_id,
                    asset_id=asset.id,
                    domain=host,
                    subdomain=subdomain,
                    source="subfinder",
                    first_seen=datetime.now(UTC),
                    last_seen=datetime.now(UTC),
                )
            )
            created += 1
        else:
            existing.last_seen = datetime.now(UTC)
    db.add(ScanResult(organization_id=job.organization_id, scan_job_id=job.id, tool="subfinder", result_type="subdomains", payload={"count": len(subdomains), "items": subdomains[:1000]}))
    db.commit()
    return 0


def _run_http_probe(db: Session, job: ScanJob, host: str, scope: dict) -> int:
    _progress(db, job, 10, "Probing HTTP endpoints")
    targets = [f"https://{host}", f"http://{host}"]
    if job.scope.get("http_targets"):
        targets = [str(t) for t in job.scope["http_targets"]]
    for target in targets:
        authorize_target(target, scope)
    adapter = HttpxAdapter()
    if not adapter.availability()["available"]:
        raise AdapterUnavailable("httpx is not installed on this host")
    entries = adapter.probe(targets)
    _progress(db, job, 60, f"Probed {len(entries)} live endpoints")
    created = 0
    for entry in entries:
        url = entry.get("url") or entry.get("input")
        if not url:
            continue
        parsed = urlparse(url)
        asset = _upsert_asset(
            db,
            job,
            host=(parsed.hostname or host),
            url=url,
            ip=entry.get("ip"),
            status_code=entry.get("status_code") or entry.get("status-code"),
            title=entry.get("title"),
        )
        technologies = entry.get("tech") or entry.get("technologies") or []
        for tech in technologies:
            name = tech if isinstance(tech, str) else tech.get("name")
            if name:
                db.add(Technology(organization_id=job.organization_id, asset_id=asset.id, name=str(name)[:150], category="detected"))
        asset.technology_summary = [str(t) for t in technologies if isinstance(t, str)][:30]
        created += 1
    db.add(ScanResult(organization_id=job.organization_id, scan_job_id=job.id, tool="httpx", result_type="http_endpoints", payload={"count": len(entries), "items": entries[:500]}))
    db.commit()
    return 0


def _run_port_scan(db: Session, job: ScanJob, host: str, scope: dict) -> int:
    _progress(db, job, 10, "Running authorized service discovery")
    adapter = NmapAdapter()
    if not adapter.availability()["available"]:
        raise AdapterUnavailable("nmap is not installed on this host")
    result = adapter.top_ports(host)
    _progress(db, job, 70, "Parsing service results")
    try:
        root = DefusedET.fromstring(result["xml"])
    except Exception as exc:  # noqa: BLE001
        raise AdapterError("nmap returned unparseable XML") from exc
    asset = _upsert_asset(db, job, host=host)
    services = 0
    for host_element in root.iter():
        if host_element.tag.split("}")[-1] != "host":
            continue
        for port in host_element.iter():
            if port.tag.split("}")[-1] != "port":
                continue
            port_id = int(port.get("portid") or 0)
            state_element = next((child for child in port if child.tag.split("}")[-1] == "state"), None)
            service_element = next((child for child in port if child.tag.split("}")[-1] == "service"), None)
            db.add(
                NetworkService(
                    organization_id=job.organization_id,
                    asset_id=asset.id,
                    port=port_id,
                    protocol=port.get("protocol") or "tcp",
                    state=(state_element.get("state") if state_element is not None else "open") or "open",
                    service_name=(service_element.get("name") if service_element is not None else None),
                    product=(service_element.get("product") if service_element is not None else None),
                    version=(service_element.get("version") if service_element is not None else None),
                    first_seen=datetime.now(UTC),
                    last_seen=datetime.now(UTC),
                )
            )
            services += 1
    db.add(ScanResult(organization_id=job.organization_id, scan_job_id=job.id, tool="nmap", result_type="network_services", payload={"count": services}))
    db.commit()
    return 0


def _run_vulnerability_scan(db: Session, job: ScanJob, host: str, scope: dict) -> int:
    _progress(db, job, 10, "Running authorized vulnerability templates")
    target = job.target if "://" in job.target else f"https://{host}"
    authorize_target(target, scope)
    adapter = NucleiAdapter()
    if not adapter.availability()["available"]:
        raise AdapterUnavailable("nuclei is not installed on this host")
    results = adapter.scan(target)
    _progress(db, job, 70, f"Processing {len(results)} template results")
    created = 0
    asset = _upsert_asset(db, job, host=host, url=target)
    for result in results:
        info = result.get("info") or {}
        severity = (info.get("severity") or "medium").lower()
        title = info.get("name") or result.get("template-id") or "Nuclei finding"
        dedup = f"nuclei:{asset.id}:{result.get('template-id')}:{result.get('matched-at')}"
        if db.scalar(select(Finding.id).where(Finding.organization_id == job.organization_id, Finding.dedup_key == dedup)):
            continue
        risk, band, _factors = compute_finding_risk(severity=severity, exposure="public", criticality=asset.criticality, first_seen=datetime.now(UTC))
        finding = Finding(
            organization_id=job.organization_id,
            finding_ref=next_ref(db, Finding, "finding_ref", "FND", job.organization_id),
            title=str(title)[:300],
            description=info.get("description"),
            category="attack_surface",
            source_module="attack_surface",
            severity=severity,
            status="open",
            asset_id=asset.id,
            business_unit=asset.business_unit,
            environment_id=asset.environment_id,
            exposure="public",
            confidence=0.85,
            risk_score=risk,
            dedup_key=dedup,
            location=result.get("matched-at"),
            remediation="Validate the template result, confirm applicability, then apply the vendor fix or configuration hardening.",
            evidence_summary=str(result.get("matcher-name") or "")[:1000],
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            sla_due_at=sla_due(severity, datetime.now(UTC)),
            tags=list(info.get("tags") or [])[:10] if isinstance(info.get("tags"), list) else [],
        )
        db.add(finding)
        db.flush()
        db.add(FindingStatusHistory(organization_id=job.organization_id, finding_id=finding.id, to_status="open", note="Discovered by authorized nuclei assessment"))
        db.add(ScanResult(organization_id=job.organization_id, scan_job_id=job.id, tool="nuclei", result_type="vulnerability", severity=severity, target=result.get("matched-at"), payload=result))
        created += 1
    db.commit()
    return created


def _run_full_recon(db: Session, job: ScanJob, host: str, scope: dict) -> int:
    _run_subdomain(db, job, host, scope)
    _progress(db, job, 30, "Subdomain enumeration complete")
    if _cancelled(db, job):
        return 0
    _run_http_probe(db, job, host, scope)
    _progress(db, job, 55, "HTTP probing complete")
    if _cancelled(db, job):
        return 0
    _run_port_scan(db, job, host, scope)
    _progress(db, job, 80, "Service discovery complete")
    if _cancelled(db, job):
        return 0
    return _run_vulnerability_scan(db, job, host, scope)
