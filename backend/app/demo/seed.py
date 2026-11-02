"""Demo environment seed data.

This module only runs when ``ATLAS_APP_ENV=demo`` or ``ATLAS_SEED_DEMO_DATA=true``.
Every record it creates belongs to an organization explicitly flagged
``demo: true``; production metrics are never populated from here.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.database.models.api_inventory import ApiEndpoint, ApiSpecification
from app.database.models.findings import Finding, FindingStatusHistory
from app.database.models.identity import (
    Organization,
    OrganizationMembership,
    Role,
    Team,
    User,
    UserRole,
)
from app.database.models.infrastructure import (
    Asset,
    Environment,
    Microservice,
    ServiceDependency,
)
from app.database.models.ops import Notification, NotificationRule
from app.database.models.risk import RemediationTask, RiskAssessment
from app.database.models.sbom import SbomComponent, VulnerabilityRecord
from app.database.models.scans import ScanHistory, ScanJob, ScanResult
from app.modules.api_inventory import service as api_service
from app.modules.data_classification import service as classification_service
from app.modules.risk_engine.service import recompute_assessments
from app.modules.sbom import service as sbom_service

DEMO_PASSWORD = "AtlasDemo!2026"

SERVICES = [
    ("payment-service", "Payments", "critical", "Java", "prod"),
    ("payment-api", "Payments", "critical", "Kotlin", "prod"),
    ("authentication-service", "Identity", "critical", "Go", "prod"),
    ("authorization-service", "Identity", "high", "Go", "prod"),
    ("transaction-service", "Payments", "critical", "Java", "prod"),
    ("notification-service", "Platform", "medium", "Python", "prod"),
    ("ledger-service", "Finance", "critical", "Java", "prod"),
    ("fraud-detection", "Risk", "high", "Python", "prod"),
    ("customer-profile", "Customer", "high", "TypeScript", "prod"),
    ("kyc-service", "Compliance", "critical", "Python", "prod"),
    ("document-service", "Compliance", "high", "Go", "prod"),
    ("web-gateway", "Platform", "critical", "TypeScript", "prod"),
    ("mobile-bff", "Platform", "high", "TypeScript", "prod"),
    ("search-service", "Platform", "medium", "Go", "prod"),
    ("recommendation-engine", "Growth", "low", "Python", "staging"),
    ("billing-service", "Finance", "high", "Java", "prod"),
    ("invoice-service", "Finance", "medium", "Java", "prod"),
    ("support-portal", "Customer", "medium", "TypeScript", "prod"),
    ("analytics-pipeline", "Data", "medium", "Python", "prod"),
    ("reporting-service", "Data", "medium", "Python", "prod"),
    ("audit-service", "Compliance", "high", "Go", "prod"),
    ("secrets-broker", "Platform", "critical", "Rust", "prod"),
    ("api-gateway", "Platform", "critical", "Go", "prod"),
    ("service-registry", "Platform", "high", "Go", "prod"),
    ("email-worker", "Platform", "low", "Python", "prod"),
    ("sms-worker", "Platform", "low", "Python", "prod"),
    ("risk-scoring", "Risk", "high", "Python", "prod"),
    ("currency-service", "Finance", "medium", "Go", "prod"),
    ("merchant-onboarding", "Payments", "high", "TypeScript", "staging"),
    ("developer-portal", "Platform", "low", "TypeScript", "dev"),
]

DEPENDENCIES = [
    ("payment-api", "payment-service"),
    ("payment-api", "authentication-service"),
    ("payment-service", "transaction-service"),
    ("payment-service", "ledger-service"),
    ("transaction-service", "ledger-service"),
    ("transaction-service", "fraud-detection"),
    ("payment-service", "notification-service"),
    ("authentication-service", "secrets-broker"),
    ("authorization-service", "authentication-service"),
    ("web-gateway", "api-gateway"),
    ("api-gateway", "payment-api"),
    ("api-gateway", "customer-profile"),
    ("api-gateway", "search-service"),
    ("mobile-bff", "api-gateway"),
    ("customer-profile", "authentication-service"),
    ("kyc-service", "document-service"),
    ("kyc-service", "customer-profile"),
    ("billing-service", "ledger-service"),
    ("invoice-service", "billing-service"),
    ("fraud-detection", "risk-scoring"),
    ("analytics-pipeline", "reporting-service"),
    ("support-portal", "customer-profile"),
    ("support-portal", "document-service"),
    ("merchant-onboarding", "kyc-service"),
    ("merchant-onboarding", "billing-service"),
    ("audit-service", "api-gateway"),
]

EXTERNAL_DEPENDENCIES = [
    ("payment-service", "payments.gateway.example"),
    ("notification-service", "smtp.provider.example"),
    ("fraud-detection", "risk.intelligence.example"),
    ("kyc-service", "identity.verification.example"),
]

ASSET_NAMES = {
    "payment-api.company.example": "Payments API",
    "payment.company.example": "Payments Portal",
    "auth.company.example": "Authentication Service",
    "api.company.example": "API Gateway",
    "portal.company.example": "Customer Portal",
    "kyc.company.example": "KYC Verification",
    "reports.company.example": "Reporting Service",
    "staging.company.example": "Staging Environment",
    "git.company.example": "Source Control",
    "registry.company.example": "Container Registry",
    "vault.company.example": "Secrets Vault",
    "grafana.company.example": "Grafana",
    "prometheus.company.example": "Prometheus",
    "jenkins.company.example": "Jenkins",
    "legacy-orders.company.example": "Legacy Orders",
    "dev-portal.company.example": "Developer Portal",
    "support.company.example": "Support Portal",
    "docs.company.example": "Documentation",
}

ASSETS = [
    ("payment-api.company.example", "public", "critical", "Payments", "prod", ["nginx", "kotlin", "spring"]),
    ("payment.company.example", "public", "critical", "Payments", "prod", ["nginx", "java"]),
    ("auth.company.example", "public", "critical", "Identity", "prod", ["go", "envoy"]),
    ("api.company.example", "public", "critical", "Platform", "prod", ["envoy", "go"]),
    ("portal.company.example", "public", "medium", "Customer", "prod", ["react", "nginx"]),
    ("kyc.company.example", "public", "critical", "Compliance", "prod", ["python", "fastapi"]),
    ("reports.company.example", "partner", "high", "Data", "prod", ["python", "grafana"]),
    ("staging.company.example", "public", "medium", "Platform", "staging", ["nginx"]),
    ("git.company.example", "internal", "high", "Platform", "prod", ["gitlab"]),
    ("registry.company.example", "internal", "critical", "Platform", "prod", ["harbor"]),
    ("vault.company.example", "internal", "critical", "Platform", "prod", ["vault"]),
    ("grafana.company.example", "internal", "medium", "Data", "prod", ["grafana"]),
    ("prometheus.company.example", "internal", "medium", "Data", "prod", ["prometheus"]),
    ("jenkins.company.example", "internal", "high", "Platform", "prod", ["jenkins"]),
    ("legacy-orders.company.example", "public", "high", "Payments", "prod", ["php"]),
    ("dev-portal.company.example", "public", "low", "Platform", "dev", ["react"]),
    ("support.company.example", "public", "medium", "Customer", "prod", ["node"]),
    ("docs.company.example", "public", "low", "Platform", "prod", ["static"]),
]

VULNERABILITIES = [
    {
        "identifier": "CVE-2021-44228",
        "cve_id": "CVE-2021-44228",
        "title": "Log4Shell remote code execution in Log4j 2",
        "description": "JNDI lookup injection in Apache Log4j 2 allows unauthenticated remote code execution when message lookup substitution is enabled.",
        "cvss": 10.0,
        "severity": "critical",
        "published": datetime(2021, 12, 10, tzinfo=UTC),
        "ecosystem": "Maven",
        "name": "log4j-core",
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core",
        "fixed": "2.17.1",
        "known_exploited": True,
    },
    {
        "identifier": "GHSA-p6mc-m468-83gw",
        "cve_id": "CVE-2021-23337",
        "title": "Command injection in lodash template",
        "description": "lodash versions prior to 4.17.21 are vulnerable to command injection via the template function.",
        "cvss": 7.2,
        "severity": "high",
        "published": datetime(2021, 2, 15, tzinfo=UTC),
        "ecosystem": "npm",
        "name": "lodash",
        "purl": "pkg:npm/lodash",
        "fixed": "4.17.21",
        "known_exploited": False,
    },
    {
        "identifier": "CVE-2023-32681",
        "cve_id": "CVE-2023-32681",
        "title": "Proxy-Authorization header leak in requests",
        "description": "Requests forwards Proxy-Authorization headers to destination servers on redirects in certain configurations.",
        "cvss": 6.1,
        "severity": "medium",
        "published": datetime(2023, 5, 26, tzinfo=UTC),
        "ecosystem": "PyPI",
        "name": "requests",
        "purl": "pkg:pypi/requests",
        "fixed": "2.31.0",
        "known_exploited": False,
    },
    {
        "identifier": "GHSA-jfh8-c2jp-5v3q",
        "cve_id": "CVE-2023-38545",
        "title": "SOCKS5 heap buffer overflow in curl",
        "description": "A heap overflow in curl's SOCKS5 handshake can lead to code execution when a long hostname is supplied.",
        "cvss": 8.8,
        "severity": "high",
        "published": datetime(2023, 10, 11, tzinfo=UTC),
        "ecosystem": "Debian",
        "name": "curl",
        "purl": "pkg:deb/debian/curl",
        "fixed": "8.5.0",
        "known_exploited": True,
    },
    {
        "identifier": "CVE-2022-42003",
        "cve_id": "CVE-2022-42003",
        "title": "Deep wrapper array nesting denial of service in Jackson",
        "description": "Uncontrolled resource consumption in jackson-databind when deserializing deeply nested wrapper arrays.",
        "cvss": 7.5,
        "severity": "high",
        "published": datetime(2022, 10, 2, tzinfo=UTC),
        "ecosystem": "Maven",
        "name": "jackson-databind",
        "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind",
        "fixed": "2.14.1",
        "known_exploited": False,
    },
    {
        "identifier": "CVE-2024-21538",
        "cve_id": "CVE-2024-21538",
        "title": "Regular expression denial of service in cross-spawn",
        "description": "Inefficient regular expression complexity in cross-spawn before 7.0.5 and 6.0.6 allows ReDoS.",
        "cvss": 5.3,
        "severity": "medium",
        "published": datetime(2024, 11, 8, tzinfo=UTC),
        "ecosystem": "npm",
        "name": "cross-spawn",
        "purl": "pkg:npm/cross-spawn",
        "fixed": "7.0.5",
        "known_exploited": False,
    },
]


def _cyclonedx(service_name: str, packages: list[tuple[str, str, str, str]]) -> bytes:
    components = []
    dependencies = []
    for purl, name, version, ecosystem in packages:
        ref = f"pkg:{ecosystem}/{name}@{version}" if ecosystem in {"npm", "pypi"} else purl
        components.append(
            {
                "bom-ref": ref,
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl,
                "supplier": {"name": "Upstream OSS"},
                "licenses": [{"license": {"id": "MIT"}}],
            }
        )
        dependencies.append({"ref": ref})
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "component": {"bom-ref": service_name, "type": "application", "name": service_name, "version": "2026.11"},
            "tools": [{"vendor": "ATLAS", "name": "demo-seed"}],
        },
        "components": components,
        "dependencies": dependencies,
    }
    return json.dumps(document).encode()


DEMO_PACKAGES = {
    "payment-service": [
        ("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "log4j-core", "2.14.1", "maven"),
        ("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", "jackson-databind", "2.13.0", "maven"),
        ("pkg:deb/debian/curl@7.88.1", "curl", "7.88.1", "deb"),
    ],
    "payment-api": [
        ("pkg:npm/lodash@4.17.20", "lodash", "4.17.20", "npm"),
        ("pkg:npm/express@4.18.2", "express", "4.18.2", "npm"),
        ("pkg:npm/cross-spawn@7.0.3", "cross-spawn", "7.0.3", "npm"),
    ],
    "kyc-service": [
        ("pkg:pypi/requests@2.25.0", "requests", "2.25.0", "pypi"),
        ("pkg:pypi/fastapi@0.110.0", "fastapi", "0.110.0", "pypi"),
        ("pkg:pypi/uvicorn@0.27.0", "uvicorn", "0.27.0", "pypi"),
    ],
    "web-gateway": [
        ("pkg:npm/react@18.2.0", "react", "18.2.0", "npm"),
        ("pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "npm"),
    ],
    "notification-service": [
        ("pkg:pypi/requests@2.31.0", "requests", "2.31.0", "pypi"),
        ("pkg:deb/debian/curl@8.5.0", "curl", "8.5.0", "deb"),
    ],
}


def seed_demo_data(db: Session) -> None:
    if db.scalar(select(Organization).where(Organization.slug == "atlas-demo")):
        return

    org = Organization(
        name="Indus Demo Corp",
        slug="atlas-demo",
        plan="enterprise",
        settings={"demo": True, "notice": "Demo environment — all records are synthetic"},
    )
    db.add(org)
    db.flush()

    role_map = {role.key: role for role in db.scalars(select(Role).where(Role.organization_id.is_(None))).all()}

    users = [
        ("admin@atlas.demo", "Aarav Sharma", "super_admin", "Platform Owner"),
        ("security@atlas.demo", "Ananya Iyer", "security_admin", "Head of Security Engineering"),
        ("soc@atlas.demo", "Rohan Mehta", "soc_analyst", "SOC Analyst"),
        ("vapt@atlas.demo", "Ishita Nair", "vapt_analyst", "Offensive Security Engineer"),
        ("dev@atlas.demo", "Arjun Patel", "developer", "Staff Engineer, Payments"),
        ("exec@atlas.demo", "Meera Krishnan", "executive", "Chief Information Security Officer"),
    ]
    user_map: dict[str, User] = {}
    for email, name, role_key, title in users:
        user = User(
            organization_id=org.id,
            email=email,
            full_name=name,
            title=title,
            hashed_password=hash_password(DEMO_PASSWORD),
            is_active=True,
        )
        db.add(user)
        db.flush()
        role = role_map.get(role_key)
        if role:
            db.add(UserRole(user_id=user.id, role_id=role.id))
        db.add(OrganizationMembership(organization_id=org.id, user_id=user.id, status="active", title=title))
        user_map[role_key] = user

    teams = {}
    for name, unit in (("Payments Platform", "Payments"), ("Identity & Access", "Identity"), ("Data Platform", "Data"), ("Core Platform", "Platform"), ("Compliance Engineering", "Compliance")):
        team = Team(organization_id=org.id, name=name, slug=name.lower().replace(" ", "-"), business_unit=unit)
        db.add(team)
        db.flush()
        teams[unit] = team

    environments = {}
    for key, name, production in (("prod", "Production", True), ("staging", "Staging", False), ("dev", "Development", False)):
        environment = Environment(organization_id=org.id, name=name, key=key, is_production=production)
        db.add(environment)
        db.flush()
        environments[key] = environment

    db.commit()

    service_map: dict[str, Microservice] = {}
    for index, (name, unit, criticality, language, env_key) in enumerate(SERVICES):
        service = Microservice(
            organization_id=org.id,
            service_ref=f"SVC-{index + 1:05d}",
            name=name,
            description=f"{name} owned by the {unit} business unit.",
            repository_url=f"https://git.company.example/{unit.lower()}/{name}",
            owner_user_id=user_map["developer"].id if unit == "Payments" else user_map["security_admin"].id,
            team_id=teams.get(unit, teams["Platform"]).id,
            business_unit=unit,
            environment_id=environments[env_key].id,
            deployment_location="Kubernetes · company-prod" if env_key == "prod" else "Kubernetes · non-prod",
            version=f"2026.{11 if env_key == 'prod' else 10}.{index % 9 + 1}",
            language=language,
            tech_stack=[language.lower(), "kubernetes", "opentelemetry"],
            criticality=criticality,
            security_posture="unknown",
            risk_level="low",
            status="active",
        )
        db.add(service)
        db.flush()
        service_map[name] = service

    for source, target in DEPENDENCIES:
        if source in service_map and target in service_map:
            db.add(
                ServiceDependency(
                    organization_id=org.id,
                    source_service_id=service_map[source].id,
                    target_service_id=service_map[target].id,
                    dependency_type="http",
                )
            )
    for source, target in EXTERNAL_DEPENDENCIES:
        if source in service_map:
            db.add(
                ServiceDependency(
                    organization_id=org.id,
                    source_service_id=service_map[source].id,
                    target_external=target,
                    dependency_type="external",
                )
            )

    asset_map: dict[str, Asset] = {}
    now = datetime.now(UTC)
    for index, (domain, exposure, criticality, unit, env_key, tech) in enumerate(ASSETS):
        asset = Asset(
            organization_id=org.id,
            asset_ref=f"AST-{index + 1:05d}",
            name=ASSET_NAMES.get(domain, domain.split(".")[0].replace("-", " ").title()),
            domain=domain,
            subdomain=domain,
            ip_address=f"203.0.113.{20 + index}",
            port=443,
            protocol="https",
            url=f"https://{domain}",
            http_status=200,
            technology_summary=tech,
            hosting_provider="Example Cloud",
            first_seen=now - timedelta(days=120 - index * 3),
            last_seen=now - timedelta(hours=index),
            owner_user_id=user_map["developer"].id,
            business_unit=unit,
            environment_id=environments[env_key].id,
            criticality=criticality,
            exposure=exposure,
            status="active",
            source="subfinder" if index % 3 else "manual",
            tags=["demo"],
        )
        db.add(asset)
        db.flush()
        asset_map[domain] = asset

    for vulnerability in VULNERABILITIES:
        entry = {
            "package": {"ecosystem": vulnerability["ecosystem"], "name": vulnerability["name"], "purl": vulnerability["purl"]},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": vulnerability["fixed"]}]}],
        }
        db.add(
            VulnerabilityRecord(
                identifier=vulnerability["identifier"],
                cve_id=vulnerability["cve_id"],
                osv_id=vulnerability["identifier"] if not vulnerability["identifier"].startswith("CVE-") else None,
                title=vulnerability["title"],
                description=vulnerability["description"],
                cvss_score=vulnerability["cvss"],
                severity=vulnerability["severity"],
                published_at=vulnerability["published"],
                modified_at=vulnerability["published"],
                known_exploited=vulnerability["known_exploited"],
                exploit_available=vulnerability["known_exploited"],
                source="osv",
                affected_packages=[entry],
                fixed_versions=[vulnerability["fixed"]],
                references=[{"url": f"https://osv.dev/vulnerability/{vulnerability['identifier']}", "type": "ADVISORY"}],
                remediation=f"Upgrade {vulnerability['name']} to {vulnerability['fixed']} or later.",
                raw={"demo": True},
            )
        )
    db.commit()

    for service_name, packages in DEMO_PACKAGES.items():
        asset = next((asset for domain, asset in asset_map.items() if service_name.split("-")[0] in domain), None)
        document = sbom_service.ingest_sbom(
            db,
            organization_id=org.id,
            uploaded_by=user_map["security_admin"].id,
            filename=f"{service_name}.cdx.json",
            content=_cyclonedx(service_name, packages),
            microservice_id=service_map[service_name].id,
            asset_id=asset.id if asset else None,
            version_label="2026.11",
            source="upload",
        )
        sbom_service.correlate(db, document, use_online=False)

    api_specs = [
        {
            "name": "Payments API",
            "base_url": "https://api.company.example/payments",
            "service": "payment-api",
            "endpoints": [
                ("post", "/v1/payments", "Create payment", True),
                ("get", "/v1/payments/{id}", "Retrieve payment", True),
                ("post", "/v1/refunds", "Create refund", True),
                ("get", "/v1/admin/reconciliation", "Reconciliation export", False),
            ],
            "secure": True,
        },
        {
            "name": "Customer Profile API",
            "base_url": "http://legacy-api.company.example",
            "service": "customer-profile",
            "endpoints": [
                ("get", "/v1/customers/{id}", "Customer profile", True),
                ("get", "/v1/customers/{id}/documents", "Customer documents", False),
                ("get", "/swagger.json", "Exposed specification", False),
            ],
            "secure": False,
        },
        {
            "name": "Identity API",
            "base_url": "https://auth.company.example",
            "service": "authentication-service",
            "endpoints": [("post", "/oauth/token", "Token exchange", False), ("get", "/.well-known/openid-configuration", "OIDC discovery", False)],
            "secure": True,
        },
        {
            "name": "Reporting API",
            "base_url": "https://reports.company.example",
            "service": "reporting-service",
            "endpoints": [
                ("get", "/v1/reports", "List reports", True),
                ("post", "/v1/reports/export", "Export report", True),
                ("get", "/v1/admin/users", "Admin user list", False),
            ],
            "secure": True,
        },
    ]
    for spec in api_specs:
        document = {
            "openapi": "3.0.3",
            "info": {"title": spec["name"], "version": "1.0.0", "description": "Demo service specification"},
            "servers": [{"url": spec["base_url"]}],
            "security": [{"bearerAuth": []}] if spec["secure"] else [],
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}} if spec["secure"] else {},
            "paths": {
                path: {
                    method: {
                        "summary": summary,
                        "security": [] if not required else [{"bearerAuth": []}],
                        "responses": {"200": {"description": "OK"}},
                    }
                }
                for method, path, summary, required in spec["endpoints"]
            },
        }
        api, _specification = api_service.import_specification(
            db,
            organization_id=org.id,
            uploaded_by=user_map["security_admin"].id,
            name=spec["name"],
            content=json.dumps(document),
            filename=f"{spec['name'].lower().replace(' ', '-')}.json",
            microservice_id=service_map[spec["service"]].id,
            environment_id=environments["prod"].id,
        )
        if not spec["secure"]:
            api.data_sensitivity = "high"
            api.exposure = "public"
            db.commit()

    classification_service.seed_rules(db, org.id)
    classification_sample = (
        "Customer contact: jane.doe@example.com, card 4111111111111111. "
        "Config dump: aws_access_key_id=AKIAIOSFODNN7EXAMPLE "
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vIn0.c2lnbmF0dXJlLWRlbW8. "
        "password=Sup3rS3cretDemoValue"
    )
    classification_service.analyze_text(
        db,
        organization_id=org.id,
        text=classification_sample,
        source_label="demo://support-portal/config-snapshot.txt",
        asset_id=asset_map["support.company.example"].id,
        microservice_id=service_map["support-portal"].id,
        service_name="support-portal",
    )

    recompute_assessments(db, org.id)

    scan = ScanJob(
        organization_id=org.id,
        name="Production external surface review (demo)",
        scan_type="full_recon",
        target="company.example",
        scope={"domains": ["company.example"]},
        adapter="demo",
        status="completed",
        progress=100,
        findings_count=0,
        created_by=user_map["vapt_analyst"].id,
        authorized_by=user_map["security_admin"].id,
        authorization_reference="DEMO-AUTH-2026-001",
        started_at=now - timedelta(days=3),
        finished_at=now - timedelta(days=3) + timedelta(minutes=18),
    )
    db.add(scan)
    db.flush()
    db.add(ScanHistory(organization_id=org.id, scan_job_id=scan.id, event="completed", message="Demo scan record. Tools were not executed for seeded data."))
    db.add(ScanResult(organization_id=org.id, scan_job_id=scan.id, tool="httpx", result_type="http_endpoints", payload={"count": len(ASSETS), "demo": True}))

    db.add(NotificationRule(organization_id=org.id, name="Critical and high findings", event_key="vulnerable_dependency", min_severity="high", channels=["in_app"], dedup_window_minutes=120))
    db.add(NotificationRule(organization_id=org.id, name="New exposed assets", event_key="new_asset", min_severity="medium", channels=["in_app"], dedup_window_minutes=60))

    db.commit()
    db.add(Notification(organization_id=org.id, user_id=user_map["soc_analyst"].id, subject="MFA enforcement reminder", body="Enable MFA for all SOC analyst accounts.", severity="info", status="sent", channel="in_app", event_key="system", sent_at=now - timedelta(days=1)))
    db.commit()

    _backdate_findings(db, org)
    _align_intelligence_timestamps(db, org)
    _seed_demo_triage(db, org)
    db.commit()


def _align_intelligence_timestamps(db: Session, org: Organization) -> None:
    """Keep demo MTTD meaningful: intelligence is ingested shortly before the
    finding is generated, while published dates stay historically accurate."""
    records = db.scalars(select(VulnerabilityRecord)).all()
    for record in records:
        earliest = db.scalar(
            select(Finding.first_seen)
            .where(Finding.organization_id == org.id, Finding.vulnerability_id == record.id, Finding.first_seen.is_not(None))
            .order_by(Finding.first_seen.asc())
            .limit(1)
        )
        if earliest:
            record.created_at = earliest - timedelta(minutes=9)
    db.commit()


def _seed_demo_triage(db: Session, org: Organization) -> None:
    from app.modules.ai_triage.service import triage

    findings = db.scalars(
        select(Finding).where(Finding.organization_id == org.id).order_by(Finding.risk_score.desc()).limit(5)
    ).all()
    for finding in findings:
        triage(db, organization_id=org.id, finding=finding)
    recompute_assessments(db, org.id)
    db.commit()


def _backdate_findings(db: Session, org: Organization) -> None:
    findings = db.scalars(select(Finding).where(Finding.organization_id == org.id)).all()
    now = datetime.now(UTC)
    for index, finding in enumerate(findings):
        finding.first_seen = now - timedelta(days=(index * 3) % 45, hours=index % 12)
        finding.last_seen = now - timedelta(hours=index % 24)
        finding.sla_due_at = finding.first_seen + timedelta(days={"critical": 7, "high": 30, "medium": 90, "low": 180}.get(finding.severity, 90))
    db.commit()
