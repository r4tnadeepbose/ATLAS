"""OpenAPI / Swagger import and API security checks."""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import ValidationError
from app.core.refs import next_ref
from app.database.models.api_inventory import (
    Api,
    ApiAuthentication,
    ApiEndpoint,
    ApiSecurityFinding,
    ApiSpecification,
)

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


def parse_spec(content: str, filename: str) -> tuple[dict, str, str | None]:
    try:
        document = json.loads(content)
        fmt = "openapi-json" if "openapi" in document else "swagger-json"
    except json.JSONDecodeError:
        try:
            document = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise ValidationError("API specification is neither valid JSON nor YAML") from exc
        if not isinstance(document, dict):
            raise ValidationError("API specification must be an object")
        fmt = "openapi-yaml" if "openapi" in document else "swagger-yaml"
    if not isinstance(document, dict) or not (document.get("openapi") or document.get("swagger")):
        raise ValidationError("Only OpenAPI 3.x and Swagger 2.0 documents are supported")
    version = document.get("openapi") or document.get("swagger")
    return document, fmt, str(version)


def _base_url(document: dict) -> str | None:
    if document.get("openapi"):
        servers = document.get("servers") or []
        if servers and isinstance(servers, list):
            return servers[0].get("url")
    host = document.get("host")
    if host:
        schemes = document.get("schemes") or ["https"]
        return f"{schemes[0]}://{host}{document.get('basePath', '')}"
    return None


def _auth_type(document: dict) -> tuple[str, dict, bool]:
    schemes = ((document.get("components") or {}).get("securitySchemes")) or document.get("securityDefinitions") or {}
    if not schemes:
        return "none", {}, False
    for name, scheme in schemes.items():
        kind = scheme.get("type")
        if kind == "http":
            return (scheme.get("scheme") or "http"), scheme, True
        if kind in {"oauth2", "openIdConnect"}:
            return "oauth2", scheme, True
        if kind == "apiKey":
            return "api_key", scheme, True
    return "other", {}, True


def import_specification(
    db: Session,
    *,
    organization_id: uuid.UUID,
    uploaded_by: uuid.UUID | None,
    name: str,
    content: str,
    filename: str,
    microservice_id: uuid.UUID | None = None,
    environment_id: uuid.UUID | None = None,
    base_url_override: str | None = None,
) -> tuple[Api, ApiSpecification]:
    document, fmt, spec_version = parse_spec(content, filename)
    info = document.get("info") or {}
    base_url = base_url_override or _base_url(document)
    auth_type, auth_scheme, auth_enforced = _auth_type(document)
    global_security = document.get("security") or []

    api = Api(
        organization_id=organization_id,
        api_ref=next_ref(db, Api, "api_ref", "API", organization_id),
        name=(info.get("title") or name)[:250],
        base_url=base_url,
        service_id=microservice_id,
        environment_id=environment_id,
        version=str(info.get("version"))[:40] if info.get("version") else None,
        auth_type=auth_type,
        authorization_model="scopes" if auth_type == "oauth2" else ("api_key" if auth_type == "api_key" else "none"),
        content_type="application/json",
        data_sensitivity="internal",
        exposure="public" if base_url and base_url.startswith("http://") else "internal",
        status="active",
        security_status="reviewed",
        last_observed=datetime.now(UTC),
        description=info.get("description"),
        tags=[],
    )
    db.add(api)
    db.flush()

    if auth_scheme:
        db.add(
            ApiAuthentication(
                organization_id=organization_id,
                api_id=api.id,
                scheme=auth_type,
                details={"definition": auth_scheme, "global_security": global_security},
                enforced=auth_enforced,
            )
        )

    endpoints = 0
    paths = document.get("paths") or {}
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            security = operation.get("security", global_security)
            endpoint = ApiEndpoint(
                organization_id=organization_id,
                api_id=api.id,
                method=method.upper(),
                path=path[:500],
                summary=(operation.get("summary") or operation.get("operationId") or "")[:500] or None,
                auth_required=bool(security),
                data_sensitivity="internal",
                status="deprecated" if operation.get("deprecated") else "active",
                deprecated=bool(operation.get("deprecated")),
                parameters=[{"name": p.get("name"), "in": p.get("in"), "required": p.get("required", False)} for p in operation.get("parameters") or [] if isinstance(p, dict)],
                last_observed=datetime.now(UTC),
            )
            db.add(endpoint)
            endpoints += 1

    specification = ApiSpecification(
        organization_id=organization_id,
        api_id=api.id,
        name=name[:250],
        format=fmt,
        spec_version=spec_version,
        content=content,
        endpoint_count=endpoints,
        uploaded_by=uploaded_by,
        imported_at=datetime.now(UTC),
    )
    db.add(specification)
    db.commit()
    run_security_checks(db, api)
    return api, specification


def run_security_checks(db: Session, api: Api) -> int:
    db.query(ApiSecurityFinding).filter(ApiSecurityFinding.api_id == api.id).delete()
    endpoints = db.scalars(select(ApiEndpoint).where(ApiEndpoint.api_id == api.id)).all()
    created = 0

    def add(check: str, severity: str, description: str, *, endpoint: ApiEndpoint | None = None, confidence: float = 0.8) -> None:
        nonlocal created
        db.add(
            ApiSecurityFinding(
                organization_id=api.organization_id,
                api_id=api.id,
                endpoint_id=endpoint.id if endpoint else None,
                check_key=check,
                severity=severity,
                status="open",
                description=description,
                confidence=confidence,
                detected_at=datetime.now(UTC),
            )
        )
        created += 1

    if api.auth_type == "none":
        add("missing_authentication", "critical", "The specification declares no authentication scheme for this API.", confidence=0.85)
    unauthenticated = [endpoint for endpoint in endpoints if endpoint.auth_required is False]
    if api.auth_type != "none" and unauthenticated:
        add(
            "weak_authorization",
            "high",
            f"{len(unauthenticated)} endpoint(s) override global security and require no authentication.",
            endpoint=unauthenticated[0],
            confidence=0.75,
        )
    if api.base_url and api.base_url.startswith("http://"):
        add("insecure_transport", "high", "The API base URL uses plain HTTP.", confidence=0.95)
    deprecated = [endpoint for endpoint in endpoints if endpoint.deprecated]
    if deprecated:
        add("deprecated_api_version", "medium", f"{len(deprecated)} endpoint(s) are marked deprecated.", endpoint=deprecated[0], confidence=0.9)
    doc_endpoints = [endpoint for endpoint in endpoints if re.search(r"/(swagger|openapi|docs|redoc)", endpoint.path, re.I)]
    if doc_endpoints:
        add("exposed_api_documentation", "medium", "API documentation endpoints are exposed by the specification.", endpoint=doc_endpoints[0], confidence=0.7)
    sensitive_paths = [endpoint for endpoint in endpoints if re.search(r"/(password|token|secret|payment|admin)", endpoint.path, re.I)]
    if sensitive_paths:
        add(
            "sensitive_endpoint_review",
            "medium",
            f"{len(sensitive_paths)} endpoint(s) appear to handle sensitive operations and require manual authorization review.",
            endpoint=sensitive_paths[0],
            confidence=0.6,
        )
    api.security_status = "issues_found" if created else "reviewed"
    db.commit()
    return created
