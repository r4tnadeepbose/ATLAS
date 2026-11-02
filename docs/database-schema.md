# ATLAS Database Schema

PostgreSQL is the primary store; SQLite is supported for local development and
the test suite. Schema is defined with SQLAlchemy 2 typed models and versioned
with Alembic (`backend/migrations`). The initial revision creates **60 tables**.

## Conventions

- UUID primary keys (`Uuid(as_uuid=True)`), application-generated.
- `created_at` / `updated_at` timestamps; UTC.
- `deleted_at` soft deletion on inventory entities (assets, microservices, APIs,
  findings, users, organizations).
- Every tenant-owned row has `organization_id` with an index; queries always
  filter it.
- JSON columns for flexible normalized intelligence (affected ranges, factors,
  metadata) rather than unbounded relational expansion.
- Composite unique constraints prevent duplicate links and racing inserts:
  `findings(organization_id, dedup_key)`, `component_vulnerabilities(component_id,
  vulnerability_id)`, `user_roles(user_id, role_id)`.

## Table groups

### Identity and organization
`organizations`, `users`, `roles`, `permissions`, `user_roles`,
`role_permissions`, `teams`, `organization_memberships`, `sessions`,
`audit_logs`.

Relationships: users belong to one organization (plus explicit membership rows),
users have many roles; roles reference permissions; sessions bind access-token
`jti` and refresh `jti` to a user for revocation.

### Infrastructure and assets
`assets`, `environments`, `asset_owners`, `asset_relationships`,
`network_services`, `discovered_subdomains`, `technologies`, `certificates`,
`microservices`, `service_dependencies`.

Relationships: assets optionally belong to an environment and have an owner;
network services, technologies and certificates reference an asset.
Microservices reference environment/team; `service_dependencies` connects
services (or names an external target).

### SBOM intelligence
`sbom_documents`, `sbom_components`, `component_relationships`,
`vulnerability_records`, `component_vulnerabilities`, `sbom_scan_history`.

`sbom_documents` may reference a microservice and asset. Components reference a
document; component relationships form dependency edges.
`vulnerability_records` is global intelligence keyed by `(source, identifier)`
with affected package ranges and fixed versions. `component_vulnerabilities`
links components to records and carries the matched version window.

### Security findings
`findings`, `finding_evidence`, `finding_comments`, `finding_status_history`,
`finding_assignments`, `finding_exceptions`.

Findings reference asset, microservice, API, component and vulnerability record.
`dedup_key` prevents duplicate creation across re-scans. Status changes append
history; evidence is stored redacted.

### Attack surface
`scan_jobs`, `scan_results`, `scan_history`, `scan_schedules`, `scan_logs`.

Scan jobs store authorized scope, progress, cancellation, error state and the
authorization reference. Results hold tool artefacts as JSON.

### API inventory
`apis`, `api_endpoints`, `api_authentication`, `api_specifications`,
`api_security_findings`.

APIs reference microservice/asset/environment; endpoints belong to an API;
specifications keep the uploaded document for re-checking.

### Data classification
`classification_rules`, `data_classifications`, `sensitive_data_findings`.

Rules are tenant-configurable; classifications record category, method,
confidence and location; sensitive findings store only redacted samples.

### Risk management
`risk_assessments`, `risk_scores`, `risk_exceptions`, `remediation_tasks`.

Assessments link to finding/asset/microservice and store factor rationale.
`risk_scores` keeps historical computations. Remediation tasks are created per
assessed finding.

### AI intelligence
`ai_triage_results`, `ai_analysis_history`, `ai_model_configurations`,
`ai_prompt_versions`.

Triage results are immutable advisory records; history stores request/response
summaries and token usage. Prompt versions support change control.

### Notifications and operations
`notifications`, `notification_rules`, `integrations`, `system_settings`,
`background_jobs`, `reports`.

## Indexing strategy

- Tenant filters: `organization_id` indexed on every domain table.
- Hot list filters: severity, status, category, risk score, dates.
- Lookup keys: `purl`, `cve_id`, `identifier`, `dedup_key`, `email`, `api_ref`.
- Unique indexes for natural identifiers and association tables.

## Migrations

```bash
cd backend
alembic upgrade head          # apply
alembic revision --autogenerate -m "change"
alembic downgrade -1          # roll back one revision
```

`alembic/env.py` reads `ATLAS_DATABASE_URL` through application settings, so the
same command works locally and in containers. Startup creates missing tables only
outside production (`development`, `demo`, `test`); in production the migration
step is authoritative and runs before the API starts.

## Data retention and privacy

- SBOM file content is parsed and not stored; normalized components are retained.
- Detected secrets are masked at write time.
- Audit logs should be retained per policy; they contain action metadata, not
  secret values.
- Deleting an organization cascades to tenant-owned rows.
