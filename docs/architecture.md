# ATLAS Architecture

## 1. Shape of the system

ATLAS is a modular monolith: one FastAPI application composed of independently
testable domain modules, backed by PostgreSQL and asynchronous workers. This
keeps transactions and tenant isolation simple while leaving clean seams for
extraction into services at 250+ microservice scale.

```
┌──────────────────────────────────────────────────────────────────────┐
│ React SPA (Vite, TanStack Query)                                     │
│  · server-driven tables, charts, module workspaces                   │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ HTTPS · /api/v1 · JWT
┌──────────────────────────────▼───────────────────────────────────────┐
│ FastAPI                                                              │
│  middleware: request-id, security headers, rate limit, CORS          │
│  auth: login/bootstrap/refresh/logout/MFA/sessions                   │
│  permissions: role → permission dependencies per route               │
│  modules: dashboard assets microservices sbom triage scan apis       │
│           classification findings risk notifications reporting       │
└───────┬────────────────────────┬──────────────────────┬──────────────┘
        │ SQLAlchemy 2           │ Celery               │ adapters
┌───────▼────────┐   ┌───────────▼──────────┐  ┌────────▼──────────────┐
│ PostgreSQL     │   │ RabbitMQ (broker)    │  │ Syft Grype Trivy      │
│ (SQLite local) │   │ Redis (cache/result) │  │ Subfinder httpx Nmap  │
│ 60 tables      │   │ Celery worker + beat │  │ Nuclei ZAP Gitleaks   │
└────────────────┘   └──────────────────────┘  │ OSV NVD LLMs          │
                                               └───────────────────────┘
```

## 2. Request lifecycle

1. Middleware assigns `x-request-id`, applies security headers, rate limit and
   CORS, then logs structured JSON with status and latency.
2. Authentication resolves the bearer token, validates issuer/expiry, checks the
   server-side session (`sessions.token_jti`, not revoked) and loads the user.
3. Route dependencies enforce permissions (e.g. `assets:write`,
   `scans:run`) before the handler executes.
4. Handlers resolve `organization_id` from the authenticated user. Tenant-scoped
   lookups return `404` for foreign object IDs, never `403`, to avoid enumeration.
5. Mutations write an `audit_logs` row with actor, action, resource, outcome and
   request metadata.
6. Long-running work is delegated: SBOM analysis via FastAPI background tasks in
   local mode or Celery tasks when a broker is configured; scans always run in
   background/worker context.

## 3. Module responsibilities

| Module | Key services |
| --- | --- |
| `dashboard` | SQL aggregates: counts, posture, trends, exposure, activity, executive metrics |
| `assets` | Asset CRUD, environments, network services, certificates, discovered view |
| `microservices` | Inventory, service dependencies, graph projection with filters |
| `sbom` | Format parsers, normalization, OSV query, offline matching, findings generation |
| `ai_triage` | Prompt construction, provider adapters, JSON validation, heuristic fallback |
| `attack_surface` | Scope authorization, adapters, scan runner, asset/scan result persistence |
| `api_inventory` | OpenAPI/Swagger parsing, endpoints, static security checks |
| `data_classification` | Rule engine, regex/entropy detection, redaction, findings |
| `vulnerabilities` | Findings lifecycle, evidence, comments, assignment, SLA, intelligence browser |
| `risk_engine` | Deterministic scoring, assessments, exceptions, remediation tasks |
| `notifications` | Event emission, rule matching, dedup, delivery state |
| `reporting` | Aggregation per report type, CSV and PDF rendering |

Each module owns its routes, Pydantic input schemas, services and persistence
queries; shared primitives live in `app/api` and `app/core`.

## 4. SBOM → vulnerability workflow

```
upload (CycloneDX/SPDX)
  → detect + parse (defusedxml for XML)
  → normalize components (name, version, purl, ecosystem, licence, supplier)
  → persist components + dependency edges
  → correlate:
       a. offline: match stored vulnerability_records by purl/name+ecosystem and
          version ranges
       b. online: OSV querybatch for all purls, upsert intelligence records
  → create component_vulnerability links
  → create/update organization findings with dedup key
       dependency:{service|asset}:{name}@{version}:{CVE|OSV}
  → deterministic risk score + SLA
  → notify (critical/high) with dedup window
  → recompute service/asset risk
```

OSV failures degrade to offline correlation and are recorded in scan history;
they never abort ingestion.

## 5. Scanning workflow and safety

- Scope is validated on submission **and** per target in the runner. Domain
  suffixes, explicit IPs and CIDRs are supported; empty scope is rejected.
- Active scans require an `authorization_reference` when
  `ATLAS_REQUIRE_SCAN_AUTHORIZATION=true` (default).
- Each adapter runs with an argument list (`shell=False`), a timeout and a target
  character allow-list; binaries that are absent report `available: false`.
- The runner records progress, logs, result artifacts and cancellation checks
  between stages. `full_recon` = subdomains → HTTP probe → service discovery →
  template assessment.
- No result is synthesized. A demo scan record is only created by the demo seed
  and is explicitly labelled as such.

## 6. Risk and metrics

- Risk score is computed by `atlas-risk-v1` (documented weights), clamped 0–100.
  AI may explain but not alter the score.
- Posture = `100 − mean(open finding risk)`.
- MTTD = finding `first_seen` − vulnerability record ingestion time (`created_at`).
- MTTR = resolved_at − first_seen, averaged over resolved findings.
- Executive metrics reuse the same aggregate functions as the command dashboard,
  so figures cannot diverge between views.

## 7. Data and scale

- UUID primary keys, foreign keys with cascade behaviour, composite indexes on
  tenant + common filters (`organization_id`, `severity`, `status`, dates).
- Soft deletion on primary inventory entities.
- Pagination on every list endpoint (default 25, max 200).
- SBOM raw content is not retained in the relational store; component and
  vulnerability intelligence is normalized. Large artefacts are intended for
  object storage (see limitations).
- API replicas are stateless; workers scale horizontally. Redis is used for
  caching/rate limiting targets, RabbitMQ for job distribution.

## 8. Deliberate trade-offs

- **Modular monolith over microservices**: transactional consistency and simpler
  tenancy at the current stage; module boundaries support later extraction.
- **Deterministic triage fallback**: without an LLM the platform still produces
  context, clearly labelled `heuristic`, instead of blocking the workflow.
- **On-demand report rendering**: avoids stale report files; generation is
  cheap at current volumes.
- **Scanners as host tools**: keeps the platform honest about availability;
  containerized sandbox execution is the next hardening step.
