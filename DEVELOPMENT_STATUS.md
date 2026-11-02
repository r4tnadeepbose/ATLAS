# ATLAS Development Status

Last updated: 2026-11-02
Current phase: Phase 9 — Enterprise hardening (in progress)

Legend: [x] implemented and verified · [~] implemented with documented gaps ·
[ ] not implemented

## Completed and verified

### Phase 1 — Foundation
- [x] Monorepo structure: frontend, backend, infrastructure, scripts, docs, tests
- [x] FastAPI application factory, configuration, structured JSON logging
- [x] SQLAlchemy 2 model set — 60 tables; Alembic initial migration applied
- [x] JWT authentication, refresh rotation, server-side session revocation
- [x] PBKDF2 password hashing, login lockout, TOTP MFA enrolment/disable
- [x] Server-side RBAC with six built-in roles; bootstrap flow
- [x] Organization tenancy enforced on all domain queries
- [x] React 18 + TypeScript + Vite + Tailwind + Recharts frontend; production build passes
- [x] Command Center with live aggregates, charts and activity

### Phase 2 — Asset and microservice intelligence
- [x] Asset inventory, environments, exposure/criticality, detail view
- [x] Microservice inventory with ownership and dependencies
- [x] Interactive relationship graph with filters (BU, risk, vulnerability status, external)
- [x] Service/asset risk refresh after findings change

### Phase 3 — SBOM intelligence
- [x] CycloneDX JSON/XML and SPDX JSON/tag-value parsers (secure XML)
- [x] Component normalization, dependency edges, checksums
- [x] OSV querybatch + offline range matching with version comparison
- [x] Findings with dedup keys, risk scoring, notifications
- [x] SBOM dashboard, component/vulnerability browsing, CSV export, version comparison
- [x] Syft generation endpoint (explicitly errors when Syft is absent)
- [x] Continuous re-analysis endpoint

### Phase 4 — Attack surface
- [x] Scope validation (domains/IPs/CIDRs) on submission and execution
- [x] Authorization-reference enforcement for active scans
- [x] Subfinder, httpx, Nmap, Nuclei adapters (argument arrays, timeouts)
- [x] Background runner with progress, logs, results, cancellation
- [x] Asset/service/technology persistence and Nuclei findings
- [x] Scan schedules with cron validation and Celery beat execution
- [x] Adapter availability reporting; no fabricated results

### Phase 5 — API inventory
- [x] OpenAPI 3.x / Swagger 2.0 JSON and YAML import
- [x] Endpoint and authentication inventory
- [x] Static checks (auth, transport, docs exposure, deprecation, sensitive paths)
- [x] API dashboard, detail, re-checks, CSV export

### Phase 6 — Data classification
- [x] Default rules: PII, financial, credentials, keys, tokens, entropy
- [x] Redaction before persistence; overlap suppression
- [x] Findings for critical/high detections
- [x] Rule management, dashboard, analysis workspace

### Phase 7 — AI triage
- [x] Provider-independent service: OpenAI-compatible, Anthropic, Ollama
- [x] Deterministic heuristic fallback labelled `heuristic`
- [x] JSON validation, prompt versioning, analysis history, token/latency tracking
- [x] Queue, batch (10), results, per-finding analysis, advisory-only enforcement
- [~] Keycloak/OIDC token validation (configuration present, validation not wired)
- [~] External notification delivery plugins (email/Slack/Teams/webhook rows and routing only)

### Phase 8 — Risk and executive intelligence
- [x] Documented deterministic scoring model with factor rationale and history
- [x] Risk register, acceptance/exception flow, remediation tasks
- [x] Executive dashboard, trend, business-unit risk, top services
- [x] Reports: executive, vulnerability, SBOM, attack surface, API, risk, remediation (PDF/CSV/JSON)
- [x] Notification rules, dedup, in-app feed, unread badge

### Phase 9 — Hardening (partial)
- [x] 21 pytest tests: auth/RBAC, tenant scoping, parsers, matching, correlation, scope, redaction, reports
- [x] Frontend type-check and production build
- [x] Dockerfiles, Compose stack, nginx SPA + API proxy, health checks
- [x] Kubernetes baseline manifests
- [x] Prometheus scraping, Grafana datasource provisioning
- [x] Security headers, CORS allow-list, rate limiting, audit logging
- [x] Setup/dev/backup/health-check scripts (Windows + Unix)
- [ ] Performance test at 250+ services / large SBOM collections
- [ ] Multi-replica Redis-backed rate limiter
- [ ] Sandboxed scanner execution (container isolation)
- [ ] Object storage for SBOM artefacts and evidence
- [ ] CI pipeline and automated dependency scanning

## Integration status

| Integration | Status |
| --- | --- |
| OSV | Implemented (live network path + offline fallback) |
| NVD | Adapter implemented (recent feed, lookup) |
| Syft / Grype / Trivy | Adapters implemented; availability depends on host install |
| Subfinder / httpx / Nmap / Nuclei | Adapters implemented; detected available on the verification host |
| ZAP / Gitleaks | Adapters implemented; not installed on the verification host |
| AI provider | Configurable; default `none` produces heuristic triage |
| Keycloak/OIDC | Configuration + Compose profile only |
| Email/Slack/Teams/Webhook | Routing/dedup/delivery-state only |

## Database migrations

| Revision | Description |
| --- | --- |
| `17dffea1d18e` | Initial ATLAS schema (60 tables) |

## API surface

Versioned REST under `/api/v1`, documented in `docs/api-documentation.md` and
generated at `/api/docs`. Includes auth, dashboard, assets, environments,
microservices, SBOM, findings, vulnerability intelligence, triage, scans,
schedules, APIs, classification, risks, remediation, notifications, reports,
users, organizations, RBAC, integrations, settings, audit, jobs and metrics.

## Testing status

```
backend: 21 passed
frontend: tsc --noEmit passed; vite build passed
browser audit: 23 routes at 1440px and 390px – no console errors, no page overflow,
responsive record cards replace tables on mobile; action-level permissions verified
for executive, developer and security-administrator roles.
```

Verified manually in browser: login, Command Center, Vulnerability Management,
Microservice map, SBOM Intelligence, AI Triage, Risk Management, Data
Classification, API Inventory.

## Known issues and limitations

1. Background jobs run as in-process FastAPI background tasks when Celery is in
   eager/local mode; the UI reports job state from scan/SBOM records, not a
   separate job queue view. `background_jobs` table exists but is not populated by
   every task.
2. Report PDF tables truncate rows at 40 per section to keep generation bounded.
3. Demo data includes historical timestamps generated relative to seed time.
4. No CSV import for assets/services; creation is via API/UI or discovery.
5. Scheduled scans run with a schedule-scoped authorization reference; operators
   must ensure schedule creation is itself an approved action.
6. OIDC/Keycloak and external notification delivery remain incomplete (see above).
7. Raw SBOM uploads are intentionally not retained; re-analysis uses normalized
   components, not the original file.
8. User provisioning is administrator-created (with a temporary password). Automated
   email invitations and administrator-initiated password reset are not implemented;
   users can change their own password from Organization Settings.

## Next development tasks

1. Wire OIDC token validation and Keycloak realm provisioning.
2. Move scanner execution to isolated containers with network policy and resource
   limits.
3. Add Redis-backed rate limiting/cache for multi-replica API deployments.
4. Introduce object storage for SBOM artefacts, evidence attachments and report
   files.
5. Implement notification delivery plugins with retry/backoff and provider audit.
6. Add load/performance tests at 250-service scale and publish results.
7. Add CI (lint, tests, build, dependency scanning, container scanning).
8. Add asset/service CSV import and bulk operations.
