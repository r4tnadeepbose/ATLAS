# ATLAS

**Advanced Threat & Asset Lifecycle Security**

Unified Intelligence. Complete Visibility. Proactive Defence.

ATLAS is an enterprise security orchestration and intelligence platform for
environments running hundreds of microservices. It centralizes SBOM-powered
vulnerability intelligence, asset and attack-surface visibility, API inventory,
sensitive-data classification, contextual risk, AI-assisted triage and executive
reporting in one API-first platform.

This repository is a working, locally runnable implementation — not a UI mockup.
Metrics are computed from organization-scoped database records, and no scanner
adapter fabricates results.

---

## Capabilities

| Module | What it does |
| --- | --- |
| **ATLAS Command** | Live posture, severity mix, discovery timeline, exposure, remediation and activity |
| **Asset Intelligence** | Authorized asset inventory, exposure/criticality, services, certificates, correlated findings |
| **Microservice Intelligence** | 250+-service inventory, ownership, dependency graph with blast-radius filters |
| **SBOM Intelligence** | CycloneDX JSON/XML and SPDX JSON/tag-value ingestion, OSV correlation, version comparison |
| **AI Triage** | Provider-independent analysis (OpenAI-compatible, Anthropic, Ollama or deterministic heuristic), advisory-only |
| **Attack Surface** | Scoped discovery with Subfinder/httpx/Nmap/Nuclei, explicit authorization and audit trail |
| **API Inventory** | OpenAPI/Swagger import, endpoint inventory, static authorization/exposure checks |
| **Data Classification** | Regex, entropy and structured detection for PII, cards, keys, tokens; mandatory redaction |
| **Vulnerability Management** | Findings, SLA tracking, assignment, evidence, comments, status history |
| **Risk Management** | Documented deterministic scoring, exceptions/acceptance, remediation tasks |
| **Reporting** | Executive, vulnerability, SBOM, attack-surface, API, risk and remediation reports (PDF/CSV/JSON) |
| **RBAC & Tenancy** | Six built-in roles, server-enforced permissions, organization-level isolation, audit trail |

Target performance objective: **MTTD under 15 minutes** from vulnerability
intelligence ingestion to finding/alert generation, measured with timestamps
(not a guarantee of discovering unknown zero-days).

---

## Architecture

```
React + TypeScript + Vite + Tailwind (frontend)
                │  REST /api/v1 (JWT)
                ▼
FastAPI modular monolith ── SQLAlchemy 2 ── PostgreSQL (SQLite for local dev)
   │        │         │
   │        │         └── Redis (cache / rate-limit target)
   │        └── RabbitMQ + Celery (SBOM analysis, scans, schedule execution)
   └── Adapters: Syft, Grype, Trivy, Subfinder, httpx, Nmap, Nuclei, ZAP, Gitleaks
                 OSV, NVD, LLM providers, notification channels
```

- **API-first**: versioned REST with generated OpenAPI at `/api/docs`.
- **Tenant isolation**: every domain table carries `organization_id`; all reads
  and writes are scoped server-side.
- **Long-running work never blocks HTTP**: SBOM correlation, scans and scheduled
  assessments run in background tasks/workers.
- **Adapters are independent**: each tool reports availability; missing binaries
  produce explicit errors, never demo results.

See [`docs/architecture.md`](docs/architecture.md) for the full design.

---

## Quick start (Windows PowerShell)

```powershell
Copy-Item .env.example .env
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1

# Terminal 1 — API
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000

# Terminal 2 — UI
cd frontend
npm run dev
```

Open <http://localhost:5173>. On first run the login screen offers **workspace
bootstrap** (first organization + super administrator).

### Demo environment

```powershell
$env:ATLAS_APP_ENV="demo"
$env:ATLAS_SEED_DEMO_DATA="true"
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
```

Demo data is explicitly synthetic and belongs to an organization flagged
`demo: true`. The UI shows a demo banner.

| Account | Role | Password |
| --- | --- | --- |
| `admin@atlas.demo` | Super Administrator | `AtlasDemo!2026` |
| `security@atlas.demo` | Security Administrator | `AtlasDemo!2026` |
| `soc@atlas.demo` | SOC Analyst | `AtlasDemo!2026` |
| `vapt@atlas.demo` | VAPT Analyst | `AtlasDemo!2026` |
| `dev@atlas.demo` | Developer | `AtlasDemo!2026` |
| `exec@atlas.demo` | Executive | `AtlasDemo!2026` |

### Quick start (Linux/macOS)

```bash
cp .env.example .env
./scripts/setup.sh
./scripts/dev.sh
```

### Docker Compose

```bash
cp .env.example .env
# Set ATLAS_SECRET_KEY and database passwords in .env
docker compose up --build
```

- UI: <http://localhost:8080>
- API docs: <http://localhost:8000/api/docs>
- Optional observability: `docker compose --profile observability up`
- Optional Keycloak: `docker compose --profile oidc up`

---

## Repository layout

```
atlas/
├── backend/            FastAPI application, models, modules, workers, migrations, tests
│   ├── app/
│   │   ├── auth/       login, bootstrap, refresh, MFA, sessions
│   │   ├── core/       security, permissions, middleware, audit, metrics
│   │   ├── database/   60-table SQLAlchemy model set
│   │   ├── modules/    dashboard, assets, microservices, sbom, ai_triage,
│   │   │               attack_surface, api_inventory, data_classification,
│   │   │               vulnerabilities, risk_engine, notifications, reporting
│   │   ├── integrations/ tool + intelligence adapters
│   │   └── workers/    Celery app, SBOM/scan/intelligence/notification tasks
│   ├── migrations/     Alembic migration history
│   └── tests/          pytest suite (21 tests)
├── frontend/           React 18 + TypeScript + Vite + Tailwind + Recharts
├── infrastructure/     Kubernetes, Prometheus, Grafana, Keycloak placeholders
├── scripts/            setup/dev/backup/health-check helpers
├── docs/               architecture, API, schema, deployment, security, integrations, guide
├── docker-compose.yml
└── DEVELOPMENT_STATUS.md
```

---

## Security guardrails

- Passwords: PBKDF2-HMAC-SHA256, 210k iterations, per-user salt.
- JWT access/refresh tokens with server-side session revocation, lockout after
  repeated failures, optional TOTP MFA.
- Permissions enforced by backend dependencies on every protected route.
  UI visibility is never authorization.
- Scans require explicit authorized scope **and** an authorization reference;
  targets outside scope are rejected with `403 scope_violation`.
- No shell execution: adapters use argument arrays, timeouts and cancellation.
- Uploaded SBOMs are parsed with `defusedxml`; content is never executed.
- Detected secrets are redacted before storage or API responses.
- AI output is advisory only; it cannot change findings, execute remediation or
  close anything.
- Rate limiting, security headers, CORS allow-list, audit logging.

See [`docs/security-model.md`](docs/security-model.md).

---

## Tests

```bash
cd backend
./.venv/Scripts/python.exe -m pytest tests -q      # Windows
./.venv/bin/python -m pytest tests -q              # Linux/macOS
cd ../frontend
npm run build                                      # type-check + production build
```

Coverage includes authentication/RBAC, tenant scoping, SBOM parsers and version
matching, offline vulnerability correlation, API specification checks,
redaction, scan scope enforcement and PDF report generation.

---

## Documentation

- [Architecture](docs/architecture.md)
- [API documentation](docs/api-documentation.md)
- [Database schema](docs/database-schema.md)
- [Deployment](docs/deployment.md)
- [Security model](docs/security-model.md)
- [Integrations](docs/integrations.md)
- [User guide](docs/user-guide.md)
- [Development status](DEVELOPMENT_STATUS.md)

---

## Authorized use

ATLAS includes active-assessment integrations (Nuclei, Nmap, httpx, Subfinder).
Use them only against assets you own or are explicitly authorized to test. The
platform enforces scope and records authorization references, but the operator
remains responsible for legal authorization.

## License

MIT — see [LICENSE](LICENSE).
