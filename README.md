# ATLAS

**Advanced Threat & Asset Lifecycle Security**

**Unified Intelligence. Complete Visibility. Proactive Defence.**

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React 18](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![License: MIT](https://img.shields.io/badge/License-MIT-36D399.svg)](LICENSE)

ATLAS is an enterprise security orchestration and intelligence platform for
organizations that run hundreds of microservices. It collects security data from
different tools, normalizes it, connects it to the services and teams it belongs
to, and turns it into one prioritized, auditable view.

It is a working, locally runnable application — not a UI mockup. Dashboard
metrics are computed from organization-scoped database records, and scanners
never fabricate results.

![ATLAS Command Center](docs/screenshots/02-command-center-dark.png)

---

## Table of contents

- [What problem does it solve?](#what-problem-does-it-solve)
- [What ATLAS is not](#what-atlas-is-not)
- [Screenshots](#screenshots)
- [Capabilities](#capabilities)
- [Specifications](#specifications)
- [Architecture](#architecture)
- [Repository structure](#repository-structure)
- [Installation](#installation)
- [Demo accounts](#demo-accounts)
- [Configuration](#configuration)
- [Security model](#security-model)
- [Testing](#testing)
- [Documentation](#documentation)
- [Known limitations](#known-limitations)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## What problem does it solve?

In a large microservice estate, security information is fragmented:

- the SBOM knows which package versions are in a service;
- a vulnerability feed knows which versions are unsafe;
- a scanner knows which host is reachable from the internet;
- an API document knows an endpoint has no authentication;
- a secret scan knows a credential is exposed;
- the CMDB knows which team owns the service;
- management asks: *how exposed are we, and what should we fix first?*

Each tool answers a small question. ATLAS answers the combined question:

> **Which parts of the business are exposed, how badly, who owns them, and what
> must be fixed first?**

It correlates assets, microservices, SBOM components, APIs, findings,
vulnerability intelligence and sensitive data into a single risk picture, then
tracks remediation to completion.

### What ATLAS is not

- Not a replacement for scanners — it orchestrates them through adapters.
- Not a guarantee of discovering unknown zero-days.
- Not an AI autopilot — AI output is advisory only.
- Not authorized to scan anything you do not own or have permission to test.

---

## Screenshots

### Login and themes

| Dark login | Light login |
| --- | --- |
| ![Dark login](docs/screenshots/01-login-dark.png) | ![Light login](docs/screenshots/01b-login-light.png) |

| Light mode — Command Center |
| --- |
| ![Light dashboard](docs/screenshots/18-command-center-light.png) |

### Core screens

| Asset Intelligence | Microservice relationship map |
| --- | --- |
| ![Assets](docs/screenshots/03-asset-intelligence.png) | ![Microservice map](docs/screenshots/04-microservice-map.png) |

| SBOM Intelligence | AI Triage |
| --- | --- |
| ![SBOM](docs/screenshots/05-sbom-intelligence.png) | ![AI Triage](docs/screenshots/06-ai-triage.png) |

| Attack Surface Management | API Inventory |
| --- | --- |
| ![Attack surface](docs/screenshots/07-attack-surface.png) | ![API inventory](docs/screenshots/08-api-inventory.png) |

| Data Classification | Vulnerability Management |
| --- | --- |
| ![Data classification](docs/screenshots/09-data-classification.png) | ![Vulnerabilities](docs/screenshots/10-vulnerability-management.png) |

| Risk Management | Executive Intelligence |
| --- | --- |
| ![Risk management](docs/screenshots/11-risk-management.png) | ![Executive](docs/screenshots/13-executive-intelligence.png) |

### Operations and administration

| Security Reports | Notification Center |
| --- | --- |
| ![Reports](docs/screenshots/14-security-reports.png) | ![Notifications](docs/screenshots/12-notification-center.png) |

| User Management | Role-Based Access Control |
| --- | --- |
| ![Users](docs/screenshots/15-user-management.png) | ![RBAC](docs/screenshots/16-rbac.png) |

| Integrations | Mobile layout |
| --- | --- |
| ![Integrations](docs/screenshots/17-integrations.png) | ![Mobile](docs/screenshots/19-command-center-mobile.png) |

> Demo data is synthetic and clearly labelled. The screenshots above show the
> bundled demo workspace, not real customer data.

---

## Capabilities

| Module | What it does |
| --- | --- |
| **ATLAS Command** | Live posture, severity mix, discovery timeline, exposure, remediation and activity |
| **Asset Intelligence** | Asset inventory, exposure and criticality, services, certificates, correlated findings |
| **Microservice Intelligence** | Service inventory, ownership, interactive dependency graph and blast radius |
| **SBOM Intelligence** | CycloneDX JSON/XML and SPDX JSON/tag-value ingestion, OSV correlation, version comparison |
| **AI Triage** | Provider-independent analysis with OpenAI-compatible, Anthropic, Ollama or deterministic heuristic fallback |
| **Attack Surface** | Scoped discovery with Subfinder, httpx, Nmap and Nuclei; authorization and audit trail |
| **API Inventory** | OpenAPI/Swagger import, endpoint inventory, static authorization and exposure checks |
| **Data Classification** | Regex and entropy detection for PII, cards, keys and tokens; redaction before storage |
| **Vulnerability Management** | Findings, SLA tracking, evidence, comments, assignment and status history |
| **Risk Management** | Documented deterministic scoring, exceptions, accepted risk and remediation tasks |
| **Executive Intelligence** | Business risk, posture trend, MTTD/MTTR and drill-through |
| **Reporting** | Executive, vulnerability, SBOM, attack-surface, API, risk and remediation reports (PDF/CSV/JSON) |
| **Notifications** | Severity rules, deduplication, in-app feed and delivery state |
| **RBAC & Tenancy** | Six built-in roles, server-enforced permissions, organization isolation, audit trail |

---

## Specifications

### Technology stack

| Layer | Technology |
| --- | --- |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Recharts, TanStack Query, React Router, React Hook Form, Zod |
| Backend | Python 3.12+, FastAPI, Pydantic, SQLAlchemy 2, Alembic, REST API |
| Data | PostgreSQL 16 in production; SQLite for local development and tests |
| Async processing | RabbitMQ, Celery workers and beat; Redis for cache/coordination targets |
| Identity | JWT access/refresh tokens, server-side sessions, TOTP MFA; Keycloak/OIDC configuration scaffold |
| Integrations | Syft, Grype, Trivy, Subfinder, httpx, Nmap, Nuclei, ZAP, Gitleaks, OSV, NVD, LLM providers |
| Delivery | Docker Compose, nginx, Kubernetes manifests, Prometheus, Grafana |
| Database size | 60 tables, UUID primary keys, tenant indexes, soft deletion, migration history |

### Security controls

- PBKDF2-HMAC-SHA256 password hashing (210k iterations, per-user salt).
- JWT session revocation, refresh rotation, login lockout, optional TOTP MFA.
- Server-side RBAC on every protected endpoint; six roles.
- Organization-level tenant isolation; foreign-tenant IDs return `404`.
- Authorized scan scope enforced on submission and at execution.
- No shell execution; adapters use argument arrays, timeouts and cancellation.
- Uploaded SBOMs parsed with `defusedxml`; files are never executed.
- Sensitive values masked before storage and excluded from logs.
- Rate limiting, security headers, CORS allow-list, audit logging.
- AI output marked advisory; it cannot modify findings or execute remediation.

### Performance target

- **MTTD under 15 minutes** from vulnerability-intelligence ingestion to
  affected-service finding generation, measured from timestamps.
- Pagination, tenant indexes, background processing and worker scaling for
  250+ microservices.
- Dashboard metrics are computed live; no hardcoded production values.

---

## Architecture

```mermaid
flowchart LR
    U["Browser<br/>React + Vite"] -->|"JWT · /api/v1"| API["FastAPI<br/>Auth · RBAC · Modules"]
    API --> DB[("PostgreSQL / SQLite")]
    API --> REDIS[("Redis")]
    API --> MQ["RabbitMQ"]
    MQ --> WORKER["Celery workers + beat"]
    WORKER --> DB
    WORKER --> ADAPTERS["Scanner adapters"]
    API --> ADAPTERS
    ADAPTERS --> TOOLS["Syft · Grype · Trivy<br/>Subfinder · httpx · Nmap<br/>Nuclei · ZAP · Gitleaks"]
    API --> INTEL["OSV · NVD"]
    API --> AI["LLM provider<br/>or heuristic triage"]
    API --> NOTIFY["Notification rules<br/>dedup · channels"]
    API --> REPORTS["PDF · CSV · JSON"]
    API --> AUDIT["Audit trail"]
```

### Data flow

```text
Collect → Normalize → Analyze → Correlate → AI triage → Risk score
        → Alert → Visualize → Remediate → Verify → Continuous monitoring
```

1. **Collect** SBOMs, authorized scan results, API specifications, data samples,
   asset records and vulnerability intelligence.
2. **Normalize** assets, services, packages (purl), findings and API metadata.
3. **Analyze** vulnerable dependencies, exposure, authentication, secrets and
   container/network results.
4. **Correlate** findings with the asset, microservice, owner, business unit,
   CVE/OSV record, exposure and data sensitivity.
5. **Triage** with an optional LLM or the deterministic heuristic engine; output
   is always advisory.
6. **Score** with the documented `atlas-risk-v1` model and assign an SLA.
7. **Alert** through rules, deduplication and configured channels.
8. **Visualize** in the dashboard, service graph, vulnerability register, risk
   register and executive view.
9. **Remediate** by assigning, fixing, attaching evidence and resolving, with a
   complete audit history.

More detail: [docs/architecture.md](docs/architecture.md).

---

## Repository structure

```text
atlas/
├── backend/
│   ├── app/
│   │   ├── auth/                    Login, bootstrap, refresh, MFA, sessions
│   │   ├── core/                    Security, permissions, audit, middleware, metrics
│   │   ├── database/
│   │   │   ├── models/              60 SQLAlchemy tables
│   │   │   └── session.py
│   │   ├── modules/
│   │   │   ├── dashboard/           Command Center aggregates
│   │   │   ├── assets/              Assets + environments
│   │   │   ├── microservices/       Inventory + dependency graph
│   │   │   ├── sbom/                Parsers, matching, correlation
│   │   │   ├── ai_triage/           Providers + heuristic service
│   │   │   ├── attack_surface/      Scope, runner, scan routes
│   │   │   ├── api_inventory/       Spec import + checks
│   │   │   ├── data_classification/ Rules + redaction
│   │   │   ├── vulnerabilities/     Findings + intelligence browser
│   │   │   ├── risk_engine/         Scoring, assessments, remediation
│   │   │   ├── notifications/       Rules, dedup, delivery state
│   │   │   └── reporting/           PDF/CSV/JSON reports
│   │   ├── integrations/            Tool and intelligence adapters
│   │   ├── workers/                 Celery app, tasks, scheduler
│   │   ├── demo/                    Synthetic demo seed
│   │   ├── api/v1/                  Versioned router + admin endpoints
│   │   └── main.py
│   ├── migrations/                  Alembic history
│   ├── tests/                       21 pytest tests
│   ├── alembic.ini
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── public/                      Favicon, theme init
│   ├── src/
│   │   ├── api/                     Typed client + endpoints
│   │   ├── components/              UI, charts, navigation, common
│   │   ├── context/                 Auth, theme, environment
│   │   ├── hooks/
│   │   ├── layouts/
│   │   ├── pages/                   All 19 module screens
│   │   ├── routes/
│   │   ├── styles/                  Dark + light design tokens
│   │   ├── types/
│   │   └── utils/
│   ├── index.html
│   ├── tailwind.config.js
│   ├── vite.config.ts
│   ├── nginx.conf
│   └── Dockerfile
├── infrastructure/
│   ├── kubernetes/                  Baseline deployment
│   ├── prometheus/                  Scrape config
│   ├── grafana/                     Datasource provisioning
│   ├── nginx/ · docker/ · monitoring/ · keycloak/
├── docs/
│   ├── architecture.md
│   ├── api-documentation.md
│   ├── database-schema.md
│   ├── deployment.md
│   ├── security-model.md
│   ├── integrations.md
│   ├── user-guide.md
│   └── screenshots/                 README screenshots
├── samples/                         Demo SBOM + OpenAPI specification
├── scripts/                         setup, dev, backup, health-check
├── tests/                           e2e checklist, k6 load profile
├── run.py                           One-click launcher
├── run.bat                          Windows double-click launcher
├── HOW_TO_RUN.md                    Plain-language run guide
├── HOW_IT_WORKS.md                  Explanation + flowchart
├── docker-compose.yml
├── .env.example
├── DEVELOPMENT_STATUS.md
├── README.md
└── LICENSE
```

---

## Installation

### Option 1 — one click (recommended)

**Windows:** double-click [`run.bat`](run.bat).

Or from a terminal:

```powershell
cd C:\path\to\atlas
python run.py
```

**Linux / macOS:**

```bash
cd atlas
python3 run.py
```

The launcher:

- creates `backend/.venv` if needed;
- installs backend and frontend dependencies;
- creates `.env` from `.env.example`;
- applies database migrations;
- starts the API on `http://127.0.0.1:8000`;
- starts the UI on `http://127.0.0.1:5173`;
- opens the browser;
- stops only the processes it started on `Ctrl+C`.

If ATLAS is already running, it opens the dashboard. If only the API or UI is
running, it starts the missing part.

```bash
python run.py --demo        # force demo data
python run.py --no-demo     # clean workspace (bootstrap on first login)
python run.py --no-browser  # do not auto-open the browser
python run.py --reinstall   # reinstall dependencies
python run.py --check       # start, verify, then stop
```

### Option 2 — manual setup (Windows)

```powershell
Copy-Item .env.example .env
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
```

Terminal 1 — API:

```powershell
cd backend
$env:ATLAS_APP_ENV="demo"
$env:ATLAS_SEED_DEMO_DATA="true"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

Terminal 2 — UI:

```powershell
cd frontend
npm run dev
```

### Option 3 — manual setup (Linux / macOS)

```bash
cp .env.example .env
./scripts/setup.sh
./scripts/dev.sh
```

### Option 4 — Docker Compose

```bash
cp .env.example .env
# set ATLAS_SECRET_KEY and database passwords in .env
docker compose up --build
```

- UI: <http://localhost:8080>
- API docs: <http://localhost:8000/api/docs>

Optional profiles:

```bash
docker compose --profile observability up   # Prometheus + Grafana
docker compose --profile oidc up            # Keycloak
```

### Requirements

- Python 3.12 or newer
- Node.js 20 or newer
- SQLite (bundled with Python) for local use, or PostgreSQL 16
- Optional: Redis 7, RabbitMQ 3.13 for background workers
- Optional: Docker Desktop

---

## Demo accounts

The demo workspace is **Indus Demo Corp**. All demo accounts use the password:

```text
AtlasDemo!2026
```

| Name | Email | Role |
| --- | --- | --- |
| Aarav Sharma | `admin@atlas.demo` | Super Administrator |
| Ananya Iyer | `security@atlas.demo` | Security Administrator |
| Rohan Mehta | `soc@atlas.demo` | SOC Analyst |
| Ishita Nair | `vapt@atlas.demo` | VAPT Analyst |
| Arjun Patel | `dev@atlas.demo` | Developer |
| Meera Krishnan | `exec@atlas.demo` | Executive |

The login page lists all six demo accounts; clicking one fills the form. Any
additional user created in **User Management** can sign in with their own email.

**Dark / light mode:** use the sun/moon button in the top bar (or on the login
screen). The choice is stored in the browser.

---

## Configuration

Configuration uses `ATLAS_`-prefixed environment variables. See
[`.env.example`](.env.example). Important values:

| Variable | Default | Purpose |
| --- | --- | --- |
| `ATLAS_APP_ENV` | `development` | `development`, `test`, `demo`, `production` |
| `ATLAS_SECRET_KEY` | development placeholder | JWT signing key; replace with 48+ random bytes |
| `ATLAS_DATABASE_URL` | `sqlite:///./atlas.db` | Database connection |
| `ATLAS_REDIS_URL` | empty | Cache/coordination |
| `ATLAS_RABBITMQ_URL` | empty | Celery broker |
| `ATLAS_CORS_ORIGINS` | localhost:5173 | Allowed origins |
| `ATLAS_RATE_LIMIT_PER_MINUTE` | `240` | Per client/path limit |
| `ATLAS_MAX_UPLOAD_MB` | `25` | Upload limit |
| `ATLAS_REQUIRE_SCAN_AUTHORIZATION` | `true` | Require authorization reference |
| `ATLAS_AI_PROVIDER` | `none` | `none`, `openai`, `anthropic`, `ollama`, `openai_compatible` |
| `ATLAS_AI_API_KEY` / `ATLAS_AI_MODEL` | — / `gpt-4o-mini` | LLM configuration |
| `ATLAS_SEED_DEMO_DATA` | `false` | Synthetic demo dataset |

Generated secrets, database files and credentials must never be committed.

---

## Security model

- Authentication: password + optional TOTP MFA, JWT access/refresh tokens,
  server-side session revocation, login lockout.
- Authorization: six roles; permissions checked on every protected endpoint.
  Frontend visibility is never treated as authorization.
- Tenant isolation: every domain record is organization-scoped; foreign IDs
  return `404`.
- Scans: explicit authorized scope, authorization reference, no shell execution,
  timeouts, cancellation and audit trail.
- Uploads: size limits, secure XML parsing, no execution.
- Sensitive data: masked at detection time; raw secrets are not stored.
- AI: advisory only; cannot modify findings or execute remediation.
- Risk: deterministic documented scoring (`atlas-risk-v1`); AI cannot set it.

Read the full model: [docs/security-model.md](docs/security-model.md).

---

## Testing

```bash
cd backend
./.venv/Scripts/python.exe -m pytest tests -q      # Windows
./.venv/bin/python -m pytest tests -q              # Linux/macOS

cd ../frontend
npm run build                                      # type-check + production build
```

Current verification:

- Backend: **21 tests passed** (authentication, RBAC, tenant scoping, SBOM
  parsers, version matching, correlation, redaction, scan scope, PDF reports).
- Frontend: TypeScript check and production build pass.
- Browser audit: 19 routes in dark and light mode, desktop and mobile; no
  console errors or page overflow.

---

## Documentation

- [How to run it](HOW_TO_RUN.md)
- [How ATLAS works](HOW_IT_WORKS.md) — plain-language explanation and flowchart
- [Architecture](docs/architecture.md)
- [API documentation](docs/api-documentation.md)
- [Database schema](docs/database-schema.md)
- [Deployment](docs/deployment.md)
- [Security model](docs/security-model.md)
- [Integrations](docs/integrations.md)
- [User guide](docs/user-guide.md)
- [Development status](DEVELOPMENT_STATUS.md)

---

## Known limitations

- Keycloak/OIDC configuration is present, but external OIDC token validation is
  not wired yet; native JWT login is the active path.
- Email, Slack, Teams and webhook delivery rules/state exist; provider delivery
  plugins require deployment-specific credentials.
- Scanner adapters depend on tools installed on the worker host. ATLAS reports
  unavailable tools honestly.
- Raw SBOM files are parsed and not retained; normalized components are stored.
- Production hardening items still open: sandboxed scanner containers, object
  storage, distributed rate limiting and 250-service load testing.

See [DEVELOPMENT_STATUS.md](DEVELOPMENT_STATUS.md) for the complete list.

---

## License

MIT License — see [LICENSE](LICENSE).

Copyright (c) 2026 ATLAS Security Orchestration.

---

## Disclaimer

ATLAS includes active assessment integrations (Subfinder, httpx, Nmap, Nuclei,
ZAP). **Use them only against assets you own or are explicitly authorized to
test.** The platform validates scope and records authorization references, but
the operator remains responsible for legal authorization, rate limits and
applicable law.

The software is provided “as is”, without warranty of any kind. It is not a
guarantee of security, compliance or discovery of every vulnerability. The
15-minute MTTD target is measured from intelligence ingestion to finding
generation; it is not a claim about zero-day discovery.

AI-generated content is advisory only and may be incorrect. All demo data is
synthetic and must never be treated as real customer data. Third-party tools
retain their own licenses and terms.

See [LICENSE](LICENSE) for the full warranty and liability disclaimer.
