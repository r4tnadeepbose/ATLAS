# ATLAS Deployment Guide

## 1. Prerequisites

| Component | Local | Production |
| --- | --- | --- |
| Python | 3.12+ | 3.12+ |
| Node.js | 20+ | build stage only |
| PostgreSQL | optional (SQLite default) | 16+ |
| Redis | optional | 7+ |
| RabbitMQ | optional | 3.13+ |
| Docker | optional | required for container path |
| Scanner tools | optional | installed on worker hosts |

Long assessments require Subfinder, httpx, Nmap, Nuclei (and optionally ZAP,
Gitleaks, Syft, Grype, Trivy) on the worker host. ATLAS reports unavailable tools
honestly; it does not simulate them.

## 2. Environment variables

All variables use the `ATLAS_` prefix and are read by `backend/app/config.py`.
A complete template lives at `.env.example`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `ATLAS_APP_ENV` | `development` | `development`, `test`, `demo`, `production` |
| `ATLAS_SECRET_KEY` | dev placeholder | JWT signing key; **must** be 48+ random bytes |
| `ATLAS_DATABASE_URL` | `sqlite:///./atlas.db` | SQLAlchemy URL |
| `ATLAS_REDIS_URL` | empty | cache/rate-limit/result backend |
| `ATLAS_RABBITMQ_URL` | empty | Celery broker |
| `ATLAS_CELERY_ALWAYS_EAGER` | `true` | local mode runs tasks inline |
| `ATLAS_CORS_ORIGINS` | localhost:5173 | comma-separated allow-list |
| `ATLAS_RATE_LIMIT_PER_MINUTE` | `240` | per client+path |
| `ATLAS_MAX_UPLOAD_MB` | `25` | SBOM/upload limit |
| `ATLAS_REQUIRE_SCAN_AUTHORIZATION` | `true` | require authorization reference |
| `ATLAS_AI_PROVIDER` | `none` | `none`, `openai`, `anthropic`, `ollama`, `openai_compatible` |
| `ATLAS_AI_API_KEY` / `ATLAS_AI_MODEL` | — / `gpt-4o-mini` | LLM configuration |
| `ATLAS_OIDC_*` | disabled | identity-provider placeholders |
| `ATLAS_SEED_DEMO_DATA` | `false` | synthetic demo dataset |

Production checklist:

- Unique random `ATLAS_SECRET_KEY` stored in a secret manager.
- `ATLAS_APP_ENV=production`, `ATLAS_DEBUG=false`, demo seeding disabled.
- TLS terminated at ingress/load balancer; same-origin API or explicit CORS.
- `ATLAS_ALLOWED_HOSTS` restricted to real hostnames.
- Database backups scheduled and restore tested.

## 3. Local development

```powershell
# Windows
Copy-Item .env.example .env
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
cd backend; .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
# second terminal
cd frontend; npm run dev
```

```bash
# Linux/macOS
cp .env.example .env
./scripts/setup.sh
./scripts/dev.sh
```

The Vite dev server proxies `/api/` (with trailing slash) to
`http://127.0.0.1:8000`. Do not widen this prefix to `/api`, or SPA routes such as
`/api-inventory` will be proxied by mistake.

### Demo dataset

```powershell
$env:ATLAS_APP_ENV="demo"; $env:ATLAS_SEED_DEMO_DATA="true"
```

Creates an organization flagged `demo: true`, six role accounts, 30 services,
18 assets, 4 API specifications, 5 SBOMs with correlated findings, classification
detections, risk assessments and heuristic triage. Password: `AtlasDemo!2026`.
The seed never touches a production organization and runs only when no demo
organization exists.

## 4. Docker Compose

```bash
cp .env.example .env
# edit ATLAS_SECRET_KEY and POSTGRES_PASSWORD / RABBITMQ_PASSWORD
docker compose up --build
```

Services: `postgres`, `redis`, `rabbitmq`, `backend` (runs
`alembic upgrade head`), `worker`, `beat`, `frontend` (nginx on port 8080).
Optional profiles: `observability` (Prometheus 9090, Grafana 3000), `oidc`
(Keycloak 8081).

Health checks:

```bash
curl http://localhost:8000/health/ready
docker compose ps
```

## 5. Kubernetes

See `infrastructure/kubernetes/README.md` and `deployment.yaml`. Build/push
images first, replace secrets, run migrations as a Job, and install scanners in
the worker image or a sandboxed execution service.

## 6. Upgrades

1. Back up the database (`scripts/backup.sh`).
2. Pull/build the new images.
3. Run `alembic upgrade head` as a one-off job before rolling replicas.
4. Roll API, then workers/beat, then frontend.
5. Verify `/health/ready`, `/api/docs`, one authenticated list endpoint and the
   notification feed.

The migration history is linear and must never be edited after deployment.

## 7. Backup and restore

```bash
./scripts/backup.sh --compose
gunzip -c backups/atlas-*.sql.gz | docker compose exec -T postgres psql -U atlas atlas
```

Also back up `.env`/secret material separately, never in the same bucket as the
dump.

## 8. Observability

- `/metrics` exposes in-process counters/gauges for Prometheus.
- `/health/live`, `/health/ready`, `/health`.
- Structured JSON logs include request id, method, path, status and duration.
- Compose profile `observability` provides Prometheus scraping `backend:8000` and
  a provisioned Grafana datasource.

## 9. Scanner installation (worker host)

```bash
# Anchore
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Aqua Trivy — follow the signed package instructions for your OS
# https://trivy.dev/latest/docs/installation/

# ProjectDiscovery
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Network / secrets
sudo apt-get install -y nmap
# gitleaks: install from signed release for your platform
# ZAP: use the official container or zap-cli wrapper
```

Restart workers after installation. Verify with `GET /api/v1/scans/tools` (an
authenticated administrator token is required).

## 10. Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `ATLAS API is unreachable` in UI | backend not running or wrong Vite proxy target |
| 401 after login | token expired; refresh runs automatically; check clock skew and `ATLAS_SECRET_KEY` consistency across replicas |
| 403 on a page | role lacks the permission; check `/api/v1/auth/me` permissions |
| SBOM stuck `queued` | worker/broker unavailable with `CELERY_ALWAYS_EAGER=false` |
| Scan `failed` with "not installed" | install the adapter on the worker host |
| Empty dashboard | no records yet; upload an SBOM or enable demo data |
| Migration error | database URL/permissions; run `alembic current` |
