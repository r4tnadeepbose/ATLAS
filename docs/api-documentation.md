# ATLAS API Documentation

Base URL: `/api/v1` · Interactive OpenAPI: `/api/docs` · ReDoc: `/api/redoc`

All endpoints except `/auth/*`, `/health*` and `/metrics` require
`Authorization: Bearer <access_token>`.

## Conventions

- JSON request/response. File uploads use `multipart/form-data`.
- List endpoints accept `page` (default 1), `page_size` (default 25, max 200),
  `q` (search), `sort_by`, `sort_dir=asc|desc`, plus module filters.
- List responses:
  ```json
  {
    "items": [],
    "pagination": {"page": 1, "page_size": 25, "total": 0, "pages": 0, "has_next": false, "has_prev": false}
  }
  ```
- Errors:
  ```json
  {"error": "forbidden", "message": "Insufficient permissions", "required": ["scans:run"], "details": null}
  ```
  Validation errors additionally return a `details` array of `{field, message}`.
- `401` means missing/expired/revoked credentials; `403` means authenticated but
  not permitted; `404` is used for both missing and foreign-tenant objects.
- Rate limiting returns `429` with `Retry-After`, `X-RateLimit-Limit`,
  `X-RateLimit-Remaining`.
- Audit-relevant mutations are recorded automatically.

## Authentication

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/auth/bootstrap-status` | `requires_bootstrap`, `demo`, roles |
| POST | `/auth/bootstrap` | First-run only: organization + super administrator |
| POST | `/auth/login` | `email`, `password`, optional `mfa_code`; returns access + refresh tokens and profile |
| POST | `/auth/refresh` | Rotates refresh token and session |
| POST | `/auth/logout` | Revokes the current session |
| GET | `/auth/me` | Profile, roles, permission keys |
| GET | `/auth/permissions` | Role/permission catalog |
| POST | `/auth/mfa/setup` | Returns TOTP secret + otpauth URI |
| POST | `/auth/mfa/enable` | Verify code, enable MFA |
| POST | `/auth/mfa/disable` | Password + code required |
| POST | `/auth/password` | Change own password |
| GET | `/auth/sessions` | Recent sessions |
| DELETE | `/auth/sessions/{id}` | Revoke a session |

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@atlas.demo","password":"AtlasDemo!2026"}'
```

## Dashboard

| Method | Path |
| --- | --- |
| GET | `/dashboard/overview` |
| GET | `/dashboard/vulnerabilities` |
| GET | `/dashboard/risk-trends` |
| GET | `/dashboard/activity?limit=20` |
| GET | `/dashboard/executive` |
| GET | `/dashboard/background-jobs` |

## Assets & environments

| Method | Path |
| --- | --- |
| GET/POST | `/assets` |
| GET | `/assets/summary` |
| GET | `/assets/discovered?days=30` |
| GET/PATCH/DELETE | `/assets/{id}` |
| POST | `/assets/{id}/relationships` |
| GET/POST | `/environments` |

## Microservices

| Method | Path |
| --- | --- |
| GET/POST | `/microservices` |
| GET | `/microservices/summary` |
| GET/PATCH/DELETE | `/microservices/{id}` |
| GET/POST | `/microservices/{id}/dependencies` |
| GET | `/microservices/graph/relationship-map?business_unit=&risk_level=&language=&vulnerability_status=` |

## SBOM intelligence

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/sbom` | filters: `microservice_id`, `status`, `format` |
| GET | `/sbom/dashboard` | |
| GET | `/sbom/compare?left=&right=` | component diff |
| POST | `/sbom/upload` | multipart `file`, optional `microservice_id`, `asset_id`, `version_label`, `analyze` |
| POST | `/sbom/generate` | Syft generation; 422 if Syft is absent |
| GET | `/sbom/{id}` | document + components + vulnerabilities + scan history |
| GET | `/sbom/{id}/components?vulnerable_only=&ecosystem=` | paginated |
| GET | `/sbom/{id}/vulnerabilities` | |
| GET | `/sbom/{id}/export` | CSV |
| POST | `/sbom/{id}/analyze?online=true` | 202; background correlation |
| DELETE | `/sbom/{id}` | |

## Findings & vulnerability records

| Method | Path |
| --- | --- |
| GET | `/findings` |
| GET | `/findings/summary` |
| GET/PATCH | `/findings/{id}` |
| POST | `/findings/{id}/comments` |
| POST | `/findings/{id}/evidence` |
| POST | `/findings/{id}/assign` |
| POST | `/findings/{id}/exception` |
| GET | `/vulnerabilities` |
| GET | `/vulnerabilities/{id}` |
| POST | `/vulnerabilities/lookup/{identifier}` |

Finding filters: `severity`, `status`, `category`, `source_module`, `asset_id`,
`microservice_id`, `assigned_to`, `business_unit`, `environment_id`, `open_only`.

## AI triage

| Method | Path |
| --- | --- |
| GET | `/triage/queue` |
| GET | `/triage/results` |
| GET | `/triage/dashboard` |
| POST | `/triage/analyze` `{finding_id}` |
| POST | `/triage/batch` `{finding_ids: [...]}` (max 20) |
| GET/POST | `/triage/config` |
| GET | `/triage/{id}` |

Results include `provider` (`heuristic` when no LLM is configured),
`advisory_only: true`, confidence, false-positive likelihood and token usage.

## Attack surface & schedules

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/scans/tools` | adapter availability |
| GET | `/scans/dashboard` | |
| GET/POST | `/scans` | POST requires `scope` and `authorization_reference` |
| GET | `/scans/{id}` | job, results, logs, history |
| POST | `/scans/{id}/cancel` | |
| GET | `/scans/{id}/results` | |
| GET | `/scans/{id}/logs` | |
| GET/POST | `/scan-schedules` | cron validated |
| PATCH/DELETE | `/scan-schedules/{id}` | |

```json
POST /api/v1/scans
{
  "name": "Q4 external review",
  "scan_type": "full_recon",
  "target": "company.example",
  "scope": {"domains": ["company.example"]},
  "authorization_reference": "AUTH-2026-014"
}
```

Out-of-scope targets return `403 scope_violation`; missing authorization returns
`422`.

## API inventory

| Method | Path |
| --- | --- |
| GET/POST | `/apis` |
| GET | `/apis/dashboard` |
| POST | `/apis/import` (multipart OpenAPI/Swagger JSON or YAML) |
| GET/PATCH | `/apis/{id}` |
| POST | `/apis/{id}/checks` |
| GET | `/apis/{id}/export` |

## Data classification

| Method | Path |
| --- | --- |
| GET | `/classification` |
| GET | `/classification/dashboard` |
| POST | `/classification/analyze` `{text, source_label, asset_id?, microservice_id?}` |
| GET/POST | `/classification/rules` |
| PATCH | `/classification/rules/{id}` |
| GET | `/classification/{id}` |
| POST | `/classification/seed-rules` |

Detected values are masked before storage; responses never include the full
secret.

## Risk & remediation

| Method | Path |
| --- | --- |
| GET | `/risks` |
| GET | `/risks/summary` |
| POST | `/risks/recompute` |
| GET/POST | `/risks/exceptions` |
| GET | `/risks/{id}` |
| POST | `/risks/{id}/accept` `{reason, expires_at?}` |
| PATCH | `/risks/{id}` |
| GET/POST | `/remediation-tasks` |
| PATCH | `/remediation-tasks/{id}` |

## Notifications

| Method | Path |
| --- | --- |
| GET | `/notifications` |
| GET | `/notifications/unread-count` |
| POST | `/notifications/{id}/read` |
| POST | `/notifications/read-all` |
| GET/POST | `/notifications/rules` |
| PATCH | `/notifications/rules/{id}` |
| POST | `/notifications/test` |

## Reports

| Method | Path |
| --- | --- |
| GET/POST | `/reports` |
| GET | `/reports/types` |
| GET | `/reports/{id}` |
| GET | `/reports/{id}/download` |

Types: `executive`, `vulnerability`, `sbom`, `attack_surface`, `api_security`,
`risk`, `remediation`. Formats: `pdf`, `csv`, `json`.

## Administration

| Method | Path |
| --- | --- |
| GET/POST | `/users` |
| GET/PATCH | `/users/{id}` |
| PATCH | `/users/{id}/role` |
| GET | `/users/roles/catalog` |
| GET | `/rbac` |
| GET | `/integrations` |
| PATCH | `/integrations/{id}` |
| POST | `/integrations/{id}/test` |
| GET | `/settings` |
| PUT | `/settings` |
| GET | `/organizations/current` |
| PATCH | `/organizations/current` |
| GET/POST | `/organizations/teams` |
| GET | `/organizations/audit-logs` |
| GET | `/admin/audit-logs` |
| GET | `/admin/background-jobs` |
| GET | `/admin/metrics` |

## Operations

| Path | Purpose |
| --- | --- |
| `GET /health` | service identity and environment |
| `GET /health/live` | process liveness |
| `GET /health/ready` | database (and Redis when configured) readiness |
| `GET /metrics` | Prometheus text exposition (in-process counters) |
