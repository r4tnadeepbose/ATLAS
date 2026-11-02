# ATLAS Security Model

ATLAS is a security product and is engineered with the assumption that it will
hold sensitive inventory and vulnerability data. This document describes the
controls implemented in the codebase and the remaining hardening work.

## 1. Authentication

- Email + password login with PBKDF2-HMAC-SHA256, 210,000 iterations, 16-byte
  per-user salt, constant-time comparison.
- JWT access tokens (default 60 min) and refresh tokens (default 7 days) signed
  with HS256 using `ATLAS_SECRET_KEY`. Tokens carry `sub`, `jti`, `iss`, `iat`,
  `exp` and type.
- Every authenticated request checks the server-side `sessions` row: revoking a
  session (logout, admin revocation, refresh rotation) invalidates the token
  immediately, even before expiry.
- Failed logins increment a counter; five failures lock the account for 15
  minutes.
- Optional TOTP MFA (`pyotp`), enrolment and disablement require verification.
  When enabled, login requires a valid code.
- OIDC/Keycloak settings exist for identity-provider integration. **The token
  validation path for external OIDC is not yet wired**; JWT login remains the
  active mechanism.

## 2. Authorization (RBAC)

Permissions are strings such as `assets:write`, `sbom:analyze`, `scans:run`,
`risks:write`, `users:write`, `settings:write`, `audit:read`.
Routes declare required permissions via FastAPI dependencies; the backend
returns `403` before the handler runs. Frontend route guards and hidden controls
are convenience only.

| Role | Summary |
| --- | --- |
| Super Administrator | Full platform, users, organization, integrations, settings |
| Security Administrator | All security modules, scans, findings, risk, reports (no user/org administration) |
| SOC Analyst | Monitoring, investigation, triage, scan execution, risk updates |
| VAPT Analyst | Authorized assessments, finding/evidence management, API inventory, reports |
| Developer | Read scoped inventory/SBOM, update and remediate assigned findings |
| Executive | Dashboard, executive intelligence, risk and reports |

Built-in role definitions live in `app/core/permissions.py::ROLE_PERMISSIONS` and
are synchronized to the permission catalog at startup.

## 3. Tenant isolation

- `organization_id` is present on every tenant-owned table and indexed.
- The authenticated user's organization is the only scope injected into
  queries. No endpoint accepts an arbitrary organization identifier from the
  client.
- Foreign-tenant object IDs return `404`, preventing object enumeration.
- Unique constraints are organization-scoped where relevant (`findings` dedup,
  environment keys, team slugs, settings keys).
- User emails are globally unique to prevent ambiguous identity resolution.

## 4. Scanner safety

- Explicit authorized scope is mandatory (`domains`, `cidrs`, `ips`).
- Targets are validated on submission and again in the runner; HTTP targets are
  parsed to a host before scope checks.
- Active scans require an authorization reference by default.
- Adapters use `subprocess.run([...], shell=False)` with allow-listed characters,
  per-tool timeouts and cancellation checks between stages.
- Missing binaries produce an explicit `AdapterUnavailable`/failed job. No adapter
  synthesizes findings.
- Uploaded files are never executed. XML is parsed with `defusedxml`.
- Scan execution occurs in background tasks/workers, never in a synchronous HTTP
  request.
- Scheduled scans record the scheduler as authorizer and a schedule-scoped
  reference; only administrators can create schedules.

## 5. Data protection

- Detected sensitive values are masked at detection time; the raw value is
  discarded. Responses never contain full credentials.
- Evidence is stored as redacted context with a `redacted` flag.
- Integration secrets are masked in API responses (`********`).
- Logs are structured JSON and exclude tokens, passwords and secret values.
- Security headers are applied globally (`nosniff`, `DENY`, `no-referrer`,
  CSP, cache-control `no-store`).
- CORS is an explicit allow-list; credentials are permitted only for configured
  origins.
- Rate limiting is applied per client/path (in-process implementation; replace
  with Redis-backed limiter for multi-replica API deployments).
- Input validation is enforced with Pydantic; query parameters have bounds.
- SQLAlchemy parameterizes all queries; no raw SQL string interpolation.

## 6. AI guardrails

- AI providers are optional (`none`, OpenAI-compatible, Anthropic, Ollama).
- Without a provider, ATLAS returns deterministic heuristic analysis labelled
  `provider: heuristic`. This is never presented as model output.
- System prompt instructs the model not to invent evidence, CVE details or
  exploitation status, and to lower confidence when context is insufficient.
- Responses must be a JSON object; malformed output triggers provider failure and
  heuristic fallback, recorded in analysis history.
- AI results are advisory (`advisory_only: true`). No code path lets AI change
  finding severity, close findings, execute remediation or modify infrastructure.
- Risk scores are computed by the documented `atlas-risk-v1` model only.
- Token usage, latency and provider outcome are recorded for audit.

## 7. Risk scoring (atlas-risk-v1)

```
base severity      critical +45 · high +32 · medium +18 · low +8 · info +2
CVSS adjustment    max(0, (cvss − 5)) × 1.5
exposure           public +15 · partner +7 · internal 0
asset criticality  critical +12 · high +7 · medium +3
known exploited    +12
exploit available  +6
sensitive data     +6
missing auth       +5
age                +1 per 7 days, capped +8
fix available      −4
```

Clamp to 0–100. Bands: critical ≥85, high ≥65, medium ≥40, low ≥15, else info.
SLA: critical 7 days, high 30, medium 90, low 180.

## 8. Metrics definitions

- **Posture**: `100 − mean(risk_score of open findings)`, bounded 0–100.
- **MTTD**: finding `first_seen` − vulnerability record `created_at` (intelligence
  ingestion time), averaged over linked findings. This measures ingestion →
  finding latency, not zero-day discovery.
- **MTTR**: `resolved_at` − `first_seen`, averaged over resolved findings.

## 9. Audit trail

Recorded actions include authentication, bootstrap, user and role changes,
asset/service/API/SBOM mutations, scan queuing/cancellation, finding status
changes, risk acceptance, settings and integration changes. Entries store actor,
organization, action, resource, outcome, IP/user-agent and non-secret details.

## 10. Known gaps / next hardening

1. OIDC token validation and Keycloak realm provisioning.
2. Redis-backed distributed rate limiting and cache.
3. Sandboxed scanner execution (container per job, seccomp, network policy).
4. Object storage for SBOM artefacts and evidence attachments.
5. Field-level encryption for integration credentials.
6. Email/Slack/Teams/webhook delivery plugins with retry/backoff.
7. External penetration test and load test at 250-service scale.
8. Automated dependency scanning of ATLAS itself in CI.
