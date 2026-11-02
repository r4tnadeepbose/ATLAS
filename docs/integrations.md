# ATLAS Integrations

Every external tool is wrapped in an adapter under `backend/app/integrations/`.
Adapters are independent, report availability, enforce safe argument handling and
never fabricate output.

## 1. Security tooling

| Tool | Directory | Capabilities | Invocation |
| --- | --- | --- | --- |
| Syft | `syft` | SBOM generation from images/directories | `syft <target> -o cyclonedx-json -q` |
| Grype | `grype` | Vulnerability scan of image/SBOM/dir | `grype <target> -o json -q` |
| Trivy | `trivy` | Container image/filesystem vulnerabilities + secrets | `trivy image --format json` |
| Subfinder | `subfinder` | Subdomain enumeration | `subfinder -d <domain> -silent` |
| httpx | `httpx` | HTTP probe + technology detection | JSONL probe |
| Nmap | `nmap` | Authorized service discovery | `nmap -Pn -sV --top-ports 100 -oX -` |
| Nuclei | `nuclei` | Template-based assessment | `-jsonl -severity critical,high,medium` |
| ZAP | `zap` | Baseline web/API scan | `zap-cli baseline` |
| Gitleaks | `gitleaks` | Secret detection in source | `detect --report-format json` |

Availability:

```bash
GET /api/v1/scans/tools
```

Returns `available`, `path`, `version` and capabilities per adapter. The UI shows
the same data under Integrations and Scan Management.

## 2. Vulnerability intelligence

| Provider | Directory | Usage |
| --- | --- | --- |
| OSV | `osv` | `querybatch` for SBOM purls; single lookup `/vulnerabilities/lookup/{id}` |
| NVD | `nvd` | Recent CVE feed and CVE lookup; optional API key raises limits |

OSV correlation runs during SBOM analysis. Network failure degrades to offline
matching against previously ingested records; the error is stored in
`sbom_scan_history.details.online_error`. Intelligence is normalized into
`vulnerability_records` with affected ranges and fixed versions.

## 3. AI providers

Configure with `ATLAS_AI_PROVIDER`:

| Value | Endpoint |
| --- | --- |
| `none` | No call; deterministic heuristic triage labelled `heuristic` |
| `openai_compatible` | `POST {base_url}/chat/completions` |
| `openai` | OpenAI default endpoint |
| `anthropic` | `POST {base_url}/v1/messages` |
| `ollama` | `POST {base_url}/api/chat` |

Per-tenant defaults can be stored through `POST /api/v1/triage/config` (provider,
model, base URL, max tokens, temperature). Environment configuration remains the
fallback. Prompt templates are versioned in `ai_prompt_versions`.

Safety: prompts forbid inventing evidence, require JSON output, and results are
stored as advisory only. Provider errors fall back to heuristic analysis and are
recorded in `ai_analysis_history`.

## 4. Notifications

| Channel | State |
| --- | --- |
| In-app | Implemented (synchronous) |
| Email / Slack / Teams / Webhook | Routing, rules, dedup and delivery state implemented; provider delivery plugins pending |

Rules (`POST /api/v1/notifications/rules`) define event key, minimum severity,
channels and dedup window. Events emitted today: vulnerable dependency, new asset,
assessment completed, test. External notifications remain `pending`/`queued` until
a provider adapter is configured; ATLAS never marks them delivered falsely.

## 5. Configuration

Integrations have a row per organization (`integrations` table) with `enabled`,
`status`, `config` and `last_checked_at`. `PATCH /api/v1/integrations/{id}` merges
configuration; secrets are masked on read. `POST /{id}/test` checks the adapter or
provider availability.

## 6. Adding an adapter

1. Create `backend/app/integrations/<tool>/adapter.py`.
2. Subclass `ToolAdapter` with key, binary, category and capabilities.
3. Validate targets with `validate_target`; call `self.run([...])` (never a shell
   string). Return structured data or raise `AdapterUnavailable`/`AdapterError`.
4. Register it in `app/api/v1/admin.py::_available_integrations` and the scan
   runner if it participates in assessments.
5. Add a unit test for argument construction and failure behaviour.
6. Document installation in `docs/deployment.md`.

## 7. Credential handling

Provider keys are supplied via environment variables or integration configuration.
They are never logged and are masked in responses. For production, use a secret
manager and task-role credentials rather than long-lived keys where supported.
