# ATLAS test assets

The executable backend suite lives in [`backend/tests`](../backend/tests) and runs
against an isolated SQLite database:

```bash
cd backend
./.venv/Scripts/python.exe -m pytest tests -q   # Windows
./.venv/bin/python -m pytest tests -q           # Linux/macOS
```

Coverage:

- `test_auth_rbac.py` — bootstrap, login, logout revocation, role enforcement,
  tenant-scoped 404s.
- `test_sbom_parsers.py` — CycloneDX JSON/XML, SPDX JSON/tag-value, invalid input.
- `test_risk_and_matching.py` — version comparison, affected ranges, deterministic
  scoring bands.
- `test_api_workflows.py` — SBOM upload and offline correlation, API specification
  checks, redaction, scan scope enforcement, PDF generation.

`e2e/` and `performance/` in this directory hold supplementary assets:

- `e2e/smoke.md` — browser smoke checklist for release verification.
- `performance/k6-load.js` — read-path load profile (k6).

Frontend verification:

```bash
cd frontend
npm run build     # tsc --noEmit + vite build
```
