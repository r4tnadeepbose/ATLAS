# How ATLAS Works

## What it is

ATLAS (**A**dvanced **T**hreat & **A**sset **L**ifecycle **S**ecurity) is a
security control room for companies that run many small services
(microservices) instead of one large application.

It collects security information from different places, cleans it up, connects
the pieces, and shows one clear picture: what we own, what is exposed, what is
vulnerable, how risky it is, who must fix it, and whether it is getting better.

---

## The problem it solves

In a large system, security data is scattered:

- a scanner knows about a vulnerable package,
- an inventory spreadsheet knows which team owns the service,
- a web scan knows the service is reachable from the internet,
- an API document knows the endpoint has no authentication,
- a secret scan knows a credential is exposed,
- and management asks, “How risky are we right now?”

Each tool answers a small question. Nobody answers the important question:

> **Which parts of our business are exposed, how badly, and what should we fix first?**

ATLAS connects those dots. A vulnerable library is no longer just a CVE row; it
becomes a prioritized finding on a named service, owned by a named team, with a
risk score, a deadline, and an audit trail.

---

## What it is not

- It is **not** a replacement for scanners. It orchestrates them.
- It does **not** guarantee discovery of unknown (zero-day) attacks.
- It does **not** let AI change findings or fix systems on its own.
- It only scans assets you explicitly authorize.

---

## Main parts in plain language

| Part | Plain-language meaning |
| --- | --- |
| **Assets** | Everything you own that can be attacked: domains, IPs, services, APIs. |
| **Microservices** | The building blocks of the application and how they call each other. |
| **SBOM** | A list of every software package inside a service, like an ingredient list. |
| **Vulnerability intelligence** | Public knowledge about which package versions are unsafe (OSV, NVD). |
| **Findings** | A specific problem that needs action, with severity, evidence and an owner. |
| **Attack surface** | What an outsider can see or reach, discovered only with permission. |
| **API inventory** | A catalogue of APIs, their endpoints, and whether they require login. |
| **Data classification** | Detection of personal data, card numbers, passwords and tokens — stored masked. |
| **AI triage** | Helpful explanation and suggested next step. It is advice, never an action. |
| **Risk engine** | A transparent formula that turns findings into a priority and a deadline. |
| **RBAC** | Different roles see and do different things; the server enforces it. |

---

## Step by step: what happens to one piece of security information

### 1. Collection

ATLAS receives information from:

- an uploaded SBOM (software ingredient list),
- an authorized external scan,
- an imported OpenAPI/Swagger document,
- a pasted configuration or log sample,
- manually registered assets and services,
- vulnerability intelligence feeds.

### 2. Validation and normalization

Everything is converted into one internal shape: consistent asset names, package
identifiers (purl), versions, severities and ownership. Invalid files are
rejected; uploaded content is never executed.

### 3. Analysis

Each input is examined:

- SBOM components are compared with known vulnerable version ranges;
- scan results become assets, services and findings;
- API documents are checked for missing authentication, HTTP, exposed docs and
  sensitive endpoints;
- text samples are checked with patterns and entropy for secrets/PII;
- network exposure and business criticality are recorded.

### 4. Correlation

This is the heart of ATLAS. A finding is attached to:

- the asset it affects,
- the microservice that uses it,
- the business unit and owner,
- the vulnerability record (CVE/OSV),
- internet exposure and data sensitivity.

A package problem becomes a business-risk problem.

### 5. AI-assisted triage (optional)

If an AI provider is configured, ATLAS asks for a technical explanation, business
impact and remediation suggestion. If no provider is configured, a deterministic
heuristic engine produces clearly labelled advice. Either way the result is
marked **advisory only**.

### 6. Risk scoring

A documented formula (`atlas-risk-v1`) combines severity, exposure, asset
criticality, known exploitation, sensitive data, missing authentication, age and
whether a fix exists. The result is a score from 0 to 100, a severity band and an
SLA deadline. AI never sets this score.

### 7. Alerting

Critical and high events create notifications. Rules control which severity is
sent, to which channel (in-app, email, Slack, Teams, webhook), and how duplicates
are suppressed.

### 8. Visualization

The data appears in:

- **Command Center** — overall posture and trends,
- **Microservice Map** — dependency graph and blast radius,
- **Vulnerability Management** — the actionable findings list,
- **Risk Management** — risk register, accepted risks and remediation tasks,
- **Executive Intelligence** — business-level view,
- **Security Reports** — PDF/CSV exports.

### 9. Remediation and verification

A finding is assigned, fixed, documented with evidence and resolved. Re-scanning
or re-analysing confirms the fix. The full history stays in the audit trail.

Then monitoring continues: new intelligence can reopen or create findings at any
time. That is why ATLAS is a lifecycle platform, not a one-time report.

---

## Who uses it

| Role | What they do |
| --- | --- |
| Super Administrator | Runs the platform, users, integrations and settings. |
| Security Administrator | Operates all security modules and scans. |
| SOC Analyst | Watches alerts, investigates and triages findings. |
| VAPT Analyst | Runs authorized assessments and submits evidence. |
| Developer | Sees their services and fixes assigned findings. |
| Executive | Follows posture, business risk and remediation rate. |

---

## Where the data lives

- **Local launcher:** SQLite file at `backend/atlas.db`.
- **Docker/production:** PostgreSQL, with Redis and RabbitMQ for background work.
- SBOM files are parsed and not stored raw; normalized components are kept.
- Detected passwords, keys and tokens are stored **masked**, never in full.
- Uploaded files and scan targets are validated; scanners are never run through a
  shell and only work inside the authorized scope.

---

## End-to-end flow

```
                         ┌─────────────────────────┐
                         │  People using ATLAS     │
                         │  SOC · Developers ·     │
                         │  Executives · Admins    │
                         └────────────┬────────────┘
                                      │ sign in (role + MFA)
                                      ▼
                         ┌─────────────────────────┐
                         │  ATLAS web interface    │
                         └────────────┬────────────┘
                                      │ REST API (JWT)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  ATLAS platform                                                         │
│                                                                         │
│  COLLECT                NORMALIZE              ANALYSE                  │
│  ├ SBOM upload          ├ assets               ├ vulnerable packages    │
│  ├ authorized scans     ├ packages (purl)      ├ exposure / ports       │
│  ├ API specifications   ├ findings             ├ API authentication     │
│  ├ data samples         ├ APIs                 ├ PII / secrets          │
│  └ intelligence feeds   └ services             └ container / network    │
│          │                    │                        │                │
│          └────────────────────┴────────────┬───────────┘                │
│                                            ▼                            │
│                                  CORRELATE                              │
│                       asset + service + owner + CVE                     │
│                       + exposure + business unit                        │
│                                            │                            │
│                    ┌───────────────────────┼───────────────────────┐    │
│                    ▼                       ▼                       ▼    │
│              AI TRIAGE (optional)     RISK ENGINE              ALERTS  │
│              explanation only         score · SLA · band       dedup   │
│                    └───────────────────────┼───────────────────────┘    │
│                                            ▼                            │
│                       DASHBOARD · GRAPH · REGISTER · REPORTS            │
└────────────────────────────────────────────┬────────────────────────────┘
                                             │
                                             ▼
                              ┌──────────────────────────────┐
                              │  ASSIGN  →  FIX  →  VERIFY   │
                              │  evidence + audit history    │
                              └──────────────┬───────────────┘
                                             │
                                             ▼
                              continuous monitoring starts again
```

### One-line summary of the flow

**Collect → Normalize → Analyze → Correlate → Triage → Score → Alert → Visualize → Remediate → Repeat.**

Ready to start it? See [HOW_TO_RUN.md](HOW_TO_RUN.md).
