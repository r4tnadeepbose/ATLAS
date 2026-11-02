# ATLAS browser smoke checklist

Run against a demo or staging environment with a seeded dataset.

1. **Authentication** — sign in as `admin@atlas.demo`; unread badge appears;
   sign out clears the session; a second login works.
2. **Command Center** — six metric cards populate; charts render; click a metric
   navigates to the matching module; recent activity lists events.
3. **Vulnerability Management** — filter by severity and status; search by CVE;
   open a finding; change status with a note; verify history entry; add a comment;
   run AI triage and confirm the provider label.
4. **Microservices** — relationship map renders nodes/edges; filters update the
   graph; double-click navigates to service detail; inventory search works.
5. **SBOM** — upload a CycloneDX JSON file attached to a service; wait for status
   `analyzed`; verify components and vulnerability tabs; export CSV; compare two
   documents.
6. **Attack Surface** — adapter availability is shown; a target outside scope is
   rejected; a valid scoped assessment queues and reports progress/logs.
7. **API Inventory** — import an OpenAPI document; verify endpoints and at least
   one static check; export CSV.
8. **Data Classification** — analyze a sample containing a fake email and token;
   confirm detections and masked samples.
9. **Risk Management** — recompute; accept a risk with justification; confirm the
   finding becomes `risk_accepted`; complete a remediation task.
10. **Reports** — generate an executive PDF and download it; open the file.
11. **Administration** — create a developer user; sign in as that user and confirm
    `/users` is inaccessible (403) while the Command Center remains available.
12. **Responsive** — verify sidebar collapse and mobile navigation at narrow
    widths.
