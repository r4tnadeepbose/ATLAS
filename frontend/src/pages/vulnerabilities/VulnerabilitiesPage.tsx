import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Download, ExternalLink, ShieldAlert } from "lucide-react";
import { findingApi } from "@/api/endpoints";
import { useListQuery } from "@/hooks/useListQuery";
import { useAuth } from "@/context/AuthContext";
import { PageHeader, StatCard } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, Pagination, SearchInput, Select, SeverityBadge, StatusBadge } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/table";
import { SeverityLegend, SeverityStackedBars, SeverityDonut, TrendArea } from "@/components/charts";
import { downloadCsv, formatDate, formatNumber, relativeTime, riskTone, titleCase, truncate } from "@/utils";
import type { Finding, Vulnerability } from "@/types";

export function VulnerabilitiesPage() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const [params] = useSearchParams();
  const [tab, setTab] = useState<"findings" | "records">("findings");
  const [severity, setSeverity] = useState(params.get("severity") ?? "");
  const [status, setStatus] = useState(params.get("status") ?? "");
  const [category, setCategory] = useState("");
  const [openOnly, setOpenOnly] = useState(params.get("status") === "open");
  const [recordSeverity, setRecordSeverity] = useState("");

  const list = useListQuery<Finding>(["findings"], findingApi.list, {
    initialSort: "risk_score",
    filters: { severity: severity || undefined, status: status || undefined, category: category || undefined, open_only: openOnly || undefined },
  });
  const summary = useQuery({ queryKey: ["findings", "summary"], queryFn: findingApi.summary });
  const records = useListQuery<Vulnerability>(["vulnerabilities"], findingApi.vulnerabilities, { initialSort: "published_at", filters: { severity: recordSeverity || undefined }, enabled: tab === "records" });

  const columns: Column<Finding>[] = [
    {
      key: "title",
      label: "Finding",
      render: (finding) => (
        <div className="min-w-0 max-w-[420px]">
          <p className="truncate text-sm font-medium text-ink">{finding.title}</p>
          <p className="mono truncate text-muted">{finding.finding_ref} · {finding.cve_id || finding.category.replace("_", " ")}</p>
        </div>
      ),
    },
    { key: "severity", label: "Severity", sortable: true, render: (finding) => <SeverityBadge severity={finding.severity} /> },
    { key: "risk_score", label: "Risk", sortable: true, render: (finding) => <span className={`font-semibold tabular-nums ${riskTone(finding.risk_score)}`}>{formatNumber(finding.risk_score, 0)}</span> },
    { key: "status", label: "Status", sortable: true, render: (finding) => <StatusBadge status={finding.status} /> },
    { key: "microservice_name", label: "Service", render: (finding) => (
      <div className="min-w-0">
        <p className="truncate text-xs text-ink">{finding.microservice_name || finding.asset_name || "—"}</p>
        <p className="truncate text-[10px] text-muted">{finding.business_unit || "unassigned unit"}</p>
      </div>
    ) },
    { key: "exposure", label: "Exposure", render: (finding) => <Badge tone={finding.exposure === "public" ? "border-critical/30 bg-critical/10 text-critical" : undefined}>{finding.exposure}</Badge> },
    { key: "first_seen", label: "First seen", sortable: true, render: (finding) => <span className="whitespace-nowrap text-2xs text-muted">{relativeTime(finding.first_seen)}</span> },
    {
      key: "sla",
      label: "SLA",
      render: (finding) => {
        if (!finding.sla_due_at || ["resolved", "closed"].includes(finding.status)) return <span className="text-muted">—</span>;
        const overdue = new Date(finding.sla_due_at).getTime() < Date.now();
        return <span className={`whitespace-nowrap text-2xs ${overdue ? "text-critical" : "text-muted"}`}>{overdue ? "Overdue " : "Due "}{formatDate(finding.sla_due_at)}</span>;
      },
    },
  ];

  const recordColumns: Column<Vulnerability>[] = [
    {
      key: "identifier",
      label: "Vulnerability",
      render: (vulnerability) => (
        <div className="max-w-[420px]">
          <p className="text-sm font-medium text-ink">{vulnerability.cve_id || vulnerability.identifier}</p>
          <p className="truncate text-2xs text-muted">{vulnerability.title}</p>
        </div>
      ),
    },
    { key: "severity", label: "Severity", render: (vulnerability) => <SeverityBadge severity={vulnerability.severity} /> },
    { key: "cvss", label: "CVSS", align: "right", render: (vulnerability) => <span className="tabular-nums">{vulnerability.cvss_score?.toFixed(1) ?? "—"}</span> },
    { key: "known_exploited", label: "Known exploited", render: (vulnerability) => vulnerability.known_exploited ? <Badge tone="border-critical/30 bg-critical/10 text-critical">KEV</Badge> : <span className="text-muted">—</span> },
    { key: "source", label: "Source", render: (vulnerability) => <Badge>{vulnerability.source}</Badge> },
    { key: "published_at", label: "Published", sortable: true, render: (vulnerability) => <span className="text-2xs text-muted">{formatDate(vulnerability.published_at)}</span> },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Security Operations"
        title="Vulnerability Management"
        description="Correlated findings with contextual risk, SLA tracking and remediation state."
        actions={
          <>
            <Button variant="ghost" size="sm" onClick={() => downloadCsv("atlas-findings.csv", list.rows as unknown as Record<string, unknown>[])}><Download className="h-3.5 w-3.5" /> Export</Button>
            {can("findings:triage") ? (
              <Button variant="primary" size="sm" onClick={() => navigate("/ai-triage")}><ShieldAlert className="h-3.5 w-3.5" /> AI triage queue</Button>
            ) : null}
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Total findings" value={formatNumber(summary.data?.total)} icon={<ShieldAlert className="h-4 w-4" />} hint={`${summary.data?.overdue ?? 0} SLA overdue`} />
        <StatCard label="Critical" value={formatNumber((summary.data?.by_severity ?? []).find((item: any) => item.name === "critical")?.value ?? 0)} tone="critical" hint="Immediate attention" />
        <StatCard label="High" value={formatNumber((summary.data?.by_severity ?? []).find((item: any) => item.name === "high")?.value ?? 0)} tone="high" hint="Prioritised remediation" />
        <StatCard label="Unassigned" value={formatNumber(summary.data?.unassigned)} tone="medium" hint="Open without owner" />
      </div>

      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Severity distribution" description="Current finding mix" />
          <div className="grid grid-cols-2 items-center gap-2 p-3">
            <SeverityDonut data={(summary.data?.by_severity ?? []).map((item: any) => ({ severity: item.name, count: item.value }))} height={180} />
            <SeverityLegend data={(summary.data?.by_severity ?? []).map((item: any) => ({ severity: item.name, count: item.value }))} />
          </div>
        </Card>
        <Card>
          <CardHeader title="By category" description="Finding source class" />
          <div className="p-3">
            {(summary.data?.by_category ?? []).map((item: any) => (
              <button key={item.name} onClick={() => { setCategory(item.name); setTab("findings"); }} className="flex w-full items-center justify-between border-b border-border/40 py-1.5 text-left last:border-0 hover:text-accent">
                <span className="text-2xs capitalize text-muted">{item.name.replace("_", " ")}</span>
                <span className="text-xs tabular-nums text-ink">{item.value}</span>
              </button>
            ))}
          </div>
        </Card>
      </div>

      <div className="flex items-center gap-1 border-b border-border">
        {[{ key: "findings", label: "Findings", count: list.pagination?.total }, { key: "records", label: "Intelligence records", count: records.pagination?.total }].map((item) => (
          <button key={item.key} onClick={() => setTab(item.key as any)} className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === item.key ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink"}`}>
            {item.label} <span className="ml-1 text-2xs text-muted">{item.count ?? ""}</span>
          </button>
        ))}
      </div>

      {tab === "findings" ? (
        <Card>
          <DataTable
            columns={columns}
            rows={list.rows}
            rowKey={(finding) => finding.id}
            loading={list.isLoading}
            error={list.error}
            onRetry={() => list.refetch()}
            sortBy={list.sortBy}
            sortDir={list.sortDir}
            onSort={list.onSort}
            onRowClick={(finding) => navigate(`/vulnerabilities/${finding.id}`)}
            toolbar={
              <>
                <SearchInput value={list.q} onChange={list.setQ} placeholder="Search findings, CVEs, services…" className="w-64" />
                <Select value={severity} onChange={(event) => setSeverity(event.target.value)} className="h-8 w-[130px] text-xs">
                  <option value="">All severities</option>
                  {["critical", "high", "medium", "low", "info"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
                </Select>
                <Select value={status} onChange={(event) => { setStatus(event.target.value); setOpenOnly(false); }} className="h-8 w-[140px] text-xs">
                  <option value="">All statuses</option>
                  {["open", "triaged", "in_progress", "assigned", "resolved", "risk_accepted", "false_positive", "closed"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
                </Select>
                <Select value={category} onChange={(event) => setCategory(event.target.value)} className="h-8 w-[150px] text-xs">
                  <option value="">All categories</option>
                  {["dependency", "attack_surface", "sensitive_data", "api_security", "container", "secrets", "manual"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
                </Select>
                <label className="flex items-center gap-1.5 text-2xs text-muted">
                  <input type="checkbox" checked={openOnly} onChange={(event) => { setOpenOnly(event.target.checked); if (event.target.checked) setStatus(""); }} className="accent-accent" /> Open only
                </label>
              </>
            }
            footer={list.pagination ? <Pagination page={list.page} pages={list.pagination.pages} total={list.pagination.total} pageSize={list.pageSize} onPage={list.setPage} onPageSize={list.setPageSize} /> : null}
            emptyTitle="No findings"
            emptyDescription="Upload an SBOM, run an authorized assessment or analyse data to generate findings."
          />
        </Card>
      ) : (
        <Card>
          <DataTable
            columns={recordColumns}
            rows={records.rows}
            rowKey={(vulnerability) => vulnerability.id}
            loading={records.isLoading}
            error={records.error}
            onRetry={() => records.refetch()}
            sortBy={records.sortBy}
            sortDir={records.sortDir}
            onSort={records.onSort}
            toolbar={
              <>
                <SearchInput value={records.q} onChange={records.setQ} placeholder="Search CVE / OSV identifiers…" className="w-64" />
                <Select value={recordSeverity} onChange={(event) => setRecordSeverity(event.target.value)} className="h-8 w-[130px] text-xs">
                  <option value="">All severities</option>
                  {["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
                </Select>
                <span className="text-2xs text-muted">Records are global vulnerability intelligence, scoped findings are organization-specific.</span>
              </>
            }
            footer={records.pagination ? <Pagination page={records.page} pages={records.pagination.pages} total={records.pagination.total} pageSize={records.pageSize} onPage={records.setPage} onPageSize={records.setPageSize} /> : null}
            emptyTitle="No vulnerability intelligence"
            emptyDescription="Correlate an SBOM with OSV to populate the intelligence store."
          />
        </Card>
      )}
    </div>
  );
}
