import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowLeft, Download, RefreshCw, ShieldAlert } from "lucide-react";
import { sbomApi } from "@/api/endpoints";
import { useAuth } from "@/context/AuthContext";
import { PageHeader } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, Pagination, SearchInput, SeverityBadge, StatusBadge, Tabs, useToast } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/table";
import { formatDateTime, formatNumber, formatPercent, relativeTime } from "@/utils";
import type { SbomComponent, Vulnerability } from "@/types";

export function SbomDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { can } = useAuth();
  const [tab, setTab] = useState("components");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [q, setQ] = useState("");
  const [vulnerableOnly, setVulnerableOnly] = useState(false);

  const document = useQuery({
    queryKey: ["sbom", id],
    queryFn: () => sbomApi.get(id),
    refetchInterval: (query) => {
      const status = (query.state.data as any)?.status;
      return ["queued", "analyzing"].includes(status) ? 3000 : false;
    },
  });
  const components = useQuery({
    queryKey: ["sbom", id, "components", page, pageSize, q, vulnerableOnly],
    queryFn: () => sbomApi.components(id, { page, page_size: pageSize, q: q || undefined, vulnerable_only: vulnerableOnly }),
    enabled: tab === "components",
  });
  const vulnerabilities = useQuery({ queryKey: ["sbom", id, "vulnerabilities"], queryFn: () => sbomApi.vulnerabilities(id), enabled: tab === "vulnerabilities" });
  const analyze = useMutation({
    mutationFn: () => sbomApi.analyze(id, true),
    onSuccess: () => {
      toast.push({ title: "Correlation queued", description: "ATLAS is matching components against vulnerability intelligence.", tone: "success" });
      document.refetch();
    },
    onError: (error: Error) => toast.push({ title: "Analysis request failed", description: error.message, tone: "error" }),
  });

  if (document.isLoading) return <div className="panel mt-4 h-72 animate-pulse" />;
  if (document.isError) return <div className="panel mt-4 p-6 text-sm text-critical">{(document.error as Error).message}</div>;
  const data = document.data!;

  const componentColumns: Column<SbomComponent>[] = [
    {
      key: "name",
      label: "Component",
      render: (component) => (
        <div>
          <p className="text-sm text-ink">{component.name}</p>
          <p className="mono text-muted">{component.purl || component.supplier || "no purl"}</p>
        </div>
      ),
    },
    { key: "version", label: "Version", render: (component) => <span className="mono">{component.version || "—"}</span> },
    { key: "ecosystem", label: "Ecosystem", render: (component) => <Badge>{component.ecosystem || "unknown"}</Badge> },
    { key: "license", label: "License", render: (component) => <span className="text-2xs text-muted">{component.license || "—"}</span> },
    { key: "type", label: "Type", render: (component) => <span className="text-2xs text-muted">{component.component_type}</span> },
    { key: "vulnerability_count", label: "Vulns", align: "right", render: (component) => <span className={`font-semibold tabular-nums ${component.vulnerability_count ? "text-critical" : "text-muted"}`}>{component.vulnerability_count}</span> },
    { key: "highest_severity", label: "Highest", render: (component) => component.highest_severity ? <SeverityBadge severity={component.highest_severity} /> : <span className="text-muted">—</span> },
  ];

  const vulnColumns: Column<Vulnerability>[] = [
    {
      key: "identifier",
      label: "Vulnerability",
      render: (vulnerability) => (
        <div>
          <p className="text-sm font-medium text-ink">{vulnerability.cve_id || vulnerability.identifier}</p>
          <p className="max-w-[380px] truncate text-2xs text-muted">{vulnerability.title}</p>
        </div>
      ),
    },
    { key: "severity", label: "Severity", render: (vulnerability) => <SeverityBadge severity={vulnerability.severity} /> },
    { key: "cvss", label: "CVSS", align: "right", render: (vulnerability) => <span className="tabular-nums">{vulnerability.cvss_score?.toFixed(1) ?? "—"}</span> },
    { key: "component", label: "Component", render: (vulnerability) => <span className="mono">{vulnerability.component} {vulnerability.component_version}</span> },
    { key: "fixed_version", label: "Fixed", render: (vulnerability) => <span className="mono text-accent">{vulnerability.fixed_version || vulnerability.fixed_versions?.[0] || "—"}</span> },
    { key: "known_exploited", label: "KEV", render: (vulnerability) => vulnerability.known_exploited ? <Badge tone="border-critical/30 bg-critical/10 text-critical">known</Badge> : <span className="text-muted">—</span> },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="SBOM Intelligence"
        title={data.name}
        description={`${data.format} ${data.spec_version || ""} · ${formatNumber(data.component_count)} components · uploaded ${relativeTime(data.created_at)}`}
        actions={
          <>
            <Button variant="ghost" size="sm" onClick={() => navigate("/sbom")}><ArrowLeft className="h-3.5 w-3.5" /> Back</Button>
            <Button variant="ghost" size="sm" onClick={() => sbomApi.exportCsv(id)}><Download className="h-3.5 w-3.5" /> Export CSV</Button>
            {can("sbom:analyze") ? (
              <Button variant="primary" size="sm" loading={analyze.isPending} onClick={() => analyze.mutate()}><RefreshCw className="h-3.5 w-3.5" /> Re-analyze</Button>
            ) : null}
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {[
          ["Components", formatNumber(data.component_count)],
          ["Matched vulnerabilities", formatNumber(data.vulnerability_count)],
          ["Format", data.format],
          ["Status", data.status],
        ].map(([label, value]) => (
          <div key={String(label)} className="panel p-3">
            <p className="label">{label}</p>
            <p className="mt-1 text-lg font-semibold text-ink">{String(value)}</p>
          </div>
        ))}
      </div>

      <Card>
        <CardHeader
          title="Document"
          description="Parsed metadata and scan history"
          action={<StatusBadge status={data.status} />}
        />
        <div className="grid grid-cols-2 gap-3 p-4 md:grid-cols-4">
          <div><p className="label">File</p><p className="mt-0.5 truncate text-sm text-ink">{data.file_name || "—"}</p></div>
          <div><p className="label">Service</p><p className="mt-0.5 text-sm text-ink">{data.microservice_name || "Unlinked"}</p></div>
          <div><p className="label">Version label</p><p className="mt-0.5 text-sm text-ink">{data.version_label || "—"}</p></div>
          <div><p className="label">Analyzed</p><p className="mt-0.5 text-sm text-ink">{formatDateTime(data.analyzed_at)}</p></div>
          <div className="md:col-span-4"><p className="label">Checksum (SHA-256)</p><p className="mono mt-0.5 truncate text-muted">{data.checksum}</p></div>
          {data.error_message ? <div className="md:col-span-4 rounded border border-critical/30 bg-critical/10 px-2 py-1.5 text-2xs text-critical">{data.error_message}</div> : null}
        </div>
        {(data.scan_history ?? []).length ? (
          <div className="border-t border-border/60 px-4 py-2.5">
            <p className="label mb-1">Recent scans</p>
            <div className="space-y-1">
              {data.scan_history!.slice(0, 4).map((entry) => (
                <div key={entry.id} className="flex items-center justify-between text-2xs text-muted">
                  <span>{entry.status} · {entry.components_processed} components · {entry.findings_count} findings</span>
                  <span>{relativeTime(entry.completed_at || entry.started_at)}</span>
                </div>
              ))}
            </div>
          </div>
        ) : null}
      </Card>

      <Tabs
        tabs={[
          { key: "components", label: "Components", count: data.component_count },
          { key: "vulnerabilities", label: "Vulnerabilities", count: data.vulnerability_count },
        ]}
        value={tab}
        onChange={setTab}
      />

      {tab === "components" ? (
        <Card>
          <DataTable
            columns={componentColumns}
            rows={components.data?.items ?? []}
            rowKey={(component) => component.id}
            loading={components.isLoading}
            error={components.error}
            onRetry={() => components.refetch()}
            toolbar={
              <>
                <SearchInput value={q} onChange={(value) => { setQ(value); setPage(1); }} placeholder="Search components…" className="w-64" />
                <label className="flex items-center gap-1.5 text-2xs text-muted">
                  <input type="checkbox" checked={vulnerableOnly} onChange={(event) => { setVulnerableOnly(event.target.checked); setPage(1); }} className="accent-accent" /> Vulnerable only
                </label>
              </>
            }
            footer={components.data?.pagination ? <Pagination page={page} pages={components.data.pagination.pages} total={components.data.pagination.total} pageSize={pageSize} onPage={setPage} onPageSize={setPageSize} /> : null}
            emptyTitle="No components match"
          />
        </Card>
      ) : (
        <Card>
          <DataTable
            columns={vulnColumns}
            rows={vulnerabilities.data?.items ?? []}
            rowKey={(vulnerability) => vulnerability.id}
            loading={vulnerabilities.isLoading}
            error={vulnerabilities.error}
            onRetry={() => vulnerabilities.refetch()}
            emptyTitle="No vulnerabilities matched"
            emptyDescription="Re-run correlation to query the latest OSV intelligence."
          />
          {(vulnerabilities.data?.items ?? []).length ? (
            <div className="flex items-center gap-2 border-t border-border/60 px-4 py-2 text-2xs text-muted">
              <ShieldAlert className="h-3.5 w-3.5" /> Findings are generated for linked services. Open Vulnerability Management to triage.
              <Button variant="ghost" size="sm" className="ml-auto" onClick={() => navigate("/vulnerabilities")}>Open findings</Button>
            </div>
          ) : null}
        </Card>
      )}
    </div>
  );
}
