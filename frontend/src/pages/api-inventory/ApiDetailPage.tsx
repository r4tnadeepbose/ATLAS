import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowLeft, Download, RefreshCw, ShieldAlert } from "lucide-react";
import { apiInventoryApi } from "@/api/endpoints";
import { useAuth } from "@/context/AuthContext";
import { PageHeader } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, EmptyState, SeverityBadge, StatusBadge, useToast } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/table";
import { formatDateTime, relativeTime, titleCase } from "@/utils";
import type { ApiEndpoint, ApiSecurityFinding } from "@/types";

export function ApiDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { can } = useAuth();
  const api = useQuery({ queryKey: ["apis", id], queryFn: () => apiInventoryApi.get(id) });
  const checks = useMutation({
    mutationFn: () => apiInventoryApi.rerunChecks(id),
    onSuccess: (result) => {
      toast.push({ title: "Security checks complete", description: `${result.new_findings} issues detected.`, tone: "success" });
      api.refetch();
    },
    onError: (error: Error) => toast.push({ title: "Checks failed", description: error.message, tone: "error" }),
  });

  if (api.isLoading) return <div className="panel mt-4 h-72 animate-pulse" />;
  if (api.isError) return <div className="panel mt-4 p-6 text-sm text-critical">{(api.error as Error).message}</div>;
  const data = api.data!;
  const issues = (Array.isArray(data.security_findings) ? data.security_findings : (data as any).security_findings) || [];

  const endpointColumns: Column<ApiEndpoint>[] = [
    { key: "method", label: "Method", render: (endpoint) => <Badge tone={endpoint.method === "GET" ? "border-cyan/30 bg-cyan/10 text-cyan" : endpoint.method === "DELETE" ? "border-critical/30 bg-critical/10 text-critical" : undefined}>{endpoint.method}</Badge> },
    { key: "path", label: "Path", render: (endpoint) => <span className="mono">{endpoint.path}</span> },
    { key: "summary", label: "Summary", render: (endpoint) => <span className="text-2xs text-muted">{endpoint.summary || "—"}</span> },
    { key: "auth_required", label: "Auth", render: (endpoint) => endpoint.auth_required === false ? <Badge tone="border-critical/30 bg-critical/10 text-critical">none</Badge> : <Badge tone="border-accent/30 bg-accent/10 text-accent">required</Badge> },
    { key: "data_sensitivity", label: "Data", render: (endpoint) => <Badge>{endpoint.data_sensitivity}</Badge> },
    { key: "deprecated", label: "Deprecated", render: (endpoint) => endpoint.deprecated ? <Badge tone="border-medium/30 bg-medium/10 text-medium">deprecated</Badge> : <span className="text-muted">—</span> },
  ];

  const issueColumns: Column<ApiSecurityFinding>[] = [
    { key: "check_key", label: "Check", render: (issue) => <span className="mono text-xs">{issue.check_key}</span> },
    { key: "severity", label: "Severity", render: (issue) => <SeverityBadge severity={issue.severity} /> },
    { key: "description", label: "Description", render: (issue) => <span className="text-2xs text-muted">{issue.description}</span> },
    { key: "confidence", label: "Confidence", align: "right", render: (issue) => <span className="tabular-nums">{Math.round(issue.confidence * 100)}%</span> },
    { key: "status", label: "Status", render: (issue) => <StatusBadge status={issue.status} /> },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="API Inventory"
        title={data.name}
        description={`${data.api_ref} · ${data.base_url || "no base URL"} · ${data.version || "unversioned"}`}
        actions={
          <>
            <Button variant="ghost" size="sm" onClick={() => navigate("/api-inventory")}><ArrowLeft className="h-3.5 w-3.5" /> Back</Button>
            <Button variant="ghost" size="sm" onClick={() => apiInventoryApi.exportCsv(id)}><Download className="h-3.5 w-3.5" /> Export CSV</Button>
            {can("apis:write") ? (
              <Button variant="primary" size="sm" loading={checks.isPending} onClick={() => checks.mutate()}><RefreshCw className="h-3.5 w-3.5" /> Run checks</Button>
            ) : null}
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
        {[
          ["Authentication", <Badge tone={data.auth_type === "none" ? "border-critical/30 bg-critical/10 text-critical" : undefined}>{data.auth_type}</Badge>],
          ["Exposure", <Badge>{data.exposure}</Badge>],
          ["Data sensitivity", <Badge>{data.data_sensitivity}</Badge>],
          ["Endpoints", <span className="text-sm font-semibold text-ink">{data.endpoints?.length ?? 0}</span>],
          ["Security status", <StatusBadge status={data.security_status} />],
          ["Last observed", <span className="text-2xs text-muted">{relativeTime(data.last_observed)}</span>],
        ].map(([label, value], index) => (
          <div key={index} className="panel p-3"><p className="label">{label as string}</p><div className="mt-1.5">{value as any}</div></div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Endpoints" description="Normalized operation inventory" />
          <DataTable columns={endpointColumns} rows={data.endpoints ?? []} rowKey={(endpoint) => endpoint.id} dense emptyTitle="No endpoints imported" />
        </Card>
        <Card>
          <CardHeader title="API metadata" description="Ownership and specification" />
          <div className="space-y-2 p-3.5 text-xs">
            {[
              ["API reference", data.api_ref],
              ["Version", data.version || "—"],
              ["Authorization model", data.authorization_model || "—"],
              ["Content type", data.content_type || "—"],
              ["Status", data.status],
              ["Deprecated", data.deprecated ? "Yes" : "No"],
              ["Description", data.description || "—"],
            ].map(([label, value]) => (
              <div key={label} className="flex items-start justify-between gap-3 border-b border-border/40 pb-1.5 last:border-0">
                <span className="shrink-0 text-muted">{label}</span>
                <span className="text-right text-ink">{String(value)}</span>
              </div>
            ))}
            <div>
              <p className="label mb-1">Specifications</p>
              {(data.specifications ?? []).length === 0 ? <p className="text-muted">None stored</p> : (data.specifications as any[]).map((specification, index) => (
                <div key={index} className="rounded border border-border bg-base/40 px-2 py-1.5">
                  <p className="text-ink">{specification.name}</p>
                  <p className="text-2xs text-muted">{specification.format} · imported {formatDateTime(specification.imported_at)}</p>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>

      <Card>
        <CardHeader title="API security issues" description="Static checks against the specification and inventory metadata" action={<ShieldAlert className="h-4 w-4 text-muted" />} />
        {issues.length === 0 ? <EmptyState title="No open API issues" description="Run the checks after updating the specification or ownership metadata." /> : (
          <DataTable columns={issueColumns} rows={issues as ApiSecurityFinding[]} rowKey={(issue) => issue.id} dense />
        )}
      </Card>
    </div>
  );
}
