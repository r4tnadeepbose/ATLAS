import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileUp, GitBranch, ShieldAlert } from "lucide-react";
import { apiInventoryApi, serviceApi } from "@/api/endpoints";
import { useListQuery } from "@/hooks/useListQuery";
import { useAuth } from "@/context/AuthContext";
import { PageHeader, StatCard } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, Field, Input, Modal, Pagination, SearchInput, Select, StatusBadge, useToast } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/table";
import { HorizontalBars } from "@/components/charts";
import { formatNumber, humanize, relativeTime, titleCase } from "@/utils";
import type { ApiRecord } from "@/types";

const CHECK_LABELS: Record<string, string> = {
  missing_authentication: "Missing auth",
  weak_authorization: "Weak authorization",
  insecure_transport: "Insecure transport",
  deprecated_api_version: "Deprecated version",
  exposed_api_documentation: "Exposed API docs",
  sensitive_endpoint_review: "Sensitive endpoints",
};

export function ApiInventoryPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const queryClient = useQueryClient();
  const { can } = useAuth();
  const fileRef = useRef<HTMLInputElement>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState("");
  const [serviceId, setServiceId] = useState("");
  const [exposure, setExposure] = useState("");
  const [authType, setAuthType] = useState("");

  const list = useListQuery<ApiRecord>(["apis"], apiInventoryApi.list, { initialSort: "created_at", filters: { exposure: exposure || undefined, auth_type: authType || undefined } });
  const dashboard = useQuery({ queryKey: ["apis", "dashboard"], queryFn: apiInventoryApi.dashboard });
  const services = useQuery({ queryKey: ["microservices", "options"], queryFn: () => serviceApi.list({ page_size: 200 }) });

  const importSpec = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error("Choose an OpenAPI or Swagger document");
      const form = new FormData();
      form.append("file", file);
      if (name) form.append("name", name);
      if (serviceId) form.append("service_id", serviceId);
      return apiInventoryApi.importSpec(form);
    },
    onSuccess: (api) => {
      toast.push({ title: "API imported", description: `${api.endpoints_imported} endpoints registered.`, tone: "success" });
      setImportOpen(false);
      setFile(null);
      setName("");
      queryClient.invalidateQueries({ queryKey: ["apis"] });
      navigate(`/api-inventory/${api.id}`);
    },
    onError: (error: Error) => toast.push({ title: "Import failed", description: error.message, tone: "error" }),
  });

  const columns: Column<ApiRecord>[] = [
    {
      key: "name",
      label: "API",
      render: (api) => (
        <div>
          <p className="text-sm font-medium text-ink">{api.name}</p>
          <p className="mono text-muted">{api.api_ref} · {api.base_url || "no base URL"}</p>
        </div>
      ),
    },
    { key: "version", label: "Version", render: (api) => api.version || "—" },
    { key: "auth_type", label: "Authentication", render: (api) => <Badge tone={api.auth_type === "none" ? "border-critical/30 bg-critical/10 text-critical" : undefined}>{api.auth_type}</Badge> },
    { key: "exposure", label: "Exposure", render: (api) => <Badge>{api.exposure}</Badge> },
    { key: "endpoint_count", label: "Endpoints", align: "right", render: (api) => <span className="tabular-nums">{api.endpoint_count ?? 0}</span> },
    { key: "security_findings", label: "Issues", align: "right", render: (api) => { const count = typeof api.security_findings === "number" ? api.security_findings : 0; return <span className={`tabular-nums font-semibold ${count ? "text-high" : "text-muted"}`}>{count}</span>; } },
    { key: "security_status", label: "Review", render: (api) => <StatusBadge status={api.security_status} /> },
    { key: "last_observed", label: "Observed", render: (api) => <span className="text-2xs text-muted">{relativeTime(api.last_observed)}</span> },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Intelligence"
        title="API Inventory"
        description="Central visibility into every API across the microservice estate, with authorization and exposure checks."
        actions={can("apis:write") ? <Button variant="primary" size="sm" onClick={() => setImportOpen(true)}><FileUp className="h-3.5 w-3.5" /> Import specification</Button> : undefined}
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 xl:grid-cols-5">
        <StatCard label="Total APIs" value={formatNumber(dashboard.data?.total)} icon={<GitBranch className="h-4 w-4" />} hint={`${dashboard.data?.endpoints ?? 0} endpoints`} />
        <StatCard label="Public" value={formatNumber(dashboard.data?.public)} tone="high" hint="Internet-facing" />
        <StatCard label="Unauthenticated" value={formatNumber(dashboard.data?.unauthenticated)} tone="critical" hint="No auth scheme" />
        <StatCard label="Sensitive" value={formatNumber(dashboard.data?.sensitive)} tone="medium" hint="High / PII data" />
        <StatCard label="Needs review" value={formatNumber(dashboard.data?.needs_review)} icon={<ShieldAlert className="h-4 w-4" />} hint={`${dashboard.data?.deprecated ?? 0} deprecated`} />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-4">
        <Card className="xl:col-span-3">
          <CardHeader title="API inventory" description="Imported specifications and registered services" />
          <DataTable
            columns={columns}
            rows={list.rows}
            rowKey={(api) => api.id}
            loading={list.isLoading}
            error={list.error}
            onRetry={() => list.refetch()}
            onRowClick={(api) => navigate(`/api-inventory/${api.id}`)}
            toolbar={
              <>
                <SearchInput value={list.q} onChange={list.setQ} placeholder="Search APIs…" className="w-56" />
                <Select value={exposure} onChange={(event) => setExposure(event.target.value)} className="h-8 w-[130px] text-xs">
                  <option value="">All exposure</option>
                  {["public", "partner", "internal"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
                </Select>
                <Select value={authType} onChange={(event) => setAuthType(event.target.value)} className="h-8 w-[140px] text-xs">
                  <option value="">All auth types</option>
                  {["oauth2", "bearer", "api_key", "none", "unknown"].map((value) => <option key={value} value={value}>{value}</option>)}
                </Select>
              </>
            }
            footer={list.pagination ? <Pagination page={list.page} pages={list.pagination.pages} total={list.pagination.total} pageSize={list.pageSize} onPage={list.setPage} onPageSize={list.setPageSize} /> : null}
            emptyTitle="No APIs registered"
            emptyDescription="Import an OpenAPI or Swagger specification to build the inventory."
            emptyAction={can("apis:write") ? <Button variant="primary" size="sm" onClick={() => setImportOpen(true)}>Import specification</Button> : undefined}
          />
        </Card>
        <div className="space-y-4">
          <Card>
            <CardHeader title="Open API issues" description="Static specification checks" />
            <div className="p-3"><HorizontalBars data={[...(dashboard.data?.checks ?? [])].sort((a: any, b: any) => b.value - a.value).map((item: any) => ({ ...item, name: CHECK_LABELS[item.name] || humanize(item.name) }))} dataKey="value" labelKey="name" color="rgb(var(--atlas-high))" height={180} /></div>
          </Card>
          <Card>
            <CardHeader title="Authentication schemes" description="Inventory distribution" />
            <div className="p-3"><HorizontalBars data={(dashboard.data?.by_auth ?? []).map((item: any) => ({ ...item, name: humanize(item.name) }))} dataKey="value" labelKey="name" color="rgb(var(--atlas-accent))" height={140} /></div>
          </Card>
        </div>
      </div>

      <Modal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        title="Import API specification"
        description="OpenAPI 3.x or Swagger 2.0, JSON or YAML. Security checks run automatically."
        footer={<><Button variant="ghost" onClick={() => setImportOpen(false)}>Cancel</Button><Button variant="primary" loading={importSpec.isPending} disabled={!file} onClick={() => importSpec.mutate()}>Import</Button></>}
      >
        <div className="space-y-3">
          <div onClick={() => fileRef.current?.click()} className="flex cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed border-border-strong bg-base/40 px-4 py-7 text-center hover:border-accent/40">
            <FileUp className="mb-2 h-5 w-5 text-muted" />
            <p className="text-sm text-ink">{file ? file.name : "Select OpenAPI / Swagger file"}</p>
            <p className="text-2xs text-muted">JSON or YAML · maximum 5 MB</p>
            <input ref={fileRef} type="file" className="hidden" accept=".json,.yaml,.yml" onChange={(event) => setFile(event.target.files?.[0] ?? null)} />
          </div>
          <Field label="API name (optional)"><Input value={name} onChange={(event) => setName(event.target.value)} placeholder="Defaults to specification title" /></Field>
          <Field label="Owning microservice">
            <Select value={serviceId} onChange={(event) => setServiceId(event.target.value)}>
              <option value="">Unlinked</option>
              {(services.data?.items ?? []).map((service) => <option key={service.id} value={service.id}>{service.name}</option>)}
            </Select>
          </Field>
        </div>
      </Modal>
    </div>
  );
}
