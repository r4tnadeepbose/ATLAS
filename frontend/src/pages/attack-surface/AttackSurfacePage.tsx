import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Crosshair, Play, ShieldCheck, Square, Terminal } from "lucide-react";
import { scanApi } from "@/api/endpoints";
import { useListQuery } from "@/hooks/useListQuery";
import { useAuth } from "@/context/AuthContext";
import { PageHeader, StatCard } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Modal, Pagination, ProgressBar, SearchInput, Select, StatusBadge, Textarea, useToast } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/table";
import { formatDateTime, formatNumber, humanizeAdapterStatus, relativeTime, titleCase } from "@/utils";
import type { ScanJob } from "@/types";

const SCAN_TYPES = [
  ["full_recon", "Full recon pipeline"],
  ["subdomain_enumeration", "Subdomain enumeration"],
  ["http_probe", "HTTP probing"],
  ["port_scan", "Authorized port discovery"],
  ["vulnerability_scan", "Template assessment"],
];

export function AttackSurfacePage() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const { can } = useAuth();
  const [createOpen, setCreateOpen] = useState(false);
  const [detailId, setDetailId] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", scan_type: "full_recon", target: "", domains: "", authorization_reference: "", options: "" });

  const list = useListQuery<ScanJob>(["scans"], scanApi.list, { initialSort: "created_at" });
  const dashboard = useQuery({ queryKey: ["scans", "dashboard"], queryFn: scanApi.dashboard, refetchInterval: 15000 });
  const tools = useQuery({ queryKey: ["scans", "tools"], queryFn: scanApi.tools });

  const create = useMutation({
    mutationFn: () =>
      scanApi.create({
        name: form.name,
        scan_type: form.scan_type,
        target: form.target,
        scope: { domains: form.domains.split(",").map((value) => value.trim()).filter(Boolean) },
        authorization_reference: form.authorization_reference,
        options: {},
      }),
    onSuccess: (job) => {
      toast.push({ title: "Assessment queued", description: `${job.name} is running in the background.`, tone: "success" });
      setCreateOpen(false);
      setForm({ name: "", scan_type: "full_recon", target: "", domains: "", authorization_reference: "", options: "" });
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (error: Error) => toast.push({ title: "Could not queue scan", description: error.message, tone: "error" }),
  });

  const cancel = useMutation({
    mutationFn: (id: string) => scanApi.cancel(id),
    onSuccess: () => {
      toast.push({ title: "Cancellation requested", tone: "info" });
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (error: Error) => toast.push({ title: "Cancel failed", description: error.message, tone: "error" }),
  });

  const columns: Column<ScanJob>[] = [
    {
      key: "name",
      label: "Assessment",
      render: (job) => (
        <div>
          <p className="text-sm font-medium text-ink">{job.name}</p>
          <p className="mono text-muted">{job.scan_type} · {job.target}</p>
        </div>
      ),
    },
    { key: "status", label: "Status", render: (job) => <StatusBadge status={job.status} /> },
    {
      key: "progress",
      label: "Progress",
      render: (job) => (
        <div className="w-28">
          <div className="mb-1 flex justify-between text-[9px] text-muted"><span>{job.current_step || titleCase(job.status)}</span><span>{job.progress}%</span></div>
          <ProgressBar value={job.progress} tone={job.status === "failed" ? "bg-critical" : job.status === "completed" ? "bg-accent" : "bg-cyan"} />
        </div>
      ),
    },
    { key: "findings_count", label: "Findings", align: "right", render: (job) => <span className="tabular-nums">{job.findings_count}</span> },
    { key: "created_at", label: "Queued", sortable: true, render: (job) => <span className="text-2xs text-muted">{relativeTime(job.created_at)}</span> },
    { key: "finished_at", label: "Finished", render: (job) => <span className="text-2xs text-muted">{job.finished_at ? relativeTime(job.finished_at) : "—"}</span> },
    {
      key: "actions",
      label: "",
      align: "right",
      render: (job) => (
        <div className="flex justify-end gap-1">
          <Button variant="ghost" size="sm" onClick={(event) => { event.stopPropagation(); setDetailId(job.id); }}>Detail</Button>
          {["queued", "running"].includes(job.status) && can("scans:run") ? (
            <Button variant="danger" size="icon" onClick={(event) => { event.stopPropagation(); cancel.mutate(job.id); }} aria-label="Cancel scan"><Square className="h-3 w-3" /></Button>
          ) : null}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Intelligence"
        title="Attack Surface Management"
        description="Authorized discovery, scope validation and change monitoring. Scans never run without explicit authorization."
        actions={can("scans:run") ? <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}><Play className="h-3.5 w-3.5" /> New assessment</Button> : undefined}
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Active scans" value={formatNumber(dashboard.data?.active)} icon={<Crosshair className="h-4 w-4" />} tone="cyan" hint="Queued or running" />
        <StatCard label="Completed" value={formatNumber((dashboard.data?.by_status ?? []).find((item: any) => item.name === "completed")?.value ?? 0)} hint="Historical assessments" />
        <StatCard label="Tools available" value={`${(tools.data?.items ?? []).filter((tool: any) => tool.available || tool.status === "configured").length}/${(tools.data?.items ?? []).length}`} icon={<Terminal className="h-4 w-4" />} hint="Adapters installed" />
        <StatCard label="Authorization" value="Required" icon={<ShieldCheck className="h-4 w-4" />} tone="accent" hint="Reference stored per scan" />
      </div>

      <Card>
        <CardHeader title="Assessment history" description="Every scan is scoped, authorized and auditable" />
        <DataTable
          columns={columns}
          rows={list.rows}
          rowKey={(job) => job.id}
          loading={list.isLoading}
          error={list.error}
          onRetry={() => list.refetch()}
          sortBy={list.sortBy}
          sortDir={list.sortDir}
          onSort={list.onSort}
          onRowClick={(job) => setDetailId(job.id)}
          toolbar={<SearchInput value={list.q} onChange={list.setQ} placeholder="Search assessments…" className="w-64" />}
          footer={list.pagination ? <Pagination page={list.page} pages={list.pagination.pages} total={list.pagination.total} pageSize={list.pageSize} onPage={list.setPage} onPageSize={list.setPageSize} /> : null}
          emptyTitle="No assessments yet"
          emptyDescription="Register an authorized domain and run a scoped assessment."
          emptyAction={can("scans:run") ? <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}>New assessment</Button> : undefined}
        />
      </Card>

      <Card>
        <CardHeader title="Scanner adapters" description="Availability is detected at runtime; unavailable tools never produce fabricated results" />
        <div className="grid gap-2 p-3 md:grid-cols-2 xl:grid-cols-4">
          {(tools.data?.items ?? []).map((tool: any) => (
            <div key={tool.key} className="rounded border border-border bg-base/40 p-2.5">
              <div className="flex items-center justify-between gap-2">
                <p className="text-xs font-medium text-ink">{tool.key}</p>
                <Badge tone={tool.available ? "border-accent/35 bg-accent/10 text-accent" : "border-border-strong bg-raised text-muted"}>
                  {humanizeAdapterStatus(tool.available ? "available" : "unavailable")}
                </Badge>
              </div>
              <p className="mt-1 truncate text-[10px] text-muted">{titleCase(tool.category)} · {tool.version || "not installed"}</p>
            </div>
          ))}
        </div>
      </Card>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="New authorized assessment"
        description="Scope must explicitly cover the target. Active scans require an authorization reference."
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button variant="primary" loading={create.isPending} disabled={!form.name || !form.target || !form.domains || !form.authorization_reference} onClick={() => create.mutate()}>Queue assessment</Button>
          </>
        }
      >
        <div className="space-y-3">
          <Field label="Assessment name"><Input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Q4 external surface review" /></Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Scan type">
              <Select value={form.scan_type} onChange={(event) => setForm({ ...form, scan_type: event.target.value })}>
                {SCAN_TYPES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
              </Select>
            </Field>
            <Field label="Authorization reference"><Input value={form.authorization_reference} onChange={(event) => setForm({ ...form, authorization_reference: event.target.value })} placeholder="AUTH-2026-014" /></Field>
          </div>
          <Field label="Target" hint="Domain, hostname or URL inside the authorized scope.">
            <Input value={form.target} onChange={(event) => setForm({ ...form, target: event.target.value })} placeholder="company.example" />
          </Field>
          <Field label="Authorized scope" hint="Comma-separated domains. CIDR scope is supported via the API.">
            <Input value={form.domains} onChange={(event) => setForm({ ...form, domains: event.target.value })} placeholder="company.example, api.company.example" />
          </Field>
          <div className="rounded border border-medium/30 bg-medium/5 px-3 py-2 text-2xs text-medium">
            Only assets you are explicitly authorized to assess. ATLAS validates every target and records the authorization reference.
          </div>
        </div>
      </Modal>

      <ScanDetailModal id={detailId} onClose={() => setDetailId(null)} />
    </div>
  );
}

function ScanDetailModal({ id, onClose }: { id: string | null; onClose: () => void }) {
  const scan = useQuery({ queryKey: ["scans", id], queryFn: () => scanApi.get(id!), enabled: Boolean(id), refetchInterval: (query) => (["queued", "running"].includes((query.state.data as any)?.status) ? 3000 : false) });
  const data = scan.data;
  return (
    <Modal open={Boolean(id)} onClose={onClose} title={data?.name || "Assessment detail"} description={data ? `${data.scan_type} · ${data.target}` : ""} size="lg" footer={<Button variant="ghost" onClick={onClose}>Close</Button>}>
      {scan.isLoading ? <p className="text-xs text-muted">Loading…</p> : data ? (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={data.status} />
            <Badge>{data.progress}%</Badge>
            <Badge>{data.findings_count} findings</Badge>
            {data.authorization_reference ? <Badge tone="border-accent/30 bg-accent/10 text-accent">AUTH {data.authorization_reference}</Badge> : null}
          </div>
          <ProgressBar value={data.progress} tone={data.status === "failed" ? "bg-critical" : "bg-cyan"} />
          {data.error_message ? <p className="rounded border border-critical/30 bg-critical/10 px-2.5 py-2 text-2xs text-critical">{data.error_message}</p> : null}
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div><p className="label">Started</p><p className="mt-0.5 text-ink">{formatDateTime(data.started_at)}</p></div>
            <div><p className="label">Finished</p><p className="mt-0.5 text-ink">{formatDateTime(data.finished_at)}</p></div>
            <div><p className="label">Scope</p><p className="mono mt-0.5 break-all text-muted">{JSON.stringify(data.scope)}</p></div>
            <div><p className="label">Current step</p><p className="mt-0.5 text-ink">{data.current_step || "—"}</p></div>
          </div>
          <div>
            <p className="label mb-1">Execution log</p>
            <div className="max-h-52 overflow-y-auto rounded border border-border bg-base/60 p-2">
              {(data.logs ?? []).length === 0 ? <p className="text-2xs text-muted">No log entries yet.</p> : data.logs!.map((log) => (
                <p key={log.id} className={`mono text-[10px] ${log.level === "error" ? "text-critical" : "text-muted"}`}>
                  {formatDateTime(log.created_at)} · {log.message}
                </p>
              ))}
            </div>
          </div>
          <div>
            <p className="label mb-1">Result artefacts</p>
            {(data.results ?? []).length === 0 ? <p className="text-2xs text-muted">No result artefacts recorded.</p> : (
              <div className="space-y-1">
                {data.results!.map((result) => (
                  <div key={result.id} className="flex items-center justify-between rounded border border-border bg-base/40 px-2 py-1.5 text-2xs">
                    <span className="text-ink">{result.tool} · {result.result_type}</span>
                    <span className="text-muted">{Object.keys(result.payload || {}).length} fields</span>
                  </div>
                ))}
              </div>
            )}
          </div>
          {!["queued", "running"].includes(data.status) && data.findings_count === 0 && data.status === "completed" ? (
            <p className="text-2xs text-muted">No findings were generated by this assessment.</p>
          ) : null}
        </div>
      ) : <EmptyState title="Assessment not found" />}
    </Modal>
  );
}
