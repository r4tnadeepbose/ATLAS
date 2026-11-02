import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Activity, FileClock, Gauge, SlidersHorizontal } from "lucide-react";
import { adminApi } from "@/api/endpoints";
import { useAuth } from "@/context/AuthContext";
import { PageHeader } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Modal, Pagination, SearchInput, StatusBadge, Textarea, useToast } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/table";
import { formatDateTime, relativeTime, titleCase } from "@/utils";

export function SystemPage() {
  const toast = useToast();
  const { can } = useAuth();
  const [tab, setTab] = useState<"settings" | "jobs" | "audit">("settings");
  const [settingOpen, setSettingOpen] = useState(false);
  const [key, setKey] = useState("");
  const [value, setValue] = useState("{}");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [q, setQ] = useState("");

  const settings = useQuery({ queryKey: ["settings"], queryFn: adminApi.settings });
  const jobs = useQuery({ queryKey: ["admin", "jobs", page, pageSize, q], queryFn: () => adminApi.jobs({ page, page_size: pageSize, q: q || undefined }), placeholderData: (previous) => previous });
  const audit = useQuery({ queryKey: ["admin", "audit", page, pageSize, q], queryFn: () => adminApi.auditLogs({ page, page_size: pageSize, q: q || undefined }), placeholderData: (previous) => previous });
  const metrics = useQuery({ queryKey: ["admin", "metrics"], queryFn: adminApi.metrics });

  const save = useMutation({
    mutationFn: () => adminApi.saveSetting({ key, value: JSON.parse(value) }),
    onSuccess: () => {
      toast.push({ title: "Setting saved", tone: "success" });
      setSettingOpen(false);
      setKey("");
      setValue("{}");
      settings.refetch();
    },
    onError: (error: Error) => toast.push({ title: "Invalid setting", description: error.message, tone: "error" }),
  });

  const auditColumns: Column<any>[] = [
    { key: "created_at", label: "Time", render: (row) => <span className="text-2xs text-muted">{formatDateTime(row.created_at)}</span> },
    { key: "action", label: "Action", render: (row) => <span className="mono text-xs">{row.action}</span> },
    { key: "resource_type", label: "Resource", render: (row) => <Badge>{row.resource_type}</Badge> },
    { key: "resource_id", label: "Reference", render: (row) => <span className="mono text-[10px] text-muted">{row.resource_id?.slice(0, 12) || "—"}</span> },
    { key: "outcome", label: "Outcome", render: (row) => <StatusBadge status={row.outcome} /> },
    { key: "actor_user_id", label: "Actor", render: (row) => <span className="mono text-[10px] text-muted">{row.actor_user_id?.slice(0, 8) || "system"}</span> },
  ];

  const jobColumns: Column<any>[] = [
    { key: "job_type", label: "Job", render: (row) => <span className="text-xs text-ink">{row.job_type}</span> },
    { key: "status", label: "Status", render: (row) => <StatusBadge status={row.status} /> },
    { key: "progress", label: "Progress", align: "right", render: (row) => <span className="tabular-nums">{row.progress}%</span> },
    { key: "created_at", label: "Created", render: (row) => <span className="text-2xs text-muted">{relativeTime(row.created_at)}</span> },
    { key: "finished_at", label: "Finished", render: (row) => <span className="text-2xs text-muted">{row.finished_at ? relativeTime(row.finished_at) : "—"}</span> },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Administration"
        title="System Configuration"
        description="Tenant settings, background processing, audit trail and operational metrics."
        actions={<Button variant="ghost" size="sm" onClick={() => { settings.refetch(); jobs.refetch(); audit.refetch(); metrics.refetch(); }}>Refresh</Button>}
      />

      {settings.isLoading ? <div className="panel h-48 animate-pulse" /> : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {[
            ["Counters", Object.keys(metrics.data?.counters ?? {}).length],
            ["Gauges", Object.keys(metrics.data?.gauges ?? {}).length],
            ["Tenant settings", settings.data?.items?.length ?? 0],
            ["Environment", settings.data?.runtime?.environment],
          ].map(([label, value]) => (
            <div key={String(label)} className="panel p-3"><p className="label">{String(label)}</p><p className="mt-1 text-lg font-semibold text-ink">{String(value ?? "—")}</p></div>
          ))}
        </div>
      )}

      <div className="flex items-center gap-1 border-b border-border">
        {[
          { key: "settings", label: "Tenant settings", icon: SlidersHorizontal },
          { key: "jobs", label: "Background jobs", icon: Activity },
          { key: "audit", label: "Audit trail", icon: FileClock },
        ].map((item) => (
          <button key={item.key} onClick={() => { setTab(item.key as any); setPage(1); }} className={`-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm ${tab === item.key ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink"}`}>
            <item.icon className="h-3.5 w-3.5" /> {item.label}
          </button>
        ))}
        <div className="ml-auto pb-1.5">
          {tab !== "settings" ? <SearchInput value={q} onChange={(value) => { setQ(value); setPage(1); }} placeholder="Search…" className="w-56" /> : null}
        </div>
      </div>

      {tab === "settings" ? (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <Card className="xl:col-span-2">
            <CardHeader
              title="Tenant settings"
              description="JSON values scoped to this organization"
              action={can("settings:write") ? <Button variant="outline" size="sm" onClick={() => setSettingOpen(true)}>Add / update</Button> : null}
            />
            {(settings.data?.items ?? []).length === 0 ? <EmptyState title="No tenant overrides" description="Defaults come from environment configuration." /> : (
              <div className="divide-y divide-border/50">
                {(settings.data?.items ?? []).map((setting: any) => (
                  <div key={setting.id} className="px-4 py-3">
                    <div className="flex items-center justify-between"><p className="mono text-xs text-ink">{setting.key}</p><span className="text-2xs text-muted">{formatDateTime(setting.updated_at)}</span></div>
                    <pre className="mono mt-1 max-h-24 overflow-auto rounded bg-base/60 p-2 text-[10px] text-muted">{JSON.stringify(setting.value, null, 2)}</pre>
                    {setting.description ? <p className="mt-1 text-[10px] text-muted">{setting.description}</p> : null}
                  </div>
                ))}
              </div>
            )}
          </Card>
          <Card>
            <CardHeader title="Metric snapshot" description="In-process counters" action={<Gauge className="h-4 w-4 text-muted" />} />
            <div className="max-h-80 space-y-1 overflow-y-auto p-3">
              {Object.entries(metrics.data?.counters ?? {}).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between gap-2 border-b border-border/40 py-1 text-2xs">
                  <span className="mono truncate text-muted">{key}</span><span className="tabular-nums text-ink">{String(value)}</span>
                </div>
              ))}
              {Object.keys(metrics.data?.counters ?? {}).length === 0 ? <p className="text-xs text-muted">No counters recorded yet.</p> : null}
            </div>
          </Card>
        </div>
      ) : tab === "jobs" ? (
        <Card>
          <DataTable columns={jobColumns} rows={jobs.data?.items ?? []} rowKey={(row) => row.id} loading={jobs.isLoading} error={jobs.error} onRetry={() => jobs.refetch()}
            footer={jobs.data?.pagination ? <Pagination page={page} pages={jobs.data.pagination.pages} total={jobs.data.pagination.total} pageSize={pageSize} onPage={setPage} onPageSize={setPageSize} /> : null}
            emptyTitle="No background jobs" emptyDescription="SBOM analysis and scans register background jobs here." />
        </Card>
      ) : (
        <Card>
          <DataTable columns={auditColumns} rows={audit.data?.items ?? []} rowKey={(row) => row.id} loading={audit.isLoading} error={audit.error} onRetry={() => audit.refetch()}
            footer={audit.data?.pagination ? <Pagination page={page} pages={audit.data.pagination.pages} total={audit.data.pagination.total} pageSize={pageSize} onPage={setPage} onPageSize={setPageSize} /> : null}
            emptyTitle="No audit events" />
        </Card>
      )}

      <Modal
        open={settingOpen}
        onClose={() => setSettingOpen(false)}
        title="Set tenant configuration"
        description="Values are stored as JSON and read by matching modules."
        footer={<><Button variant="ghost" onClick={() => setSettingOpen(false)}>Cancel</Button><Button variant="primary" loading={save.isPending} disabled={!key} onClick={() => save.mutate()}>Save</Button></>}
      >
        <div className="space-y-3">
          <Field label="Key"><Input value={key} onChange={(event) => setKey(event.target.value)} placeholder="notification.default_channels" /></Field>
          <Field label="JSON value"><Textarea rows={6} className="mono text-xs" value={value} onChange={(event) => setValue(event.target.value)} /></Field>
        </div>
      </Modal>
    </div>
  );
}
