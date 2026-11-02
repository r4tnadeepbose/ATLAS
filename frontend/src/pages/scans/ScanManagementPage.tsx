import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Plus, Trash2, Wrench } from "lucide-react";
import { scanApi } from "@/api/endpoints";
import { useAuth } from "@/context/AuthContext";
import { PageHeader } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Modal, Select, StatusBadge, Switch, useToast } from "@/components/ui/primitives";
import { formatDateTime, humanizeAdapterStatus, relativeTime, titleCase } from "@/utils";

export function ScanManagementPage() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: "", scan_type: "full_recon", target: "", cron: "0 2 * * *", domains: "" });

  const schedules = useQuery({ queryKey: ["scan-schedules"], queryFn: scanApi.schedules });
  const tools = useQuery({ queryKey: ["scans", "tools"], queryFn: scanApi.tools });
  const create = useMutation({
    mutationFn: () => scanApi.createSchedule({ name: form.name, scan_type: form.scan_type, target: form.target, cron: form.cron, scope: { domains: form.domains.split(",").map((value) => value.trim()).filter(Boolean) } }),
    onSuccess: () => {
      toast.push({ title: "Schedule created", description: "The scheduler may run this assessment automatically; scope is still enforced.", tone: "success" });
      setOpen(false);
      queryClient.invalidateQueries({ queryKey: ["scan-schedules"] });
    },
    onError: (error: Error) => toast.push({ title: "Could not create schedule", description: error.message, tone: "error" }),
  });

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Security Operations"
        title="Scan Management"
        description="Scheduling, adapter availability and execution guardrails for authorized assessments."
        actions={can("scans:admin") ? <Button variant="primary" size="sm" onClick={() => setOpen(true)}><Plus className="h-3.5 w-3.5" /> New schedule</Button> : undefined}
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Scheduled assessments" description="Cron-driven authorized discovery" action={<CalendarClock className="h-4 w-4 text-muted" />} />
          {(schedules.data?.items ?? []).length === 0 ? (
            <EmptyState title="No schedules configured" description="Create a recurring assessment for an authorized domain." action={can("scans:admin") ? <Button variant="outline" size="sm" onClick={() => setOpen(true)}>Create schedule</Button> : undefined} />
          ) : (
            <div className="divide-y divide-border/50">
              {schedules.data!.items.map((schedule) => (
                <div key={schedule.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-ink">{schedule.name}</p>
                    <p className="mono text-2xs text-muted">{schedule.scan_type} · {schedule.target} · {schedule.cron}</p>
                    <p className="text-[10px] text-muted">Last run {schedule.last_run_at ? relativeTime(schedule.last_run_at) : "never"}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    {can("scans:admin") ? (
                      <Switch
                        checked={schedule.enabled}
                        onChange={async (value) => {
                          await scanApi.updateSchedule(schedule.id, { enabled: value });
                          schedules.refetch();
                        }}
                        label={schedule.enabled ? "Enabled" : "Paused"}
                      />
                    ) : <Badge>{schedule.enabled ? "enabled" : "paused"}</Badge>}
                    {can("scans:admin") ? (
                      <Button variant="ghost" size="icon" aria-label="Delete schedule" onClick={async () => {
                        await scanApi.deleteSchedule(schedule.id);
                        toast.push({ title: "Schedule deleted", tone: "info" });
                        schedules.refetch();
                      }}><Trash2 className="h-3.5 w-3.5" /></Button>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card>
          <CardHeader title="Guardrails" description="Enforced by the scan runner" action={<Wrench className="h-4 w-4 text-muted" />} />
          <div className="space-y-2 p-3.5 text-2xs text-muted">
            {[
              "Explicit authorized scope required for every target",
              "Authorization reference mandatory for active scans",
              "No shell execution; argument arrays only",
              "Per-adapter timeouts and cancellation checks",
              "Scans run outside synchronous HTTP requests",
              "Adapters report unavailable instead of fabricating results",
            ].map((rule) => (
              <div key={rule} className="flex items-start gap-1.5">
                <span className="mt-1 h-1 w-1 shrink-0 rounded-full bg-accent" /> {rule}
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card>
        <CardHeader title="Adapter availability" description="Detected on the API host" action={<Badge>{tools.data?.items?.length ?? 0} adapters</Badge>} />
        <div className="grid gap-2 p-3 md:grid-cols-2 xl:grid-cols-4">
          {(tools.data?.items ?? []).map((tool: any) => (
            <div key={tool.key} className="rounded border border-border bg-base/40 p-2.5">
              <div className="flex items-center justify-between"><p className="text-xs font-medium text-ink">{tool.key}</p><Badge tone={tool.available ? "border-accent/35 bg-accent/10 text-accent" : "border-border-strong bg-raised text-muted"}>{humanizeAdapterStatus(tool.available ? "available" : "unavailable")}</Badge></div>
              <p className="mt-1 text-[10px] text-muted">{tool.version || "Not installed on this host"}</p>
              <div className="mt-1.5 flex flex-wrap gap-1">{(tool.capabilities ?? []).slice(0, 3).map((capability: string) => <Badge key={capability} className="text-[8px]">{capability}</Badge>)}</div>
            </div>
          ))}
        </div>
      </Card>

      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Create scan schedule"
        description="Schedules are recorded with scope; the runner enforces authorization at execution time."
        footer={<><Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" loading={create.isPending} disabled={!form.name || !form.target || !form.domains} onClick={() => create.mutate()}>Create</Button></>}
      >
        <div className="space-y-3">
          <Field label="Name"><Input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Nightly external review" /></Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Scan type">
              <Select value={form.scan_type} onChange={(event) => setForm({ ...form, scan_type: event.target.value })}>
                {["full_recon", "subdomain_enumeration", "http_probe", "port_scan", "vulnerability_scan"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
              </Select>
            </Field>
            <Field label="Cron" hint="Standard five-field cron expression"><Input value={form.cron} onChange={(event) => setForm({ ...form, cron: event.target.value })} className="mono" /></Field>
          </div>
          <Field label="Target"><Input value={form.target} onChange={(event) => setForm({ ...form, target: event.target.value })} placeholder="company.example" /></Field>
          <Field label="Authorized domains"><Input value={form.domains} onChange={(event) => setForm({ ...form, domains: event.target.value })} placeholder="company.example" /></Field>
        </div>
      </Modal>
    </div>
  );
}
