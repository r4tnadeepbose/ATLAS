import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Plug, RefreshCw, Settings2, ShieldCheck, Terminal } from "lucide-react";
import { adminApi } from "@/api/endpoints";
import { useAuth } from "@/context/AuthContext";
import { PageHeader } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Modal, StatusBadge, Switch, Textarea, useToast } from "@/components/ui/primitives";
import { formatDateTime, humanize, humanizeAdapterStatus } from "@/utils";
import type { Integration } from "@/types";

export function IntegrationsPage() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const { can } = useAuth();
  const [editing, setEditing] = useState<Integration | null>(null);
  const [config, setConfig] = useState("{}");

  const integrations = useQuery({ queryKey: ["integrations"], queryFn: adminApi.integrations });
  const grouped = (integrations.data?.items ?? []).reduce<Record<string, Integration[]>>((accumulator, item) => {
    (accumulator[item.category] ||= []).push(item);
    return accumulator;
  }, {});

  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) => adminApi.updateIntegration(id, body),
    onSuccess: () => {
      toast.push({ title: "Integration updated", tone: "success" });
      queryClient.invalidateQueries({ queryKey: ["integrations"] });
    },
    onError: (error: Error) => toast.push({ title: "Update failed", description: error.message, tone: "error" }),
  });

  const test = useMutation({
    mutationFn: (id: string) => adminApi.testIntegration(id),
    onSuccess: (result) => {
      toast.push({ title: result.ok ? "Integration healthy" : "Integration unavailable", description: result.error || undefined, tone: result.ok ? "success" : "error" });
      integrations.refetch();
    },
    onError: (error: Error) => toast.push({ title: "Test failed", description: error.message, tone: "error" }),
  });

  const saveConfig = async () => {
    if (!editing?.id) return;
    try {
      const parsed = JSON.parse(config);
      await update.mutateAsync({ id: editing.id, body: { config: parsed } });
      setEditing(null);
    } catch (error) {
      toast.push({ title: "Invalid configuration", description: (error as Error).message, tone: "error" });
    }
  };

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Administration"
        title="Integrations"
        description="Security tooling, intelligence providers and notification channels. Availability is detected, never assumed."
        actions={<Button variant="ghost" size="sm" onClick={() => integrations.refetch()}><RefreshCw className="h-3.5 w-3.5" /> Refresh status</Button>}
      />

      {integrations.isLoading ? <div className="panel h-64 animate-pulse" /> : (
        <div className="grid gap-4 xl:grid-cols-2">
          {Object.entries(grouped).map(([category, items]) => (
            <Card key={category}>
              <CardHeader title={humanize(category)} description={`${items.length} integration${items.length === 1 ? "" : "s"}`} action={<Plug className="h-4 w-4 text-muted" />} />
              <div className="grid gap-3 p-3 md:grid-cols-2">
                {items.map((integration) => (
                  <div key={integration.key} className="rounded border border-border bg-base/40 p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex min-w-0 items-center gap-2">
                        {integration.category === "notification" ? <Settings2 className="h-4 w-4 shrink-0 text-muted" /> : <Terminal className="h-4 w-4 shrink-0 text-muted" />}
                        <div className="min-w-0">
                          <p className="truncate text-xs font-semibold text-ink">{integration.name}</p>
                          <p className="mono truncate text-[10px] text-muted">{integration.key}</p>
                        </div>
                      </div>
                      <Badge tone={integration.status === "available" || integration.status === "configured" ? "border-accent/35 bg-accent/10 text-accent" : undefined}>
                        {humanizeAdapterStatus(integration.status)}
                      </Badge>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-1">{(integration.capabilities ?? []).map((capability) => <Badge key={capability} className="text-[8px]">{humanize(capability)}</Badge>)}</div>
                    <p className="mt-1.5 truncate text-[10px] text-muted">
                      {integration.status === "unavailable"
                        ? "Not installed on this host"
                        : integration.version
                          ? `v${integration.version}`
                          : "No version reported"}
                    </p>
                    {integration.last_error ? <p className="mt-1 truncate text-[10px] text-critical">{integration.last_error}</p> : null}
                    <div className="mt-2.5 flex items-center justify-between gap-2">
                      {can("integrations:write") ? (
                        <Switch
                          checked={integration.enabled}
                          onChange={(value) => integration.id && update.mutate({ id: integration.id, body: { enabled: value } })}
                          label={integration.enabled ? "Enabled" : "Disabled"}
                        />
                      ) : <Badge>{integration.enabled ? "enabled" : "disabled"}</Badge>}
                      {can("integrations:write") ? (
                        <div className="flex gap-1">
                          <Button variant="ghost" size="sm" disabled={!integration.id} onClick={() => integration.id && test.mutate(integration.id)}>Test</Button>
                          <Button variant="ghost" size="sm" disabled={!integration.id} onClick={() => { setEditing(integration); setConfig(JSON.stringify(integration.config || {}, null, 2)); }}>Configure</Button>
                        </div>
                      ) : null}
                    </div>
                    {integration.last_checked_at ? <p className="mt-1 text-[10px] text-muted/70">Checked {formatDateTime(integration.last_checked_at)}</p> : null}
                  </div>
                ))}
              </div>
            </Card>
          ))}
        </div>
      )}
      {(integrations.data?.items ?? []).length === 0 ? <EmptyState title="No integrations" description="Adapters are registered automatically on first load." /> : null}

      <Card>
        <CardHeader title="Integration policy" description="How ATLAS handles external tools" action={<ShieldCheck className="h-4 w-4 text-accent" />} />
        <div className="grid gap-2 p-4 text-2xs text-muted md:grid-cols-2">
          <p>• Every external tool is wrapped in an independent adapter with availability reporting.</p>
          <p>• Scans execute with argument arrays, timeouts and no shell interpolation.</p>
          <p>• Unavailable tools return an explicit error instead of demo results.</p>
          <p>• Provider credentials are masked in API responses and never logged.</p>
          <p className="md:col-span-2 flex items-center gap-1.5">Installation guide: <a href="/api/docs" className="inline-flex items-center gap-1 text-accent hover:underline">adapter API <ExternalLink className="h-3 w-3" /></a></p>
        </div>
      </Card>

      <Modal
        open={Boolean(editing)}
        onClose={() => setEditing(null)}
        title={`Configure ${editing?.name || "integration"}`}
        description="Configuration is stored per organization. Secret values are masked when read."
        footer={<><Button variant="ghost" onClick={() => setEditing(null)}>Cancel</Button><Button variant="primary" loading={update.isPending} onClick={saveConfig}>Save configuration</Button></>}
      >
        <Field label="Configuration JSON" hint="Example: { &quot;base_url&quot;: &quot;https://…&quot;, &quot;api_key&quot;: &quot;…&quot; }">
          <Textarea rows={8} className="mono text-xs" value={config} onChange={(event) => setConfig(event.target.value)} />
        </Field>
      </Modal>
    </div>
  );
}
