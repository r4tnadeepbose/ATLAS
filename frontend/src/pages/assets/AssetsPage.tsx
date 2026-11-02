import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, Plus, Radar, ServerCog } from "lucide-react";
import { assetApi } from "@/api/endpoints";
import { useListQuery } from "@/hooks/useListQuery";
import { useEnvironment } from "@/context/EnvironmentContext";
import { useAuth } from "@/context/AuthContext";
import { useToast } from "@/components/ui/primitives";
import { PageHeader, StatCard } from "@/components/common/PageHeader";
import { Button, Card, CardHeader, Field, Input, Modal, Select, SeverityBadge, StatusBadge, Pagination, SearchInput, Badge } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/table";
import { downloadCsv, formatDate, formatNumber, relativeTime, riskTone, titleCase } from "@/utils";
import type { Asset } from "@/types";

export function AssetsPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const queryClient = useQueryClient();
  const { can } = useAuth();
  const { environments, selectedEnvironmentId, setSelectedEnvironmentId } = useEnvironment();
  const [exposure, setExposure] = useState("");
  const [criticality, setCriticality] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ name: "", domain: "", ip_address: "", criticality: "medium", exposure: "internal", business_unit: "" });

  const filters = {
    exposure: exposure || undefined,
    criticality: criticality || undefined,
    environment_id: selectedEnvironmentId || undefined,
  };
  const list = useListQuery<Asset>(["assets"], assetApi.list, { initialSort: "risk_score", filters });
  const summary = useQuery({ queryKey: ["assets", "summary"], queryFn: assetApi.summary });
  const create = useMutation({
    mutationFn: () => assetApi.create({ ...form, environment_id: selectedEnvironmentId || undefined, source: "manual" }),
    onSuccess: () => {
      toast.push({ title: "Asset registered", description: "The asset is now part of the inventory.", tone: "success" });
      setCreateOpen(false);
      setForm({ name: "", domain: "", ip_address: "", criticality: "medium", exposure: "internal", business_unit: "" });
      queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (error: Error) => toast.push({ title: "Could not create asset", description: error.message, tone: "error" }),
  });

  const columns: Column<Asset>[] = [
    {
      key: "asset_ref",
      label: "Asset",
      sortable: false,
      render: (asset) => (
        <div className="min-w-0">
          <p className="truncate text-sm font-medium text-ink">{asset.name}</p>
          <p className="mono text-muted">{asset.domain || asset.ip_address || asset.asset_ref}</p>
        </div>
      ),
    },
    { key: "asset_ref_id", label: "Ref", render: (asset) => <span className="mono text-muted">{asset.asset_ref}</span> },
    { key: "exposure", label: "Exposure", render: (asset) => <Badge tone={asset.exposure === "public" ? "border-critical/30 bg-critical/10 text-critical" : "border-border-strong bg-raised text-muted"}>{asset.exposure}</Badge> },
    { key: "criticality", label: "Criticality", render: (asset) => <Badge>{asset.criticality}</Badge> },
    { key: "business_unit", label: "Business unit", render: (asset) => asset.business_unit || "—" },
    {
      key: "risk_score",
      label: "Risk",
      sortable: true,
      render: (asset) => <span className={`text-sm font-semibold tabular-nums ${riskTone(asset.risk_score)}`}>{formatNumber(asset.risk_score, 0)}</span>,
    },
    { key: "technology_summary", label: "Technology", render: (asset) => <span className="text-2xs text-muted">{asset.technology_summary?.slice(0, 3).join(", ") || "—"}</span> },
    { key: "last_seen", label: "Last seen", render: (asset) => <span className="text-2xs text-muted">{relativeTime(asset.last_seen)}</span> },
    { key: "status", label: "Status", render: (asset) => <StatusBadge status={asset.status} /> },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Intelligence"
        title="Asset Intelligence"
        description="Authorized organizational assets, exposure classification and correlated risk."
        actions={
          <>
            <Button variant="ghost" size="sm" onClick={() => downloadCsv("atlas-assets.csv", list.rows as unknown as Record<string, unknown>[])}>
              <Download className="h-3.5 w-3.5" /> Export
            </Button>
            {can("assets:write") ? (
              <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}>
                <Plus className="h-3.5 w-3.5" /> Register asset
              </Button>
            ) : null}
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Total assets" value={formatNumber(summary.data?.total)} icon={<ServerCog className="h-4 w-4" />} hint="Active inventory" />
        <StatCard label="Internet-facing" value={formatNumber((summary.data?.by_exposure ?? []).find((item: any) => item.name === "public")?.value ?? 0)} icon={<Radar className="h-4 w-4" />} tone="high" hint="Exposure classification" />
        <StatCard label="Critical assets" value={formatNumber((summary.data?.by_criticality ?? []).find((item: any) => item.name === "critical")?.value ?? 0)} tone="critical" hint="Business criticality" />
        <StatCard label="Discovery sources" value={formatNumber((summary.data?.by_source ?? []).length)} hint={(summary.data?.by_source ?? []).map((item: any) => item.name).join(", ") || "Manual only"} />
      </div>

      <Card>
        <CardHeader
          title="Asset inventory"
          description="Search, filter and drill into any asset"
          action={<span className="text-2xs text-muted">{list.pagination?.total ?? 0} records</span>}
        />
        <DataTable
          columns={columns}
          rows={list.rows}
          rowKey={(asset) => asset.id}
          loading={list.isLoading}
          error={list.error}
          onRetry={() => list.refetch()}
          sortBy={list.sortBy}
          sortDir={list.sortDir}
          onSort={list.onSort}
          onRowClick={(asset) => navigate(`/assets/${asset.id}`)}
          toolbar={
            <>
              <SearchInput value={list.q} onChange={list.setQ} placeholder="Search assets, domains, IPs…" className="w-64" />
              <Select value={exposure} onChange={(event) => setExposure(event.target.value)} className="h-8 w-[130px] text-xs">
                <option value="">All exposure</option>
                <option value="public">Public</option>
                <option value="partner">Partner</option>
                <option value="internal">Internal</option>
              </Select>
              <Select value={criticality} onChange={(event) => setCriticality(event.target.value)} className="h-8 w-[140px] text-xs">
                <option value="">All criticality</option>
                {["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
              </Select>
              <Select value={selectedEnvironmentId} onChange={(event) => setSelectedEnvironmentId(event.target.value)} className="h-8 w-[150px] text-xs">
                <option value="">All environments</option>
                {environments.map((environment) => <option key={environment.id} value={environment.id}>{environment.name}</option>)}
              </Select>
            </>
          }
          footer={list.pagination ? (
            <Pagination page={list.page} pages={list.pagination.pages} total={list.pagination.total} pageSize={list.pageSize} onPage={list.setPage} onPageSize={list.setPageSize} />
          ) : null}
          emptyTitle="No assets registered"
          emptyDescription="Register an asset manually or run an authorized discovery assessment."
        />
      </Card>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Register asset"
        description="Assets created here are explicitly owned inventory records."
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button variant="primary" loading={create.isPending} disabled={!form.name} onClick={() => create.mutate()}>Register</Button>
          </>
        }
      >
        <div className="grid grid-cols-2 gap-3">
          <Field label="Display name" className="col-span-2"><Input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Payments API" /></Field>
          <Field label="Domain"><Input value={form.domain} onChange={(event) => setForm({ ...form, domain: event.target.value })} placeholder="payments.company.com" /></Field>
          <Field label="IP address"><Input value={form.ip_address} onChange={(event) => setForm({ ...form, ip_address: event.target.value })} placeholder="203.0.113.10" /></Field>
          <Field label="Exposure">
            <Select value={form.exposure} onChange={(event) => setForm({ ...form, exposure: event.target.value })}>
              {["public", "partner", "internal"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
            </Select>
          </Field>
          <Field label="Criticality">
            <Select value={form.criticality} onChange={(event) => setForm({ ...form, criticality: event.target.value })}>
              {["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
            </Select>
          </Field>
          <Field label="Business unit" className="col-span-2"><Input value={form.business_unit} onChange={(event) => setForm({ ...form, business_unit: event.target.value })} placeholder="Payments" /></Field>
        </div>
      </Modal>
    </div>
  );
}

export function AssetDetailPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const queryClient = useQueryClient();
  const { can } = useAuth();
  const { id = "" } = useParams();
  const [exposure, setExposure] = useState("");
  const [criticality, setCriticality] = useState("");
  const asset = useQuery({ queryKey: ["assets", id], queryFn: () => assetApi.get(id) });
  const update = useMutation({
    mutationFn: () => assetApi.update(id, { exposure: exposure || asset.data?.exposure, criticality: criticality || asset.data?.criticality }),
    onSuccess: () => {
      toast.push({ title: "Asset updated", tone: "success" });
      queryClient.invalidateQueries({ queryKey: ["assets", id] });
    },
    onError: (error: Error) => toast.push({ title: "Update failed", description: error.message, tone: "error" }),
  });

  if (asset.isLoading) return <div className="panel mt-4 h-64 animate-pulse" />;
  if (asset.isError) return <div className="panel mt-4 p-6 text-sm text-critical">{(asset.error as Error).message}</div>;
  const data = asset.data!;

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Asset Intelligence"
        title={data.name}
        description={`${data.domain || data.ip_address || "No address recorded"} · ${data.asset_ref}`}
        actions={
          <>
            <Button variant="ghost" size="sm" onClick={() => navigate("/assets")}>Back to inventory</Button>
            {can("assets:write") ? (
              <>
                <Select value={exposure || data.exposure} onChange={(event) => setExposure(event.target.value)} className="h-8 w-[120px] text-xs">
                  {["public", "partner", "internal"].map((value) => <option key={value} value={value}>{titleCase(value)} exposure</option>)}
                </Select>
                <Select value={criticality || data.criticality} onChange={(event) => setCriticality(event.target.value)} className="h-8 w-[130px] text-xs">
                  {["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{titleCase(value)} criticality</option>)}
                </Select>
                <Button variant="primary" size="sm" loading={update.isPending} onClick={() => update.mutate()}>Save classification</Button>
              </>
            ) : null}
          </>
        }
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Asset profile" description="Normalized inventory record" />
          <div className="grid grid-cols-2 gap-4 p-4 md:grid-cols-3">
            {[
              ["Reference", data.asset_ref],
              ["Domain", data.domain || "—"],
              ["IP address", data.ip_address || "—"],
              ["Port", data.port ?? "—"],
              ["HTTP status", data.http_status ?? "—"],
              ["Hosting", data.hosting_provider || "—"],
              ["Business unit", data.business_unit || "—"],
              ["First seen", formatDate(data.first_seen)],
              ["Last observed", relativeTime(data.last_seen)],
              ["Source", data.source],
              ["Exposure", data.exposure],
              ["Criticality", data.criticality],
            ].map(([label, value]) => (
              <div key={String(label)}>
                <p className="label">{label}</p>
                <p className="mt-0.5 truncate text-sm text-ink">{String(value)}</p>
              </div>
            ))}
            <div className="col-span-2 md:col-span-3">
              <p className="label">Technology stack</p>
              <div className="mt-1.5 flex flex-wrap gap-1">
                {(data.technology_summary ?? []).length ? data.technology_summary.map((tech) => <Badge key={tech}>{tech}</Badge>) : <span className="text-sm text-muted">None recorded</span>}
              </div>
            </div>
          </div>
        </Card>

        <Card>
          <CardHeader title="Risk posture" description="Derived from correlated findings" />
          <div className="p-4">
            <div className="flex items-end justify-between">
              <p className={`text-4xl font-semibold tabular-nums ${riskTone(data.risk_score)}`}>{formatNumber(data.risk_score, 0)}</p>
              <StatusBadge status={data.status} />
            </div>
            <div className="mt-4 space-y-2">
              <p className="label">Open findings</p>
              {(data.findings ?? []).filter((finding) => !["resolved", "closed"].includes(finding.status)).slice(0, 5).map((finding) => (
                <button key={finding.id} onClick={() => navigate(`/vulnerabilities/${finding.id}`)} className="flex w-full items-center justify-between gap-2 rounded border border-border bg-base/40 px-2 py-1.5 text-left hover:border-border-strong">
                  <span className="truncate text-2xs text-ink">{finding.title}</span>
                  <SeverityBadge severity={finding.severity} />
                </button>
              ))}
              {(data.findings ?? []).filter((finding) => !["resolved", "closed"].includes(finding.status)).length === 0 ? <p className="text-xs text-muted">No open findings linked to this asset.</p> : null}
            </div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader title="Network services" description="Observed ports from authorized assessments" />
          <div className="p-4">
            {(data.network_services ?? []).length === 0 ? (
              <p className="text-xs text-muted">No network services recorded. Run an authorized port assessment to populate this view.</p>
            ) : (
              <div className="space-y-1.5">
                {data.network_services!.map((service) => (
                  <div key={service.id} className="flex items-center justify-between rounded border border-border bg-base/40 px-2.5 py-1.5 text-xs">
                    <span className="mono text-ink">{service.port}/{service.protocol}</span>
                    <span className="text-muted">{service.service_name || "unknown"} {service.version ? `· ${service.version}` : ""}</span>
                    <StatusBadge status={service.state} />
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="Certificates & technologies" description="Observed infrastructure metadata" />
          <div className="p-4">
            {(data.certificates ?? []).length === 0 ? <p className="text-xs text-muted">No certificates recorded.</p> : (
              <div className="space-y-1.5">
                {data.certificates!.map((certificate) => (
                  <div key={certificate.id} className="flex items-center justify-between rounded border border-border bg-base/40 px-2.5 py-1.5 text-xs">
                    <span className="truncate text-ink">{certificate.common_name}</span>
                    <span className="text-muted">{certificate.issuer || "unknown issuer"}</span>
                    <span className="text-2xs text-muted">{formatDate(certificate.not_after)}</span>
                  </div>
                ))}
              </div>
            )}
            <div className="mt-3 flex flex-wrap gap-1">
              {(data.technologies ?? []).map((technology) => <Badge key={technology.id}>{technology.name}{technology.version ? ` ${technology.version}` : ""}</Badge>)}
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
