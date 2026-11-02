import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Focus, Plus, RefreshCw, Share2, Waypoints } from "lucide-react";
import { serviceApi } from "@/api/endpoints";
import { useListQuery } from "@/hooks/useListQuery";
import { useEnvironment } from "@/context/EnvironmentContext";
import { useAuth } from "@/context/AuthContext";
import { PageHeader, StatCard } from "@/components/common/PageHeader";
import { Button, Badge, Card, CardHeader, EmptyState, ErrorState, Field, Input, Modal, Select, Skeleton, StatusBadge, Tabs, Pagination, SearchInput, useToast, Switch } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/table";
import { formatNumber, relativeTime, riskTone, titleCase } from "@/utils";
import type { GraphEdge, GraphNode, Microservice } from "@/types";
import { useGraphLayout, placeLabels } from "./layout";

const RISK_COLORS: Record<string, string> = {
  critical: "rgb(var(--atlas-critical))",
  high: "rgb(var(--atlas-high))",
  medium: "rgb(var(--atlas-medium))",
  low: "rgb(var(--atlas-low))",
};

export function MicroservicesPage() {
  const [tab, setTab] = useState<"map" | "inventory">("map");
  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Intelligence"
        title="Microservice Intelligence"
        description="Service ownership, dependency relationships and the blast radius of vulnerable dependencies."
        actions={<Badge tone="border-accent/30 bg-accent/10 text-accent">{tab === "map" ? "Relationship map" : "Inventory"}</Badge>}
      />
      <Tabs tabs={[{ key: "map", label: "Relationship map" }, { key: "inventory", label: "Service inventory" }]} value={tab} onChange={(key) => setTab(key as "map" | "inventory")} />
      {tab === "map" ? <ServiceMap /> : <ServiceInventory />}
    </div>
  );
}

function ServiceMap() {
  const navigate = useNavigate();
  const [businessUnit, setBusinessUnit] = useState("");
  const [riskLevel, setRiskLevel] = useState("");
  const [vulnerabilityStatus, setVulnerabilityStatus] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [showExternal, setShowExternal] = useState(true);

  const summary = useQuery({ queryKey: ["microservices", "summary"], queryFn: serviceApi.summary });
  const graph = useQuery({
    queryKey: ["microservices", "graph", businessUnit, riskLevel, vulnerabilityStatus],
    queryFn: () => serviceApi.graph({ business_unit: businessUnit || undefined, risk_level: riskLevel || undefined, vulnerability_status: vulnerabilityStatus || undefined }),
  });

  const nodes = useMemo(() => (graph.data?.nodes ?? []).filter((node) => showExternal || !node.external), [graph.data, showExternal]);
  const edges = useMemo(() => (graph.data?.edges ?? []).filter((edge) => nodes.some((node) => node.id === edge.source) && nodes.some((node) => node.id === edge.target)), [graph.data, nodes]);
  const { positions } = useGraphLayout(nodes, edges);
  const labels = useMemo(() => placeLabels(nodes, positions), [nodes, positions]);
  const selectedNode = nodes.find((node) => node.id === selected);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Services" value={formatNumber(summary.data?.total)} icon={<Waypoints className="h-4 w-4" />} hint="Registered inventory" />
        <StatCard label="Dependencies" value={formatNumber(summary.data?.dependencies)} icon={<Share2 className="h-4 w-4" />} hint="Mapped service edges" />
        <StatCard label="Critical services" value={formatNumber((summary.data?.by_criticality ?? []).find((item: any) => item.name === "critical")?.value ?? 0)} tone="critical" hint="Business criticality" />
        <StatCard label="High risk" value={formatNumber((summary.data?.high_risk ?? []).filter((service: any) => service.risk_score >= 65).length)} tone="high" hint="Current risk model" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-4">
        <Card className="xl:col-span-3">
          <CardHeader
            title="Service dependency graph"
            description="Interactive map of service-to-service and external dependencies"
            action={
              <div className="flex items-center gap-2">
                <Switch checked={showExternal} onChange={setShowExternal} label="External" />
                <Button variant="ghost" size="icon" onClick={() => graph.refetch()} aria-label="Refresh graph">
                  <RefreshCw className={`h-3.5 w-3.5 ${graph.isFetching ? "animate-spin" : ""}`} />
                </Button>
              </div>
            }
          />
          <div className="relative">
            {graph.isLoading ? (
              <Skeleton className="m-3 h-[520px]" />
            ) : graph.isError ? (
              <ErrorState message={(graph.error as Error).message} retry={() => graph.refetch()} />
            ) : nodes.length === 0 ? (
              <EmptyState icon={<Focus className="h-5 w-5" />} title="No services in this view" description="Adjust the filters or register microservices to build the map." />
            ) : (
              <>
                <svg viewBox="0 0 1200 680" className="h-[520px] w-full" role="img" aria-label="Microservice dependency graph">
                  <defs>
                    <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
                      <path d="M 0 0 L 10 5 L 0 10 z" fill="rgb(var(--atlas-border-strong))" />
                    </marker>
                  </defs>
                  {edges.map((edge) => {
                    const source = positions.get(edge.source);
                    const target = positions.get(edge.target);
                    if (!source || !target) return null;
                    const highlighted = !selected || edge.source === selected || edge.target === selected;
                    return (
                      <line
                        key={edge.id}
                        x1={source.x}
                        y1={source.y}
                        x2={target.x}
                        y2={target.y}
                        stroke={highlighted ? "rgb(var(--atlas-border-strong))" : "rgb(var(--atlas-border))"}
                        strokeWidth={highlighted ? 1.1 : 0.7}
                        markerEnd="url(#arrow)"
                      />
                    );
                  })}
                  {nodes.map((node) => {
                    const position = positions.get(node.id);
                    if (!position) return null;
                    const color = node.external ? "rgb(var(--atlas-muted))" : RISK_COLORS[node.risk_level || "low"] || "rgb(var(--atlas-cyan))";
                    const isSelected = selected === node.id;
                    const label = labels.get(node.id);
                    const showLabel = isSelected || Boolean(label?.visible);
                    return (
                      <g key={node.id} transform={`translate(${position.x}, ${position.y})`} onClick={() => setSelected(isSelected ? null : node.id)} onDoubleClick={() => !node.external && navigate(`/microservices/${node.id}`)} className="cursor-pointer">
                        <title>{node.label}{node.open_findings ? ` — ${node.open_findings} open finding${node.open_findings === 1 ? "" : "s"}` : ""}</title>
                        {isSelected ? <circle r={20} fill={color} opacity={0.12} /> : null}
                        <circle r={node.external ? 5 : 8} fill={color} stroke="rgb(var(--atlas-base))" strokeWidth={2} opacity={node.external ? 0.7 : 1} />
                        {showLabel && label ? (
                          <text x={label.x - position.x} y={label.y - position.y} textAnchor={label.anchor} fill={isSelected ? "rgb(var(--atlas-ink))" : "rgb(var(--atlas-muted))"} fontSize={node.external ? 10 : 11} fontWeight={isSelected ? 600 : 500}>
                            {node.label.length > 24 ? `${node.label.slice(0, 23)}…` : node.label}
                          </text>
                        ) : null}
                        {!node.external && node.open_findings > 0 ? (
                          <g transform="translate(10,-8)">
                            <circle r={6.5} fill="rgb(var(--atlas-panel))" stroke={color} strokeWidth={1} />
                            <text y={2.5} textAnchor="middle" fill={color} fontSize={8} fontWeight={700}>{node.open_findings}</text>
                          </g>
                        ) : null}
                      </g>
                    );
                  })}
                </svg>
                <div className="absolute bottom-3 left-3 rounded border border-border bg-base/90 px-2.5 py-1.5">
                  <p className="mb-1 text-[9px] uppercase tracking-widest text-muted">Risk level</p>
                  <div className="flex items-center gap-3">
                    {Object.entries(RISK_COLORS).map(([level, color]) => (
                      <span key={level} className="flex items-center gap-1 text-[10px] capitalize text-muted">
                        <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} /> {level}
                      </span>
                    ))}
                  </div>
                </div>
                <p className="absolute bottom-3 right-3 text-[10px] text-muted/70">Click to focus · double-click to open</p>
              </>
            )}
          </div>
        </Card>

        <div className="space-y-4 xl:col-span-1">
          <Card>
            <CardHeader title="Graph filters" description="Reduce noise while investigating" />
            <div className="space-y-3 p-3.5">
              <Field label="Business unit">
                <Select value={businessUnit} onChange={(event) => setBusinessUnit(event.target.value)}>
                  <option value="">All units</option>
                  {(summary.data?.by_business_unit ?? []).map((unit: any) => (
                    <option key={unit.name} value={unit.name}>{unit.name}</option>
                  ))}
                </Select>
              </Field>
              <Field label="Risk level">
                <Select value={riskLevel} onChange={(event) => setRiskLevel(event.target.value)}>
                  <option value="">All risk levels</option>
                  {["critical", "high", "medium", "low"].map((level) => <option key={level} value={level}>{titleCase(level)}</option>)}
                </Select>
              </Field>
              <Field label="Vulnerability status">
                <Select value={vulnerabilityStatus} onChange={(event) => setVulnerabilityStatus(event.target.value)}>
                  <option value="">All services</option>
                  <option value="vulnerable">With open findings</option>
                  <option value="clean">No open findings</option>
                </Select>
              </Field>
            </div>
          </Card>

          <Card>
            <CardHeader title={selectedNode ? selectedNode.label : "Service focus"} description={selectedNode ? "Selected node detail" : "Select a node in the graph"} />
            {selectedNode ? (
              <div className="space-y-2 p-3.5">
                <div className="flex items-center justify-between"><span className="label">Risk score</span><span className={`text-sm font-semibold ${riskTone(selectedNode.risk_score)}`}>{formatNumber(selectedNode.risk_score, 0)}</span></div>
                <div className="flex items-center justify-between"><span className="label">Open findings</span><span className="text-sm text-ink">{selectedNode.open_findings}</span></div>
                <div className="flex items-center justify-between"><span className="label">Business unit</span><span className="text-xs text-ink">{selectedNode.business_unit || "—"}</span></div>
                <div className="flex items-center justify-between"><span className="label">Language</span><span className="text-xs text-ink">{selectedNode.language || "—"}</span></div>
                <div className="flex items-center justify-between"><span className="label">Criticality</span><StatusBadge status={selectedNode.criticality} /></div>
                {!selectedNode.external ? (
                  <Button variant="outline" size="sm" className="mt-2 w-full" onClick={() => navigate(`/microservices/${selectedNode.id}`)}>Open service record</Button>
                ) : (
                  <p className="text-2xs text-muted">External dependency — no ATLAS inventory record.</p>
                )}
              </div>
            ) : (
              <EmptyState title="Nothing selected" description="Click a service to inspect its risk and findings." className="py-8" />
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}

function ServiceInventory() {
  const navigate = useNavigate();
  const toast = useToast();
  const { selectedEnvironmentId, selectedEnvironment } = useEnvironment();
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: "", business_unit: "", language: "", criticality: "medium", version: "" });
  const list = useListQuery<Microservice>(["microservices"], serviceApi.list, {
    initialSort: "risk_score",
    filters: { environment_id: selectedEnvironmentId || undefined },
  });
  const summary = useQuery({ queryKey: ["microservices", "summary"], queryFn: serviceApi.summary });

  const columns: Column<Microservice>[] = [
    {
      key: "name",
      label: "Service",
      sortable: true,
      render: (service) => (
        <div>
          <p className="text-sm font-medium text-ink">{service.name}</p>
          <p className="mono text-muted">{service.service_ref}{service.language ? ` · ${service.language}` : ""}</p>
        </div>
      ),
    },
    { key: "business_unit", label: "Business unit", render: (service) => service.business_unit || "—" },
    { key: "environment_name", label: "Environment", render: (service) => service.environment_name || "—" },
    { key: "criticality", label: "Criticality", render: (service) => <Badge>{service.criticality}</Badge> },
    { key: "risk_level", label: "Risk level", render: (service) => <Badge tone={service.risk_level === "critical" ? "border-critical/30 bg-critical/10 text-critical" : "border-border-strong bg-raised text-muted"}>{service.risk_level}</Badge> },
    { key: "risk_score", label: "Risk", sortable: true, render: (service) => <span className={`font-semibold tabular-nums ${riskTone(service.risk_score)}`}>{formatNumber(service.risk_score, 0)}</span> },
    { key: "open_findings", label: "Open", render: (service) => <span className="tabular-nums">{service.open_findings ?? 0}</span> },
    { key: "last_assessed_at", label: "Last assessed", render: (service) => <span className="text-2xs text-muted">{relativeTime(service.last_assessed_at)}</span> },
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-muted">
          {list.pagination?.total ?? 0} services tracked{selectedEnvironment ? ` in ${selectedEnvironment.name}` : " across all environments"} · {summary.data?.by_business_unit?.length ?? 0} business units.
        </p>
        {can("microservices:write") ? <Button variant="primary" size="sm" onClick={() => setOpen(true)}><Plus className="h-3.5 w-3.5" /> Register service</Button> : null}
      </div>
      <Card>
        <DataTable
          columns={columns}
          rows={list.rows}
          rowKey={(service) => service.id}
          loading={list.isLoading}
          error={list.error}
          onRetry={() => list.refetch()}
          sortBy={list.sortBy}
          sortDir={list.sortDir}
          onSort={list.onSort}
          onRowClick={(service) => navigate(`/microservices/${service.id}`)}
          toolbar={<SearchInput value={list.q} onChange={list.setQ} placeholder="Search services, owners, units…" className="w-72" />}
          footer={list.pagination ? <Pagination page={list.page} pages={list.pagination.pages} total={list.pagination.total} pageSize={list.pageSize} onPage={list.setPage} onPageSize={list.setPageSize} /> : null}
          emptyTitle="No microservices registered"
          emptyDescription="Register services to map dependencies and correlate SBOM findings."
        />
      </Card>

      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Register microservice"
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="primary" disabled={!form.name} onClick={async () => {
              try {
                await serviceApi.create({ ...form, tech_stack: form.language ? [form.language.toLowerCase()] : [] });
                toast.push({ title: "Service registered", tone: "success" });
                setOpen(false);
                setForm({ name: "", business_unit: "", language: "", criticality: "medium", version: "" });
                list.refetch();
              } catch (error) {
                toast.push({ title: "Registration failed", description: (error as Error).message, tone: "error" });
              }
            }}>Register</Button>
          </>
        }
      >
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name" className="col-span-2"><Input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="payment-service" /></Field>
          <Field label="Business unit"><Input value={form.business_unit} onChange={(event) => setForm({ ...form, business_unit: event.target.value })} placeholder="Payments" /></Field>
          <Field label="Language"><Input value={form.language} onChange={(event) => setForm({ ...form, language: event.target.value })} placeholder="Go" /></Field>
          <Field label="Criticality">
            <Select value={form.criticality} onChange={(event) => setForm({ ...form, criticality: event.target.value })}>
              {["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
            </Select>
          </Field>
          <Field label="Version"><Input value={form.version} onChange={(event) => setForm({ ...form, version: event.target.value })} placeholder="1.4.0" /></Field>
        </div>
      </Modal>
    </div>
  );
}
