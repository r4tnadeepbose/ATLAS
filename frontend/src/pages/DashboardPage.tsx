import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import {
  Activity,
  AlertOctagon,
  ArrowRight,
  Boxes,
  BrainCircuit,
  Crosshair,
  FileWarning,
  GitBranch,
  Layers,
  Radar,
  ServerCog,
  ShieldAlert,
  ShieldCheck,
  Waypoints,
} from "lucide-react";
import { dashboardApi, serviceApi, sbomApi, apiInventoryApi, adminApi } from "@/api/endpoints";
import { PageHeader, DemoBanner, StatCard, InlineStat } from "@/components/common/PageHeader";
import { Card, CardHeader, Button, ErrorState, Skeleton, StatusBadge, ProgressBar, SeverityBadge, EmptyState } from "@/components/ui/primitives";
import { ChartFrame, SeverityDonut, SeverityLegend, SeverityStackedBars, TrendArea, HorizontalBars, PostureGauge } from "@/components/charts";
import { formatNumber, formatPercent, humanize, relativeTime, titleCase, riskTone } from "@/utils";

export function DashboardPage() {
  const navigate = useNavigate();
  const overview = useQuery({ queryKey: ["dashboard", "overview"], queryFn: dashboardApi.overview, refetchInterval: 60000 });
  const trends = useQuery({ queryKey: ["dashboard", "trends"], queryFn: dashboardApi.riskTrends });
  const activity = useQuery({ queryKey: ["dashboard", "activity"], queryFn: () => dashboardApi.activity(12) });
  const services = useQuery({ queryKey: ["microservices", "summary"], queryFn: serviceApi.summary });
  const sbom = useQuery({ queryKey: ["sbom", "dashboard"], queryFn: sbomApi.dashboard });
  const apis = useQuery({ queryKey: ["apis", "dashboard"], queryFn: apiInventoryApi.dashboard });
  const organization = useQuery({ queryKey: ["organization"], queryFn: adminApi.organization });

  if (overview.isError) {
    return <ErrorState message={(overview.error as Error)?.message || "Dashboard unavailable"} retry={() => overview.refetch()} className="panel mt-10" />;
  }

  const counts = overview.data?.counts ?? {};
  const trendData = (trends.data?.posture as any[]) ?? [];
  const discovery = (trends.data?.discovery as any[]) ?? [];
  const exposure = (trends.data?.exposure as any[]) ?? [];
  const businessUnits = (trends.data?.business_units as any[]) ?? [];
  const remediation = (trends.data?.remediation as any[]) ?? [];
  const apiSecurity = (trends.data?.api_security as any[]) ?? [];
  const demo = Boolean((organization.data?.settings as any)?.demo);
  const activityGroups = (() => {
    const groups: { item: (typeof activity.data extends undefined ? never : NonNullable<typeof activity.data>["items"][number]); count: number }[] = [];
    for (const item of activity.data?.items ?? []) {
      const last = groups[groups.length - 1];
      if (last && last.item.title === item.title) last.count += 1;
      else groups.push({ item, count: 1 });
    }
    return groups;
  })();

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Overview"
        title="Command Center"
        description="Correlated security intelligence across assets, microservices, SBOMs, APIs and authorized assessments."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => navigate("/vulnerabilities")}>
              <ShieldAlert className="h-3.5 w-3.5" /> Review findings
            </Button>
            <Link to="/sbom">
              <Button variant="primary" size="sm">
                <Boxes className="h-3.5 w-3.5" /> Upload SBOM
              </Button>
            </Link>
          </>
        }
      />

      {demo ? <DemoBanner /> : null}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Monitored assets" value={overview.isLoading ? "—" : formatNumber(counts.assets as number)} icon={<ServerCog className="h-4 w-4" />} to="/assets" hint={`${counts.new_assets_7d ?? 0} new in 7d`} />
        <StatCard label="Microservices" value={formatNumber(counts.microservices as number)} icon={<Waypoints className="h-4 w-4" />} to="/microservices" hint={`SBOM coverage ${formatPercent(counts.sbom_coverage as number, 1)}`} />
        <StatCard label="Discovered APIs" value={formatNumber(counts.apis as number)} icon={<GitBranch className="h-4 w-4" />} to="/api-inventory" hint="Central inventory" />
        <StatCard label="Open findings" value={formatNumber(counts.unresolved as number)} icon={<FileWarning className="h-4 w-4" />} to="/vulnerabilities?status=open" tone="critical" hint={`${counts.open_incidents ?? 0} high/critical`} />
        <StatCard label="Security posture" value={formatPercent(counts.posture_score as number, 0)} icon={<ShieldCheck className="h-4 w-4" />} to="/risk-management" tone="accent" hint="Derived from open risk" />
        <StatCard label="MTTD" value={counts.mttd_minutes == null ? "—" : `${formatNumber(counts.mttd_minutes as number, 1)}m`} icon={<Radar className="h-4 w-4" />} hint="Intelligence → finding" tone="cyan" />
      </div>

      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-12">
        <Card className="xl:col-span-3">
          <CardHeader
            title="Security posture"
            description="100 − average open finding risk"
            action={<StatusBadge status={Number(counts.posture_score) >= 70 ? "healthy" : "at_risk"} />}
          />
          <div className="px-3 pb-3">
            {overview.isLoading ? <Skeleton className="h-[180px] w-full" /> : <PostureGauge score={Number(counts.posture_score ?? 0)} />}
            <div className="mt-1 grid grid-cols-2 gap-x-3">
              <InlineStat label="Critical" value={counts.critical ?? 0} tone="text-critical" />
              <InlineStat label="High" value={counts.high ?? 0} tone="text-high" />
              <InlineStat label="Medium" value={counts.medium ?? 0} tone="text-medium" />
              <InlineStat label="Resolved 7d" value={counts.findings_resolved_7d ?? 0} tone="text-accent" />
              <InlineStat label="MTTR" value={counts.mttr_hours == null ? "—" : `${formatNumber(counts.mttr_hours as number, 1)}h`} />
              <InlineStat label="Open" value={counts.unresolved ?? 0} />
            </div>
          </div>
        </Card>

        <Card className="xl:col-span-4">
          <CardHeader
            title="Severity distribution"
            description="All active findings by severity"
            action={<Link to="/vulnerabilities" className="text-2xs text-muted hover:text-accent">View all</Link>}
          />
          <div className="p-3">
            <div className="grid grid-cols-2 items-center">
              <SeverityDonut data={overview.data?.severity_distribution ?? []} height={190} />
              <SeverityLegend data={overview.data?.severity_distribution ?? []} />
            </div>
            <div className="mt-2 border-t border-border/60 pt-2">
              <p className="label mb-1.5">Finding status</p>
              <div className="flex flex-wrap gap-1.5">
                {(overview.data?.status_distribution ?? []).map((entry) => (
                  <Link key={entry.status} to={`/vulnerabilities?status=${entry.status}`} className="rounded border border-border bg-base/40 px-2 py-1 text-2xs text-muted hover:border-border-strong hover:text-ink">
                    {humanize(entry.status)} <span className="ml-1 text-ink">{entry.count}</span>
                  </Link>
                ))}
              </div>
            </div>
          </div>
        </Card>

        <div className="xl:col-span-5">
          <ChartFrame
            title="Posture over time"
            description="Weekly posture and open finding volume"
            action={
              <div className="flex items-center gap-2 text-[10px] text-muted">
                <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-accent" /> posture</span>
                <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-cyan" /> open</span>
              </div>
            }
            height={300}
          >
            {trends.isLoading ? (
              <Skeleton className="mx-2 h-[200px]" />
            ) : trendData.length ? (
              <div className="flex h-full flex-col">
                <div className="h-1/2"><TrendArea data={trendData} dataKey="posture" xKey="week" color="rgb(var(--atlas-accent))" height={145} yDomain={[0, 100]} /></div>
                <div className="h-1/2"><TrendArea data={trendData} dataKey="open_findings" xKey="week" color="rgb(var(--atlas-cyan))" height={145} /></div>
              </div>
            ) : (
              <EmptyState title="Posture history appears after findings are triaged" className="py-8" />
            )}
          </ChartFrame>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <ChartFrame title="Vulnerability discovery" description="New findings by severity, last 30 days" height={240} className="xl:col-span-6">
          {trends.isLoading ? <Skeleton className="mx-2 h-[210px]" /> : <SeverityStackedBars data={discovery} />}
        </ChartFrame>
        <ChartFrame title="Asset exposure" description="Internet-facing versus internal estate" height={240} className="xl:col-span-3">
          <HorizontalBars data={exposure} dataKey="value" labelKey="name" color="rgb(var(--atlas-cyan))" height={205} />
        </ChartFrame>
        <ChartFrame title="Risk by business unit" description="Finding volume weighted by severity" height={240} className="xl:col-span-3">
          <HorizontalBars data={businessUnits.map((unit: any) => ({ ...unit, value: unit.total }))} dataKey="value" labelKey="business_unit" color="rgb(var(--atlas-high))" height={205} />
        </ChartFrame>
      </div>

      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-12">
        <Card className="xl:col-span-4">
          <CardHeader title="Top vulnerable services" description="Highest open finding volume" action={<Link to="/microservices" className="text-2xs text-muted hover:text-accent">Microservice map</Link>} />
          {services.isLoading ? (
            <div className="space-y-2 p-3">{Array.from({ length: 5 }).map((_, index) => <Skeleton key={index} className="h-9" />)}</div>
          ) : (services.data?.high_risk ?? []).length === 0 ? (
            <EmptyState title="No vulnerable services" className="py-8" />
          ) : (
            <div className="divide-y divide-border/50">
              {(services.data?.high_risk ?? []).map((service: any) => (
                <Link key={service.id} to={`/microservices/${service.id}`} className="flex items-center justify-between gap-3 px-3.5 py-2 hover:bg-raised/50">
                  <div className="min-w-0">
                    <p className="truncate text-xs font-medium text-ink">{service.name}</p>
                    <p className="text-[10px] text-muted">{service.business_unit} · {titleCase(service.criticality)}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-sm font-semibold tabular-nums ${riskTone(service.risk_score ?? 0)}`}>{formatNumber(service.risk_score, 0)}</span>
                    <ArrowRight className="h-3 w-3 text-muted" />
                  </div>
                </Link>
              ))}
            </div>
          )}
        </Card>

        <Card className="xl:col-span-4">
          <CardHeader title="Coverage & exposure" description="SBOM and API programme health" action={<Layers className="h-4 w-4 text-muted" />} />
          <div className="space-y-3 p-3.5">
            <div>
              <div className="mb-1 flex items-center justify-between text-2xs">
                <span className="text-muted">SBOM coverage</span>
                <span className="text-ink">{formatPercent(counts.sbom_coverage as number, 1)}</span>
              </div>
              <ProgressBar value={Number(counts.sbom_coverage ?? 0)} />
            </div>
            <div>
              <div className="mb-1 flex items-center justify-between text-2xs">
                <span className="text-muted">Remediation completed</span>
                <span className="text-ink">
                  {remediation.length ? formatNumber(remediation.find((item: any) => item.name === "completed")?.value ?? 0) : "0"}
                </span>
              </div>
              <ProgressBar
                value={(() => {
                  const total = remediation.reduce((sum: number, item: any) => sum + item.value, 0);
                  const done = remediation.find((item: any) => item.name === "completed")?.value ?? 0;
                  return total ? (done / total) * 100 : 0;
                })()}
                tone="bg-cyan"
              />
            </div>
            <div className="grid grid-cols-2 gap-2 pt-1">
              <Link to="/sbom" className="rounded border border-border bg-base/40 p-2.5 hover:border-border-strong">
                <p className="label">SBOM docs</p>
                <p className="mt-1 text-lg font-semibold text-ink">{formatNumber(counts.sbom_documents as number)}</p>
                <p className="text-[10px] text-muted">{formatNumber(sbom.data?.vulnerable_components)} vulnerable components</p>
              </Link>
              <Link to="/api-inventory" className="rounded border border-border bg-base/40 p-2.5 hover:border-border-strong">
                <p className="label">Unauthenticated APIs</p>
                <p className="mt-1 text-lg font-semibold text-critical">{formatNumber(apis.data?.unauthenticated)}</p>
                <p className="text-[10px] text-muted">{formatNumber(apis.data?.endpoints)} endpoints</p>
              </Link>
              <Link to="/attack-surface" className="rounded border border-border bg-base/40 p-2.5 hover:border-border-strong">
                <p className="label">Active scans</p>
                <p className="mt-1 text-lg font-semibold text-cyan">{formatNumber(counts.active_scans as number)}</p>
                <p className="text-[10px] text-muted">Authorized scope only</p>
              </Link>
              <Link to="/ai-triage" className="rounded border border-border bg-base/40 p-2.5 hover:border-border-strong">
                <p className="label">Recent CVEs</p>
                <p className="mt-1 text-lg font-semibold text-ink">{formatNumber(counts.recent_cves_7d as number)}</p>
                <p className="text-[10px] text-muted">Intelligence ingested 7d</p>
              </Link>
            </div>
            {apiSecurity.length ? (
              <div className="pt-1">
                <p className="label mb-1.5">API security posture</p>
                <HorizontalBars data={apiSecurity.map((item: any) => ({ ...item, name: humanize(item.name) }))} dataKey="value" labelKey="name" color="rgb(var(--atlas-accent))" height={110} />
              </div>
            ) : null}
          </div>
        </Card>

        <Card className="xl:col-span-4">
          <CardHeader title="Recent security activity" description="Latest correlated events" action={<Activity className="h-4 w-4 text-muted" />} />
          <div className="max-h-[330px] overflow-y-auto">
            {activity.isLoading ? (
              <div className="space-y-2 p-3">{Array.from({ length: 6 }).map((_, index) => <Skeleton key={index} className="h-8" />)}</div>
            ) : (activity.data?.items ?? []).length === 0 ? (
              <EmptyState title="No recent activity" className="py-8" />
            ) : (
              <div className="divide-y divide-border/50">
                {activityGroups.map(({ item, count }, index) => (
                  <div key={index} className="flex items-start gap-2.5 px-3.5 py-2">
                    <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${item.type === "finding" ? "bg-accent" : "bg-cyan"}`} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-2xs font-medium text-ink">{item.title}</p>
                      <div className="mt-0.5 flex items-center gap-1.5 text-[10px] text-muted">
                        <SeverityBadge severity={item.severity} className="px-1 py-0 text-[8px]" />
                        <span>{relativeTime(item.timestamp)}</span>
                        {count > 1 ? <span className="rounded bg-raised px-1 text-[9px]">×{count}</span> : null}
                        {item.reference ? <span className="mono">{item.reference}</span> : null}
                      </div>
                    </div>
                    {item.link ? (
                      <Link to={item.link} className="text-muted hover:text-accent">
                        <ArrowRight className="h-3 w-3" />
                      </Link>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {[
          { to: "/ai-triage", icon: BrainCircuit, title: "AI Triage", body: "Contextual analysis, deduplication and remediation guidance.", tone: "text-cyan" },
          { to: "/attack-surface", icon: Crosshair, title: "Attack Surface", body: "Authorized discovery with scope validation and audit trail.", tone: "text-high" },
          { to: "/data-classification", icon: AlertOctagon, title: "Data Classification", body: "PII, credential and secret detection with redaction.", tone: "text-accent" },
          { to: "/reports", icon: FileWarning, title: "Reports", body: "Executive, vulnerability, SBOM and remediation exports.", tone: "text-medium" },
        ].map((item) => (
          <Link key={item.to} to={item.to} className="panel flex items-start gap-3 p-3.5 transition-colors hover:border-border-strong">
            <item.icon className={`mt-0.5 h-4 w-4 ${item.tone}`} />
            <div>
              <p className="text-xs font-semibold text-ink">{item.title}</p>
              <p className="mt-0.5 text-[10px] text-muted">{item.body}</p>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
