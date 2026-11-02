import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Gauge, ShieldCheck, TimerReset, TrendingUp } from "lucide-react";
import { dashboardApi } from "@/api/endpoints";
import { ExecutiveLayout } from "@/layouts/AuthLayout";
import { PageHeader, StatCard } from "@/components/common/PageHeader";
import { Card, CardHeader, ErrorState, ProgressBar, SeverityBadge, StatusBadge } from "@/components/ui/primitives";
import { PostureGauge, TrendArea, TrendLines, SeverityStackedBars } from "@/components/charts";
import { formatNumber, formatPercent, riskTone } from "@/utils";

export function ExecutivePage() {
  const executive = useQuery({ queryKey: ["dashboard", "executive"], queryFn: dashboardApi.executive });

  if (executive.isLoading) return <div className="panel mt-4 h-96 animate-pulse" />;
  if (executive.isError) return <ErrorState message={(executive.error as Error).message} retry={() => executive.refetch()} className="panel mt-10" />;
  const data = executive.data!;
  const counts = data.counts ?? {};

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Reporting"
        title="Executive Intelligence"
        description="Business risk, programme coverage and remediation performance — with drill-through to technical detail."
      />

      <ExecutiveLayout>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
          <StatCard label="Security posture" value={formatPercent(counts.posture_score, 0)} icon={<Gauge className="h-4 w-4" />} tone="accent" hint="Derived from open risk" />
          <StatCard label="Organizational risk" value={formatNumber(data.average_risk ?? counts.average_risk, 0)} tone="high" hint="Mean assessment score" />
          <StatCard label="Critical business risks" value={formatNumber(counts.open_incidents)} tone="critical" hint="High + critical open" />
          <StatCard label="MTTD" value={counts.mttd_minutes == null ? "—" : `${formatNumber(counts.mttd_minutes, 1)}m`} icon={<TimerReset className="h-4 w-4" />} tone="cyan" hint="Intelligence → finding" />
          <StatCard label="MTTR" value={counts.mttr_hours == null ? "—" : `${formatNumber(counts.mttr_hours, 1)}h`} icon={<TrendingUp className="h-4 w-4" />} hint="Mean time to resolve" />
          <StatCard label="SBOM coverage" value={formatPercent(counts.sbom_coverage, 1)} icon={<ShieldCheck className="h-4 w-4" />} hint={`${counts.sbom_documents ?? 0} documents`} />
        </div>

        <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-12">
          <Card className="xl:col-span-3">
            <CardHeader title="Posture" description="Board-level security health" />
            <div className="p-3">
              <PostureGauge score={Number(counts.posture_score ?? 0)} height={190} />
              <div className="mt-2 grid grid-cols-2 gap-2 text-2xs">
                <div className="rounded border border-border bg-base/40 p-2"><p className="label">Resolved 7d</p><p className="mt-1 text-base font-semibold text-accent">{counts.findings_resolved_7d ?? 0}</p></div>
                <div className="rounded border border-border bg-base/40 p-2"><p className="label">New 7d</p><p className="mt-1 text-base font-semibold text-medium">{counts.findings_created_7d ?? 0}</p></div>
              </div>
            </div>
          </Card>
          <div className="xl:col-span-5">
            <ChartFrame title="Security trend" description="Posture and open findings" height={280}>
              {(data.posture_trend ?? []).length ? (
                <div className="flex h-full flex-col">
                  <div className="h-1/2"><TrendArea data={data.posture_trend} dataKey="posture" xKey="week" color="#36D399" height={125} yDomain={[0, 100]} /></div>
                  <div className="h-1/2"><TrendArea data={data.posture_trend} dataKey="open_findings" xKey="week" color="#38BDF8" height={125} /></div>
                </div>
              ) : <p className="px-3 text-xs text-muted">Trend appears after several weeks of data.</p>}
            </ChartFrame>
          </div>
          <Card className="xl:col-span-4">
            <CardHeader title="Risk by business unit" description="Average residual risk score" />
            <div className="space-y-3 p-4">
              {(data.risk_by_unit ?? []).map((unit: any) => (
                <div key={unit.name}>
                  <div className="mb-1 flex items-center justify-between text-2xs">
                    <span className="text-muted">{unit.name}</span>
                    <span className="text-ink">{formatNumber(unit.average, 1)} · {unit.count} assessment{unit.count === 1 ? "" : "s"}</span>
                  </div>
                  <ProgressBar value={unit.average} tone={unit.average >= 85 ? "bg-critical" : unit.average >= 65 ? "bg-high" : unit.average >= 40 ? "bg-medium" : "bg-accent"} />
                </div>
              ))}
              {(data.risk_by_unit ?? []).length === 0 ? <p className="text-xs text-muted">No open assessments recorded.</p> : null}
            </div>
          </Card>
        </div>

        <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-2">
          <Card>
            <CardHeader title="Top business risks" description="Highest scoring assessments" action={<Link to="/risk-management" className="text-2xs text-muted hover:text-accent">Risk register</Link>} />
            <div className="divide-y divide-border/50">
              {(data.top_risks ?? []).map((risk: any) => (
                <div key={risk.id} className="flex items-center gap-3 px-4 py-2.5">
                  <span className={`w-9 text-lg font-semibold tabular-nums ${riskTone(risk.score)}`}>{formatNumber(risk.score, 0)}</span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-xs text-ink">{risk.title || risk.business_impact || "Risk assessment"}</p>
                    <p className="text-[10px] text-muted">{risk.business_unit || "unassigned unit"}{risk.finding_ref ? ` · ${risk.finding_ref}` : ""}</p>
                  </div>
                  <StatusBadge status={risk.status} />
                </div>
              ))}
              {(data.top_risks ?? []).length === 0 ? <p className="px-4 py-6 text-xs text-muted">No assessments yet.</p> : null}
            </div>
          </Card>
          <Card>
            <CardHeader title="High-risk exposed services" description="Services carrying the most risk" action={<Link to="/microservices" className="text-2xs text-muted hover:text-accent">Service map</Link>} />
            <div className="divide-y divide-border/50">
              {(data.top_services ?? []).map((service: any) => (
                <div key={service.id} className="flex items-center gap-3 px-4 py-2.5">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-xs text-ink">{service.name}</p>
                    <p className="text-[10px] text-muted">{service.business_unit} · {service.open_findings} open</p>
                  </div>
                  <SeverityBadge severity={service.criticality} />
                  <span className={`w-8 text-right text-xs font-semibold ${riskTone(service.risk_score)}`}>{formatNumber(service.risk_score, 0)}</span>
                </div>
              ))}
              {(data.top_services ?? []).length === 0 ? <p className="px-4 py-6 text-xs text-muted">No service risk data yet.</p> : null}
            </div>
          </Card>
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <ChartFrame title="Remediation performance" description="Task completion state" height={220}>
            <RemediationBars data={data.remediation ?? []} />
          </ChartFrame>
          <ChartFrame title="Risk score trend" description="Average assessment score over time" height={220}>
            <TrendLines data={data.risk_trends ?? []} series={[{ key: "average_score", color: "#FB923C", label: "Average score" }]} />
          </ChartFrame>
        </div>

        <p className="text-[10px] text-muted/70">
          Definitions: posture = 100 − average open finding risk; MTTD = intelligence ingestion to finding generation; MTTR = finding first seen to resolution. All metrics are computed from organization-scoped records.
        </p>
      </ExecutiveLayout>
    </div>
  );
}

function ChartFrame({ title, description, height, children }: { title: string; description: string; height: number; children: React.ReactNode }) {
  return (
    <div className="panel flex flex-col">
      <div className="px-3.5 py-2.5">
        <p className="text-xs font-semibold text-ink">{title}</p>
        <p className="text-[10px] text-muted">{description}</p>
      </div>
      <div style={{ height }} className="px-1 pb-2">{children}</div>
    </div>
  );
}

function RemediationBars({ data }: { data: { name: string; value: number }[] }) {
  const total = data.reduce((sum, item) => sum + item.value, 0);
  if (!total) return <p className="px-3 py-8 text-center text-xs text-muted">No remediation tasks yet.</p>;
  const completed = data.find((item) => item.name === "completed")?.value ?? 0;
  const open = total - completed;
  return (
    <div className="space-y-2 px-4 py-2">
      <div className="mb-2 grid grid-cols-3 gap-2 text-center">
        <div className="rounded border border-border bg-base/40 p-1.5"><p className="label">Open</p><p className="text-base font-semibold text-medium">{open}</p></div>
        <div className="rounded border border-border bg-base/40 p-1.5"><p className="label">Completed</p><p className="text-base font-semibold text-accent">{completed}</p></div>
        <div className="rounded border border-border bg-base/40 p-1.5"><p className="label">Rate</p><p className="text-base font-semibold text-ink">{Math.round((completed / total) * 100)}%</p></div>
      </div>
      {data.map((item) => (
        <div key={item.name}>
          <div className="mb-1 flex items-center justify-between text-2xs"><span className="capitalize text-muted">{item.name}</span><span className="text-ink">{item.value}</span></div>
          <ProgressBar value={(item.value / total) * 100} tone={item.name === "completed" ? "bg-accent" : "bg-cyan"} />
        </div>
      ))}
    </div>
  );
}
