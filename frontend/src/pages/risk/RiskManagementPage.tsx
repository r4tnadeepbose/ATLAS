import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Calculator, ClipboardCheck, ShieldOff, TriangleAlert } from "lucide-react";
import { riskApi } from "@/api/endpoints";
import { useListQuery } from "@/hooks/useListQuery";
import { useAuth } from "@/context/AuthContext";
import { PageHeader, StatCard } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Modal, Pagination, ProgressBar, SearchInput, Select, SeverityBadge, StatusBadge, Tabs, Textarea, useToast } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/table";
import { formatDate, formatNumber, relativeTime, riskTone, titleCase } from "@/utils";
import type { RemediationTask, RiskAssessment } from "@/types";

export function RiskManagementPage() {
  const toast = useToast();
  const { can } = useAuth();
  const [tab, setTab] = useState<"assessments" | "remediation">("assessments");
  const [severity, setSeverity] = useState("");
  const [accepting, setAccepting] = useState<RiskAssessment | null>(null);
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState("");

  const risks = useListQuery<RiskAssessment>(["risks"], riskApi.list, { initialSort: "score", filters: { severity: severity || undefined } });
  const tasks = useListQuery<RemediationTask>(["remediation"], riskApi.tasks, { initialSort: "created_at" });
  const summary = useQuery({ queryKey: ["risks", "summary"], queryFn: riskApi.summary });

  const recompute = useMutation({
    mutationFn: riskApi.recompute,
    onSuccess: (result) => {
      toast.push({ title: "Risk recomputed", description: `${result.updated} assessments updated.`, tone: "success" });
      risks.refetch();
      summary.refetch();
    },
    onError: (error: Error) => toast.push({ title: "Recompute failed", description: error.message, tone: "error" }),
  });

  const accept = useMutation({
    mutationFn: () => riskApi.accept(accepting!.id, reason, expires || undefined),
    onSuccess: () => {
      toast.push({ title: "Risk accepted", description: "An exception has been recorded with audit context.", tone: "success" });
      setAccepting(null);
      setReason("");
      setExpires("");
      risks.refetch();
      summary.refetch();
    },
    onError: (error: Error) => toast.push({ title: "Acceptance failed", description: error.message, tone: "error" }),
  });

  const riskColumns: Column<RiskAssessment>[] = [
    {
      key: "finding",
      label: "Risk / finding",
      render: (risk) => (
        <div className="min-w-0 max-w-[300px]">
          <p className="truncate text-sm font-medium text-ink">{risk.finding_title || risk.finding_ref || "Asset-level risk"}</p>
          <p className="mono text-muted">{risk.finding_ref || risk.id.slice(0, 8)}</p>
        </div>
      ),
    },
    {
      key: "score",
      label: "Score",
      sortable: true,
      render: (risk) => (
        <div className="flex items-center gap-2">
          <span className={`text-sm font-semibold tabular-nums ${riskTone(risk.score)}`}>{formatNumber(risk.score, 0)}</span>
          <SeverityBadge severity={risk.severity} />
        </div>
      ),
    },
    {
      key: "ownership",
      label: "Ownership",
      render: (risk) => (
        <div className="min-w-0">
          <p className="truncate text-xs text-ink">{risk.business_unit || "Unassigned unit"}</p>
          <p className="truncate text-[10px] text-muted">{risk.responsible_team || "No owner"}</p>
        </div>
      ),
    },
    { key: "status", label: "Status", render: (risk) => <StatusBadge status={risk.status} /> },
    {
      key: "deadline",
      label: "Deadline",
      render: (risk) => {
        const overdue = risk.remediation_deadline && new Date(risk.remediation_deadline).getTime() < Date.now() && risk.status !== "closed";
        return <span className={`whitespace-nowrap text-2xs ${overdue ? "text-critical" : "text-muted"}`}>{formatDate(risk.remediation_deadline)}</span>;
      },
    },
    {
      key: "actions",
      label: "",
      align: "right",
      render: (risk) => can("risks:write") ? (
        <div className="flex justify-end gap-1">
          <Button variant="ghost" size="sm" onClick={(event) => { event.stopPropagation(); setAccepting(risk); setReason(""); }}>Accept</Button>
        </div>
      ) : null,
    },
  ];

  const taskColumns: Column<RemediationTask>[] = [
    { key: "title", label: "Task", render: (task) => <div><p className="text-sm text-ink">{task.title}</p><p className="text-2xs text-muted">{task.description || "No detail"}</p></div> },
    { key: "priority", label: "Priority", render: (task) => <SeverityBadge severity={task.priority} /> },
    { key: "status", label: "Status", render: (task) => <StatusBadge status={task.status} /> },
    { key: "due_at", label: "Due", render: (task) => <span className="text-2xs text-muted">{formatDate(task.due_at)}</span> },
    {
      key: "actions",
      label: "",
      align: "right",
      render: (task) => task.status !== "completed" && can("risks:write") ? (
        <Button variant="outline" size="sm" onClick={async () => { await riskApi.updateTask(task.id, { status: "completed" }); toast.push({ title: "Remediation completed", tone: "success" }); tasks.refetch(); risks.refetch(); }}>Complete</Button>
      ) : <Badge tone="border-accent/30 bg-accent/10 text-accent">{task.status === "completed" ? "done" : task.status}</Badge>,
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Security Operations"
        title="Risk Management"
        description="Documented, deterministic risk scoring across all modules. AI explains context but never sets the score."
        actions={can("risks:write") ? <Button variant="primary" size="sm" loading={recompute.isPending} onClick={() => recompute.mutate()}><Calculator className="h-3.5 w-3.5" /> Recompute risks</Button> : undefined}
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Assessments" value={formatNumber(summary.data?.total)} icon={<TriangleAlert className="h-4 w-4" />} hint="Open and historical" />
        <StatCard label="Average score" value={formatNumber(summary.data?.average_score, 1)} tone={riskTone(summary.data?.average_score ?? 0)} hint="atlas-risk-v1" />
        <StatCard label="Critically exposed" value={formatNumber(summary.data?.critically_exposed)} tone="critical" hint="Score ≥ 85" />
        <StatCard label="Risk accepted" value={formatNumber(summary.data?.accepted)} tone="medium" icon={<ShieldOff className="h-4 w-4" />} hint="Documented exceptions" />
      </div>

      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-4">
        <Card className="xl:col-span-3">
          <div className="flex items-center gap-1 border-b border-border px-3">
            {[{ key: "assessments", label: "Risk register" }, { key: "remediation", label: "Remediation tasks" }].map((item) => (
              <button key={item.key} onClick={() => setTab(item.key as any)} className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === item.key ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink"}`}>{item.label}</button>
            ))}
          </div>
          {tab === "assessments" ? (
            <DataTable
              columns={riskColumns}
              rows={risks.rows}
              rowKey={(risk) => risk.id}
              loading={risks.isLoading}
              error={risks.error}
              onRetry={() => risks.refetch()}
              sortBy={risks.sortBy}
              sortDir={risks.sortDir}
              onSort={risks.onSort}
              toolbar={
                <>
                  <SearchInput value={risks.q} onChange={risks.setQ} placeholder="Search risk register…" className="w-64" />
                  <Select value={severity} onChange={(event) => setSeverity(event.target.value)} className="h-8 w-[130px] text-xs">
                    <option value="">All bands</option>
                    {["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
                  </Select>
                </>
              }
              footer={risks.pagination ? <Pagination page={risks.page} pages={risks.pagination.pages} total={risks.pagination.total} pageSize={risks.pageSize} onPage={risks.setPage} onPageSize={risks.setPageSize} /> : null}
              emptyTitle="No risk assessments"
              emptyDescription="Run recompute to generate assessments from current findings."
            />
          ) : (
            <DataTable
              columns={taskColumns}
              rows={tasks.rows}
              rowKey={(task) => task.id}
              loading={tasks.isLoading}
              error={tasks.error}
              onRetry={() => tasks.refetch()}
              toolbar={<SearchInput value={tasks.q} onChange={tasks.setQ} placeholder="Search remediation tasks…" className="w-64" />}
              footer={tasks.pagination ? <Pagination page={tasks.page} pages={tasks.pagination.pages} total={tasks.pagination.total} pageSize={tasks.pageSize} onPage={tasks.setPage} onPageSize={tasks.setPageSize} /> : null}
              emptyTitle="No remediation tasks"
              emptyDescription="Tasks are generated for each assessed finding."
            />
          )}
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader title="Score by business unit" description="Average risk per unit" />
            <div className="space-y-2 p-3.5">
              {(summary.data?.by_business_unit ?? []).map((unit: any) => (
                <div key={unit.name}>
                  <div className="mb-1 flex items-center justify-between text-2xs"><span className="text-muted">{unit.name}</span><span className="text-ink">{formatNumber(unit.value, 1)}</span></div>
                  <ProgressBar value={unit.value} tone={unit.value >= 85 ? "bg-critical" : unit.value >= 65 ? "bg-high" : unit.value >= 40 ? "bg-medium" : "bg-accent"} />
                </div>
              ))}
              {(summary.data?.by_business_unit ?? []).length === 0 ? <EmptyState title="No business unit data" className="py-6" /> : null}
            </div>
          </Card>
          <Card>
            <CardHeader title="Scoring model" description="atlas-risk-v1 · deterministic" action={<ClipboardCheck className="h-4 w-4 text-muted" />} />
            <div className="space-y-1.5 p-3.5 text-2xs text-muted">
              <p>Base severity weights, exposure, asset criticality, known exploitation, sensitive data, missing authentication, age and fix availability.</p>
              <p>Final score is clamped to 0–100. Bands: critical ≥85, high ≥65, medium ≥40, low ≥15.</p>
              <p>AI triage may explain but never determine the authoritative score.</p>
              <p className="mono text-[10px] text-muted/70">SLA: critical 7d · high 30d · medium 90d · low 180d</p>
            </div>
          </Card>
        </div>
      </div>

      <Modal
        open={Boolean(accepting)}
        onClose={() => setAccepting(null)}
        title="Accept residual risk"
        description={accepting ? `${accepting.finding_title || accepting.finding_ref || "Assessment"} · score ${formatNumber(accepting.score, 0)}` : ""}
        footer={<><Button variant="ghost" onClick={() => setAccepting(null)}>Cancel</Button><Button variant="primary" loading={accept.isPending} disabled={reason.trim().length < 5} onClick={() => accept.mutate()}>Record acceptance</Button></>}
      >
        <div className="space-y-3">
          <Field label="Justification" hint="Recorded in the risk exception register and audit log.">
            <Textarea rows={4} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Compensating controls, business constraint, approval reference…" />
          </Field>
          <Field label="Exception expiry (optional)"><Input type="date" value={expires} onChange={(event) => setExpires(event.target.value)} /></Field>
        </div>
      </Modal>
    </div>
  );
}
