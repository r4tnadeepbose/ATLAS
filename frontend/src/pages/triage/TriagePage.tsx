import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BrainCircuit, Info, Sparkles } from "lucide-react";
import { triageApi } from "@/api/endpoints";
import { useListQuery } from "@/hooks/useListQuery";
import { useAuth } from "@/context/AuthContext";
import { PageHeader, StatCard } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, EmptyState, Modal, Pagination, ProgressBar, SearchInput, SeverityBadge, StatusBadge, Tabs, useToast } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/table";
import { formatNumber, formatPercent, relativeTime, riskTone } from "@/utils";
import type { Finding, TriageResult } from "@/types";

export function TriagePage() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const { can } = useAuth();
  const [tab, setTab] = useState<"queue" | "results">("queue");
  const [selected, setSelected] = useState<TriageResult | null>(null);
  const [batchRunning, setBatchRunning] = useState(false);

  const dashboard = useQuery({ queryKey: ["triage", "dashboard"], queryFn: triageApi.dashboard });
  const queue = useListQuery<Finding>(["triage", "queue"], triageApi.queue, { initialSort: "risk_score" });
  const results = useListQuery<TriageResult>(["triage", "results"], triageApi.results, { initialSort: "created_at" });
  const config = useQuery({ queryKey: ["triage", "config"], queryFn: triageApi.config });

  const analyze = useMutation({
    mutationFn: (findingId: string) => triageApi.analyze(findingId),
    onSuccess: (result) => {
      toast.push({ title: "Triage complete", description: `${result.provider} · confidence ${formatPercent(result.confidence * 100, 0)}`, tone: "success" });
      setSelected(result);
      queryClient.invalidateQueries({ queryKey: ["triage"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (error: Error) => toast.push({ title: "Triage failed", description: error.message, tone: "error" }),
  });

  const runBatch = async () => {
    const ids = queue.rows.slice(0, 10).map((finding) => finding.id);
    if (!ids.length) return;
    setBatchRunning(true);
    try {
      await triageApi.batch(ids);
      toast.push({ title: `Triaged ${ids.length} findings`, tone: "success" });
      queryClient.invalidateQueries({ queryKey: ["triage"] });
    } catch (error) {
      toast.push({ title: "Batch triage failed", description: (error as Error).message, tone: "error" });
    } finally {
      setBatchRunning(false);
    }
  };

  const queueColumns: Column<Finding>[] = [
    {
      key: "title",
      label: "Finding",
      render: (finding) => (
        <div className="min-w-0">
          <Link to={`/vulnerabilities/${finding.id}`} className="text-sm font-medium text-ink hover:text-accent">{finding.title}</Link>
          <p className="mono text-muted">{finding.finding_ref} · {finding.category.replace("_", " ")}</p>
        </div>
      ),
    },
    { key: "severity", label: "Severity", render: (finding) => <SeverityBadge severity={finding.severity} /> },
    { key: "microservice_name", label: "Service", render: (finding) => finding.microservice_name || finding.asset_name || "unlinked" },
    { key: "exposure", label: "Exposure", render: (finding) => <Badge tone={finding.exposure === "public" ? "border-critical/30 bg-critical/10 text-critical" : undefined}>{finding.exposure}</Badge> },
    { key: "risk_score", label: "Risk", sortable: true, render: (finding) => <span className={`font-semibold tabular-nums ${riskTone(finding.risk_score)}`}>{formatNumber(finding.risk_score, 0)}</span> },
    { key: "first_seen", label: "Age", render: (finding) => <span className="text-2xs text-muted">{relativeTime(finding.first_seen)}</span> },
    {
      key: "action",
      label: "",
      align: "right",
      render: (finding) => can("findings:triage") ? (
        <Button variant="outline" size="sm" loading={analyze.isPending && analyze.variables === finding.id} onClick={(event) => { event.stopPropagation(); analyze.mutate(finding.id); }}>
          <Sparkles className="h-3 w-3" /> Analyze
        </Button>
      ) : <span className="text-2xs text-muted">read-only</span>,
    },
  ];

  const resultColumns: Column<TriageResult>[] = [
    {
      key: "finding",
      label: "Finding",
      render: (result) => (
        <div className="min-w-0">
          <p className="truncate text-sm font-medium text-ink">{result.finding_title || result.finding_ref || "Finding"}</p>
          <p className="mono text-muted">{result.classification || "unclassified"}</p>
        </div>
      ),
    },
    { key: "provider", label: "Provider", render: (result) => <Badge tone={result.provider === "heuristic" ? "border-medium/30 bg-medium/10 text-medium" : "border-cyan/30 bg-cyan/10 text-cyan"}>{result.provider}</Badge> },
    { key: "priority", label: "Priority", render: (result) => <SeverityBadge severity={result.priority} /> },
    {
      key: "confidence",
      label: "Confidence",
      render: (result) => (
        <div className="w-20">
          <div className="mb-0.5 flex justify-between text-[9px] text-muted"><span>{formatPercent(result.confidence * 100, 0)}</span><span>FP {formatPercent(result.false_positive_likelihood * 100, 0)}</span></div>
          <ProgressBar value={result.confidence * 100} tone="bg-cyan" />
        </div>
      ),
    },
    { key: "latency_ms", label: "Latency", align: "right", render: (result) => <span className="tabular-nums text-muted">{result.latency_ms} ms</span> },
    { key: "created_at", label: "Created", sortable: true, render: (result) => <span className="text-2xs text-muted">{relativeTime(result.created_at)}</span> },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Intelligence"
        title="AI Triage"
        description="Provider-independent, advisory-only analysis. Findings are never modified or closed by the model."
        actions={
          <div className="flex items-center gap-2">
            <Badge tone="border-cyan/30 bg-cyan/10 text-cyan">{config.data?.environment_provider || "none"}</Badge>
            {can("findings:triage") ? (
              <Button variant="primary" size="sm" loading={batchRunning} onClick={runBatch} disabled={queue.rows.length === 0}>
                <BrainCircuit className="h-3.5 w-3.5" /> Triage {Math.min(10, queue.rows.length) || "batch"}
              </Button>
            ) : null}
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Open findings" value={formatNumber(dashboard.data?.open_findings)} icon={<BrainCircuit className="h-4 w-4" />} hint="Awaiting analysis" />
        <StatCard label="Triaged" value={formatNumber(dashboard.data?.triaged)} tone="cyan" hint="Advisory results stored" />
        <StatCard label="Pending" value={formatNumber(dashboard.data?.pending)} tone="medium" hint="Queue depth" />
        <StatCard label="Avg confidence" value={formatPercent((dashboard.data?.average_confidence ?? 0) * 100, 0)} hint="Across provider results" />
      </div>

      <div className="flex items-start gap-2 rounded-md border border-border bg-surface/60 px-3 py-2">
        <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan" />
        <p className="text-2xs text-muted">
          AI output is advisory intelligence. It cannot execute remediation, change severity automatically or close findings. When no LLM is configured, ATLAS
          produces deterministic heuristic context labelled <span className="text-medium">heuristic</span>.
        </p>
      </div>

      <Tabs tabs={[{ key: "queue", label: "Triage queue", count: queue.pagination?.total }, { key: "results", label: "Analysis history", count: results.pagination?.total }]} value={tab} onChange={(key) => setTab(key as any)} />

      {tab === "queue" ? (
        <Card>
          <DataTable
            columns={queueColumns}
            rows={queue.rows}
            rowKey={(finding) => finding.id}
            loading={queue.isLoading}
            error={queue.error}
            onRetry={() => queue.refetch()}
            sortBy={queue.sortBy}
            sortDir={queue.sortDir}
            onSort={queue.onSort}
            toolbar={<SearchInput value={queue.q} onChange={queue.setQ} placeholder="Search untriaged findings…" className="w-72" />}
            footer={queue.pagination ? <Pagination page={queue.page} pages={queue.pagination.pages} total={queue.pagination.total} pageSize={queue.pageSize} onPage={queue.setPage} onPageSize={queue.setPageSize} /> : null}
            emptyTitle="Queue is clear"
            emptyDescription="Every open finding has been analysed. New findings will appear here automatically."
          />
        </Card>
      ) : (
        <Card>
          <DataTable
            columns={resultColumns}
            rows={results.rows}
            rowKey={(result) => result.id}
            loading={results.isLoading}
            error={results.error}
            onRetry={() => results.refetch()}
            sortBy={results.sortBy}
            sortDir={results.sortDir}
            onSort={results.onSort}
            onRowClick={(result) => setSelected(result)}
            toolbar={<SearchInput value={results.q} onChange={results.setQ} placeholder="Search analysis history…" className="w-72" />}
            footer={results.pagination ? <Pagination page={results.page} pages={results.pagination.pages} total={results.pagination.total} pageSize={results.pageSize} onPage={results.setPage} onPageSize={results.setPageSize} /> : null}
            emptyTitle="No analyses yet"
            emptyDescription="Run triage from the queue to build analysis history."
          />
        </Card>
      )}

      <Card>
        <CardHeader title="Provider configuration" description="Runtime configuration is environment-driven; per-tenant defaults can override" />
        <div className="grid gap-3 p-4 md:grid-cols-3">
          <div><p className="label">Environment provider</p><p className="mt-1 text-sm text-ink">{config.data?.environment_provider}</p></div>
          <div><p className="label">Environment model</p><p className="mt-1 text-sm text-ink">{config.data?.environment_model}</p></div>
          <div><p className="label">Tenant defaults</p><p className="mt-1 text-sm text-ink">{config.data?.configurations?.length ?? 0} configured</p></div>
        </div>
      </Card>

      <Modal open={Boolean(selected)} onClose={() => setSelected(null)} title="AI triage analysis" description={selected ? `${selected.provider} · ${selected.model || "—"}` : ""} size="lg" footer={<Button variant="ghost" onClick={() => setSelected(null)}>Close</Button>}>
        {selected ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={selected.priority} />
              <Badge tone={selected.provider === "heuristic" ? "border-medium/30 bg-medium/10 text-medium" : "border-cyan/30 bg-cyan/10 text-cyan"}>{selected.provider}</Badge>
              <Badge>confidence {formatPercent(selected.confidence * 100, 0)}</Badge>
              <Badge>false positive {formatPercent(selected.false_positive_likelihood * 100, 0)}</Badge>
              {selected.advisory_only ? <Badge tone="border-border-strong bg-raised text-muted">advisory only</Badge> : null}
            </div>
            {[
              ["Summary", selected.summary],
              ["Technical impact", selected.technical_impact],
              ["Business impact", selected.business_impact],
              ["Recommendation", selected.recommendation],
            ].map(([label, value]) => (
              <div key={label as string}>
                <p className="label mb-1">{label as string}</p>
                <p className="text-sm leading-relaxed text-ink/90">{value || "—"}</p>
              </div>
            ))}
            <div className="grid grid-cols-3 gap-2 border-t border-border pt-3 text-2xs text-muted">
              <span>Tokens in: <span className="text-ink">{selected.tokens_input}</span></span>
              <span>Tokens out: <span className="text-ink">{selected.tokens_output}</span></span>
              <span>Latency: <span className="text-ink">{selected.latency_ms} ms</span></span>
            </div>
            <p className="rounded border border-border bg-base/50 px-2.5 py-2 text-2xs text-muted">
              Evidence is limited to the finding context supplied to the analyser. Verify applicability before remediation.
            </p>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
