import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Fingerprint, ScanLine, ShieldCheck } from "lucide-react";
import { classificationApi, assetApi, serviceApi } from "@/api/endpoints";
import { useListQuery } from "@/hooks/useListQuery";
import { useAuth } from "@/context/AuthContext";
import { PageHeader, StatCard } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Modal, Pagination, SearchInput, Select, SeverityBadge, Switch, Textarea, useToast } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/table";
import { HorizontalBars } from "@/components/charts";
import { categoryLabel, formatDateTime, formatNumber, formatPercent, humanize, relativeTime, titleCase } from "@/utils";
import type { Classification, ClassificationRule } from "@/types";

export function ClassificationPage() {
  const toast = useToast();
  const { can } = useAuth();
  const [tab, setTab] = useState<"results" | "rules">("results");
  const [analyzeOpen, setAnalyzeOpen] = useState(false);
  const [text, setText] = useState("");
  const [sourceLabel, setSourceLabel] = useState("manual submission");
  const [assetId, setAssetId] = useState("");
  const [serviceId, setServiceId] = useState("");
  const [ruleOpen, setRuleOpen] = useState(false);
  const [ruleForm, setRuleForm] = useState({ name: "", category: "pii", detection_method: "regex", pattern: "", severity: "medium" });

  const list = useListQuery<Classification>(["classification"], classificationApi.list, { initialSort: "created_at" });
  const dashboard = useQuery({ queryKey: ["classification", "dashboard"], queryFn: classificationApi.dashboard });
  const rules = useQuery({ queryKey: ["classification", "rules"], queryFn: classificationApi.rules });
  const assets = useQuery({ queryKey: ["assets", "options"], queryFn: () => assetApi.list({ page_size: 200 }) });
  const services = useQuery({ queryKey: ["microservices", "options"], queryFn: () => serviceApi.list({ page_size: 200 }) });

  const analyze = useMutation({
    mutationFn: () => classificationApi.analyze({ text, source_label: sourceLabel, asset_id: assetId || undefined, microservice_id: serviceId || undefined }),
    onSuccess: (result) => {
      toast.push({ title: `${result.detections} detections`, description: `${result.created_findings} findings created · values redacted`, tone: result.detections ? "success" : "info" });
      setAnalyzeOpen(false);
      setText("");
      list.refetch();
      dashboard.refetch();
    },
    onError: (error: Error) => toast.push({ title: "Analysis failed", description: error.message, tone: "error" }),
  });

  const createRule = useMutation({
    mutationFn: () => classificationApi.createRule(ruleForm),
    onSuccess: () => {
      toast.push({ title: "Rule created", tone: "success" });
      setRuleOpen(false);
      setRuleForm({ name: "", category: "pii", detection_method: "regex", pattern: "", severity: "medium" });
      rules.refetch();
    },
    onError: (error: Error) => toast.push({ title: "Rule rejected", description: error.message, tone: "error" }),
  });

  const columns: Column<Classification>[] = [
    {
      key: "category",
      label: "Category",
      render: (item) => (
        <div>
          <p className="text-sm font-medium text-ink">{categoryLabel(item.category)}</p>
          <p className="mono text-muted">{item.detection_method}</p>
        </div>
      ),
    },
    { key: "service_name", label: "Source", render: (item) => item.service_name || "—" },
    { key: "exposure_location", label: "Location", render: (item) => <span className="mono max-w-[280px] truncate text-[10px] text-muted">{item.exposure_location || "—"}</span> },
    { key: "risk_classification", label: "Risk", render: (item) => <SeverityBadge severity={item.risk_classification} /> },
    { key: "confidence", label: "Confidence", align: "right", render: (item) => <span className="tabular-nums">{formatPercent(item.confidence * 100, 0)}</span> },
    { key: "last_seen", label: "Detected", render: (item) => <span className="text-2xs text-muted">{relativeTime(item.last_seen || item.created_at)}</span> },
  ];

  const ruleColumns: Column<ClassificationRule>[] = [
    { key: "name", label: "Rule", render: (rule) => <div><p className="text-sm text-ink">{rule.name}</p><p className="mono text-muted">{rule.category} · {rule.detection_method}</p></div> },
    { key: "pattern", label: "Pattern", render: (rule) => <span className="mono max-w-[320px] truncate text-[10px] text-muted">{rule.pattern || "—"}</span> },
    { key: "severity", label: "Severity", render: (rule) => <SeverityBadge severity={rule.severity} /> },
    { key: "confidence_weight", label: "Weight", align: "right", render: (rule) => <span className="tabular-nums">{formatPercent(rule.confidence_weight * 100, 0)}</span> },
    {
      key: "enabled",
      label: "Enabled",
      render: (rule) => can("classification:write") ? (
        <Switch checked={rule.enabled} onChange={async (value) => { await classificationApi.updateRule(rule.id, { enabled: value }); rules.refetch(); }} />
      ) : <Badge>{rule.enabled ? "enabled" : "disabled"}</Badge>,
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Intelligence"
        title="Data Classification"
        description="PII, financial, credential and secret discovery with mandatory redaction of detected values."
        actions={
          <>
            {can("classification:write") ? <Button variant="ghost" size="sm" onClick={() => setRuleOpen(true)}><ShieldCheck className="h-3.5 w-3.5" /> New rule</Button> : null}
            {can("classification:write") ? <Button variant="primary" size="sm" onClick={() => setAnalyzeOpen(true)}><ScanLine className="h-3.5 w-3.5" /> Analyze content</Button> : null}
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Detections" value={formatNumber(dashboard.data?.total)} icon={<Fingerprint className="h-4 w-4" />} hint="Stored classifications" />
        <StatCard label="Credentials & tokens" value={formatNumber(dashboard.data?.credentials)} tone="critical" hint="Rotate immediately" />
        <StatCard label="PII" value={formatNumber(dashboard.data?.pii)} tone="high" hint="Personal data exposure" />
        <StatCard label="Active rules" value={formatNumber(dashboard.data?.rules)} hint="Regex + entropy" />
      </div>

      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-4">
        <Card className="xl:col-span-3">
          <div className="flex items-center gap-1 border-b border-border px-3">
            {[{ key: "results", label: "Classification results" }, { key: "rules", label: "Detection rules" }].map((item) => (
              <button key={item.key} onClick={() => setTab(item.key as any)} className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === item.key ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink"}`}>{item.label}</button>
            ))}
          </div>
          {tab === "results" ? (
            <DataTable
              columns={columns}
              rows={list.rows}
              rowKey={(item) => item.id}
              loading={list.isLoading}
              error={list.error}
              onRetry={() => list.refetch()}
              toolbar={<SearchInput value={list.q} onChange={list.setQ} placeholder="Search classifications…" className="w-64" />}
              footer={list.pagination ? <Pagination page={list.page} pages={list.pagination.pages} total={list.pagination.total} pageSize={list.pageSize} onPage={list.setPage} onPageSize={list.setPageSize} /> : null}
              emptyTitle="No classifications yet"
              emptyDescription="Submit content for analysis to detect PII, credentials and secrets."
            />
          ) : (
            <DataTable
              columns={ruleColumns}
              rows={rules.data?.items ?? []}
              rowKey={(rule) => rule.id}
              loading={rules.isLoading}
              error={rules.error}
              onRetry={() => rules.refetch()}
              emptyTitle="No rules configured"
              emptyAction={can("classification:write") ? <Button variant="primary" size="sm" onClick={() => classificationApi.seedRules().then(() => rules.refetch())}>Install default rules</Button> : undefined}
            />
          )}
        </Card>
        <div className="space-y-4">
          <Card>
            <CardHeader title="By category" description="Detected data classes" />
            <div className="p-3"><HorizontalBars data={(dashboard.data?.by_category ?? []).map((item: any) => ({ ...item, name: categoryLabel(item.name) }))} dataKey="value" labelKey="name" color="#36D399" height={170} /></div>
          </Card>
          <Card>
            <CardHeader title="Detection method" description="Rule type coverage" />
            <div className="p-3"><HorizontalBars data={(dashboard.data?.by_method ?? []).map((item: any) => ({ ...item, name: humanize(item.name) }))} dataKey="value" labelKey="name" color="#38BDF8" height={130} /></div>
          </Card>
        </div>
      </div>

      <Modal
        open={analyzeOpen}
        onClose={() => setAnalyzeOpen(false)}
        title="Analyze sensitive content"
        description="Detected values are redacted before storage. Never paste live production secrets."
        size="lg"
        footer={<><Button variant="ghost" onClick={() => setAnalyzeOpen(false)}>Cancel</Button><Button variant="primary" loading={analyze.isPending} disabled={!text.trim()} onClick={() => analyze.mutate()}>Analyze</Button></>}
      >
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Field label="Source label"><Input value={sourceLabel} onChange={(event) => setSourceLabel(event.target.value)} /></Field>
            <Field label="Owning microservice">
              <Select value={serviceId} onChange={(event) => setServiceId(event.target.value)}>
                <option value="">Unlinked</option>
                {(services.data?.items ?? []).map((service) => <option key={service.id} value={service.id}>{service.name}</option>)}
              </Select>
            </Field>
            <Field label="Asset" className="col-span-2">
              <Select value={assetId} onChange={(event) => setAssetId(event.target.value)}>
                <option value="">No asset context</option>
                {(assets.data?.items ?? []).map((asset) => <option key={asset.id} value={asset.id}>{asset.name}</option>)}
              </Select>
            </Field>
          </div>
          <Field label="Content" hint="Regex + entropy detection. Values are masked in all responses.">
            <Textarea rows={8} value={text} onChange={(event) => setText(event.target.value)} className="mono text-xs" placeholder="Paste configuration, logs or request samples…" />
          </Field>
        </div>
      </Modal>

      <Modal
        open={ruleOpen}
        onClose={() => setRuleOpen(false)}
        title="New classification rule"
        footer={<><Button variant="ghost" onClick={() => setRuleOpen(false)}>Cancel</Button><Button variant="primary" loading={createRule.isPending} disabled={!ruleForm.name || (ruleForm.detection_method === "regex" && !ruleForm.pattern)} onClick={() => createRule.mutate()}>Create rule</Button></>}
      >
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name" className="col-span-2"><Input value={ruleForm.name} onChange={(event) => setRuleForm({ ...ruleForm, name: event.target.value })} /></Field>
          <Field label="Category">
            <Select value={ruleForm.category} onChange={(event) => setRuleForm({ ...ruleForm, category: event.target.value })}>
              {["pii", "financial", "credentials", "api_keys", "access_tokens", "confidential", "internal"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
            </Select>
          </Field>
          <Field label="Detection method">
            <Select value={ruleForm.detection_method} onChange={(event) => setRuleForm({ ...ruleForm, detection_method: event.target.value })}>
              <option value="regex">Regex</option><option value="entropy">Entropy</option>
            </Select>
          </Field>
          <Field label="Pattern" className="col-span-2"><Textarea rows={3} className="mono text-xs" value={ruleForm.pattern} onChange={(event) => setRuleForm({ ...ruleForm, pattern: event.target.value })} placeholder="\\b[A-Z0-9]{20}\\b" /></Field>
          <Field label="Severity">
            <Select value={ruleForm.severity} onChange={(event) => setRuleForm({ ...ruleForm, severity: event.target.value })}>
              {["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
            </Select>
          </Field>
        </div>
      </Modal>
    </div>
  );
}
