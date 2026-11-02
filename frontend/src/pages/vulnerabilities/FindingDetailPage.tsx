import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, BrainCircuit, CheckCircle2, Clock, MessageSquare, Paperclip, ShieldAlert, Sparkles, UserPlus } from "lucide-react";
import { adminApi, findingApi, triageApi } from "@/api/endpoints";
import { useAuth } from "@/context/AuthContext";
import { PageHeader } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, EmptyState, Field, Input, Modal, ProgressBar, Select, SeverityBadge, StatusBadge, Tabs, Textarea, useToast } from "@/components/ui/primitives";
import { formatDateTime, formatNumber, formatPercent, relativeTime, riskTone, titleCase } from "@/utils";
import type { TriageResult } from "@/types";

const STATUSES = ["open", "triaged", "in_progress", "assigned", "resolved", "risk_accepted", "false_positive", "closed"];

export function FindingDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const queryClient = useQueryClient();
  const { can } = useAuth();
  const [tab, setTab] = useState("overview");
  const [status, setStatus] = useState("");
  const [note, setNote] = useState("");
  const [comment, setComment] = useState("");
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [evidence, setEvidence] = useState({ kind: "text", content: "", location: "" });
  const [triage, setTriage] = useState<TriageResult | null>(null);
  const [assignee, setAssignee] = useState("");

  const finding = useQuery({ queryKey: ["findings", id], queryFn: () => findingApi.get(id) });
  const users = useQuery({ queryKey: ["users", "options"], queryFn: () => adminApi.users({ page_size: 100 }), enabled: can("users:read") });
  const config = useQuery({ queryKey: ["triage", "config"], queryFn: triageApi.config });
  const provider = config.data?.environment_provider || "none";

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["findings", id] });
    queryClient.invalidateQueries({ queryKey: ["findings"] });
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  };

  const update = useMutation({
    mutationFn: (body: Record<string, unknown>) => findingApi.update(id, body),
    onSuccess: () => {
      toast.push({ title: "Finding updated", tone: "success" });
      setStatus("");
      setNote("");
      invalidate();
    },
    onError: (error: Error) => toast.push({ title: "Update failed", description: error.message, tone: "error" }),
  });

  const addComment = useMutation({
    mutationFn: () => findingApi.comment(id, comment),
    onSuccess: () => {
      setComment("");
      toast.push({ title: "Comment added", tone: "success" });
      invalidate();
    },
    onError: (error: Error) => toast.push({ title: "Comment failed", description: error.message, tone: "error" }),
  });

  const addEvidence = useMutation({
    mutationFn: () => findingApi.evidence(id, evidence),
    onSuccess: () => {
      setEvidenceOpen(false);
      setEvidence({ kind: "text", content: "", location: "" });
      toast.push({ title: "Evidence attached", tone: "success" });
      invalidate();
    },
    onError: (error: Error) => toast.push({ title: "Evidence failed", description: error.message, tone: "error" }),
  });

  const assign = useMutation({
    mutationFn: () => findingApi.assign(id, assignee, "Assigned from finding detail"),
    onSuccess: () => {
      toast.push({ title: "Finding assigned", tone: "success" });
      invalidate();
    },
    onError: (error: Error) => toast.push({ title: "Assignment failed", description: error.message, tone: "error" }),
  });

  const runTriage = useMutation({
    mutationFn: () => triageApi.analyze(id),
    onSuccess: (result) => {
      setTriage(result);
      toast.push({ title: "Triage complete", description: `${result.provider} analysis stored as advisory intelligence.`, tone: "success" });
      invalidate();
    },
    onError: (error: Error) => toast.push({ title: "Triage failed", description: error.message, tone: "error" }),
  });

  if (finding.isLoading) return <div className="panel mt-4 h-80 animate-pulse" />;
  if (finding.isError) return <div className="panel mt-4 p-6 text-sm text-critical">{(finding.error as Error).message}</div>;
  const data = finding.data!;
  const triageHistory = data.ai_triage ?? [];
  const shownTriage: any = triage || triageHistory[0];
  const overdue = data.sla_due_at && new Date(data.sla_due_at).getTime() < Date.now() && !["resolved", "closed"].includes(data.status);

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Vulnerability Management"
        title={data.title}
        description={`${data.finding_ref} · ${data.category.replace("_", " ")} · discovered ${relativeTime(data.first_seen)}`}
        actions={
          <>
            <Button variant="ghost" size="sm" onClick={() => navigate("/vulnerabilities")}><ArrowLeft className="h-3.5 w-3.5" /> Back</Button>
            {can("findings:triage") ? (
              <Button variant="outline" size="sm" loading={runTriage.isPending} onClick={() => runTriage.mutate()}><BrainCircuit className="h-3.5 w-3.5" /> AI triage</Button>
            ) : null}
            {can("findings:write") ? (
              <Button variant="primary" size="sm" loading={update.isPending} disabled={!status} onClick={() => update.mutate({ status, note: note || undefined })}>
                <CheckCircle2 className="h-3.5 w-3.5" /> Update status
              </Button>
            ) : null}
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {[
          ["Severity", <SeverityBadge severity={data.severity} />],
          ["Risk score", <span className={`text-sm font-semibold ${riskTone(data.risk_score)}`}>{formatNumber(data.risk_score, 0)}</span>],
          ["Status", <StatusBadge status={data.status} />],
          ["CVSS", data.cvss_score?.toFixed(1) ?? "—"],
          ["Exposure", <Badge>{data.exposure}</Badge>],
          ["SLA", overdue ? <span className="text-2xs text-critical">Overdue</span> : <span className="text-2xs text-muted">{formatDateTime(data.sla_due_at)}</span>],
        ].map(([label, value], index) => (
          <div key={index} className="panel p-3">
            <p className="label">{label as string}</p>
            <div className="mt-1.5">{value as any}</div>
          </div>
        ))}
      </div>

      {can("findings:write") ? (
        <Card>
          <div className="flex flex-wrap items-end gap-3 p-3.5">
            <Field label="Status transition" className="w-48">
              <Select value={status} onChange={(event) => setStatus(event.target.value)}>
                <option value="">Current: {titleCase(data.status)}</option>
                {STATUSES.filter((value) => value !== data.status).map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
              </Select>
            </Field>
            <Field label="Transition note" className="min-w-[220px] flex-1">
              <Input value={note} onChange={(event) => setNote(event.target.value)} placeholder="Reason, ticket reference, validation evidence…" />
            </Field>
            {can("users:read") ? (
              <Field label="Assign owner" className="w-64">
                <div className="flex gap-1.5">
                  <Select value={assignee} onChange={(event) => setAssignee(event.target.value)}>
                    <option value="">Select user</option>
                    {(users.data?.items ?? []).map((user: any) => <option key={user.id} value={user.id}>{user.full_name}</option>)}
                  </Select>
                  <Button variant="secondary" size="icon" disabled={!assignee} loading={assign.isPending} onClick={() => assign.mutate()} aria-label="Assign">
                    <UserPlus className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </Field>
            ) : null}
          </div>
        </Card>
      ) : null}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Tabs
            tabs={[
              { key: "overview", label: "Overview" },
              { key: "evidence", label: "Evidence", count: data.evidence?.length ?? 0 },
              { key: "comments", label: "Comments", count: data.comments?.length ?? 0 },
              { key: "history", label: "History", count: data.history?.length ?? 0 },
              { key: "triage", label: "AI analysis", count: triageHistory.length },
            ]}
            value={tab}
            onChange={setTab}
          />

          {tab === "overview" ? (
            <Card>
              <CardHeader title="Finding context" description="Evidence and remediation guidance" />
              <div className="space-y-4 p-4">
                <div>
                  <p className="label mb-1">Description</p>
                  <p className="whitespace-pre-wrap text-sm leading-relaxed text-ink/90">{data.description || "No description supplied."}</p>
                </div>
                <div>
                  <p className="label mb-1">Remediation recommendation</p>
                  <p className="whitespace-pre-wrap text-sm leading-relaxed text-ink/90">{data.remediation || "No remediation recorded. Triage the finding to generate guidance."}</p>
                </div>
                <div className="grid grid-cols-2 gap-4 border-t border-border pt-3 md:grid-cols-4">
                  {[
                    ["Category", titleCase(data.category)],
                    ["Source module", titleCase(data.source_module)],
                    ["Confidence", formatPercent(data.confidence * 100, 0)],
                    ["Exploitability", titleCase(data.exploitability)],
                    ["Business unit", data.business_unit || "—"],
                    ["CVE", data.cve_id || "—"],
                    ["First seen", formatDateTime(data.first_seen)],
                    ["Last seen", formatDateTime(data.last_seen)],
                  ].map(([label, value]) => (
                    <div key={label}>
                      <p className="label">{label}</p>
                      <p className="mt-0.5 truncate text-sm text-ink">{value}</p>
                    </div>
                  ))}
                </div>
              </div>
            </Card>
          ) : null}

          {tab === "evidence" ? (
            <Card>
              <CardHeader
                title="Evidence"
                description="Redacted evidence supporting the finding"
                action={can("findings:write") ? <Button variant="outline" size="sm" onClick={() => setEvidenceOpen(true)}><Paperclip className="h-3.5 w-3.5" /> Attach</Button> : null}
              />
              {(data.evidence ?? []).length === 0 ? (
                <EmptyState title="No evidence attached" description="Evidence and scan artefacts should be attached before closing a finding." />
              ) : (
                <div className="divide-y divide-border/50">
                  {data.evidence!.map((item) => (
                    <div key={item.id} className="px-4 py-3">
                      <div className="flex items-center justify-between">
                        <Badge>{item.kind}</Badge>
                        <span className="text-2xs text-muted">{formatDateTime(item.created_at)}</span>
                      </div>
                      <pre className="mono mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded border border-border bg-base/60 p-2 text-[11px] text-ink/80">{item.content}</pre>
                      {item.location ? <p className="mono mt-1 text-2xs text-muted">{item.location}</p> : null}
                    </div>
                  ))}
                </div>
              )}
            </Card>
          ) : null}

          {tab === "comments" ? (
            <Card>
              <CardHeader title="Analyst comments" description="Collaboration trail" />
              <div className="divide-y divide-border/50">
                {(data.comments ?? []).length === 0 ? <EmptyState title="No comments" description="Add context for the remediation owner." /> : data.comments!.map((item) => (
                  <div key={item.id} className="px-4 py-3">
                    <div className="flex items-center justify-between text-2xs text-muted">
                      <span className="mono">{item.author_id?.slice(0, 8) || "system"}</span>
                      <span>{formatDateTime(item.created_at)}</span>
                    </div>
                    <p className="mt-1 text-sm text-ink/90">{item.body}</p>
                  </div>
                ))}
              </div>
              {can("findings:write") ? (
                <div className="flex gap-2 border-t border-border p-3">
                  <Textarea rows={2} value={comment} onChange={(event) => setComment(event.target.value)} placeholder="Add a comment…" />
                  <Button variant="secondary" size="sm" disabled={!comment.trim()} loading={addComment.isPending} onClick={() => addComment.mutate()}><MessageSquare className="h-3.5 w-3.5" /> Post</Button>
                </div>
              ) : null}
            </Card>
          ) : null}

          {tab === "history" ? (
            <Card>
              <CardHeader title="Status history" description="Every transition is auditable" />
              <div className="p-4">
                {(data.history ?? []).length === 0 ? <EmptyState title="No history" /> : (
                  <ol className="relative space-y-4 border-l border-border pl-5">
                    {data.history!.map((entry) => (
                      <li key={entry.id} className="relative">
                        <span className="absolute -left-[25px] top-1 h-2 w-2 rounded-full bg-accent" />
                        <div className="flex flex-wrap items-center gap-2">
                          <StatusBadge status={entry.to_status} />
                          {entry.from_status ? <span className="text-2xs text-muted">from {titleCase(entry.from_status)}</span> : null}
                          <span className="text-2xs text-muted">· {formatDateTime(entry.created_at)}</span>
                        </div>
                        {entry.note ? <p className="mt-1 text-xs text-muted">{entry.note}</p> : null}
                      </li>
                    ))}
                  </ol>
                )}
              </div>
            </Card>
          ) : null}

          {tab === "triage" ? (
            <Card>
              <CardHeader
                title="AI-assisted analysis"
                description={`Provider: ${provider} · advisory only`}
                action={can("findings:triage") ? <Button variant="outline" size="sm" loading={runTriage.isPending} onClick={() => runTriage.mutate()}><Sparkles className="h-3.5 w-3.5" /> Analyze</Button> : undefined}
              />
              {!shownTriage ? (
                <EmptyState title="No analysis yet" description="Run triage to generate technical context, business impact and remediation guidance." />
              ) : (
                <div className="space-y-4 p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={shownTriage.priority} />
                    <Badge tone={shownTriage.provider === "heuristic" ? "border-medium/30 bg-medium/10 text-medium" : "border-cyan/30 bg-cyan/10 text-cyan"}>{shownTriage.provider}</Badge>
                    <Badge>{shownTriage.model}</Badge>
                    <span className="text-2xs text-muted">confidence {formatPercent(shownTriage.confidence * 100, 0)} · FP likelihood {formatPercent(shownTriage.false_positive_likelihood * 100, 0)}</span>
                  </div>
                  {[
                    ["Summary", shownTriage.summary],
                    ["Technical impact", shownTriage.technical_impact],
                    ["Business impact", shownTriage.business_impact],
                    ["Recommendation", shownTriage.recommendation],
                  ].map(([label, value]) => (
                    <div key={label as string}>
                      <p className="label mb-1">{label as string}</p>
                      <p className="text-sm leading-relaxed text-ink/90">{value || "—"}</p>
                    </div>
                  ))}
                  <ProgressBar value={shownTriage.confidence * 100} tone="bg-cyan" />
                  <p className="text-2xs text-muted">AI output is advisory. Severity and risk score remain determined by the documented ATLAS scoring model.</p>
                  {triageHistory.length > 1 ? <p className="text-2xs text-muted">{triageHistory.length} analyses stored for this finding.</p> : null}
                </div>
              )}
            </Card>
          ) : null}
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader title="Affected context" description="Linked inventory" />
            <div className="space-y-3 p-3.5">
              <div>
                <p className="label">Asset</p>
                {data.asset ? (
                  <Link to={`/assets/${data.asset.id}`} className="mt-1 block rounded border border-border bg-base/40 px-2.5 py-2 hover:border-border-strong">
                    <p className="text-xs font-medium text-ink">{data.asset.name}</p>
                    <p className="mono text-[10px] text-muted">{data.asset.domain || "no domain"} · {data.asset.exposure}</p>
                  </Link>
                ) : <p className="mt-1 text-xs text-muted">No asset linked</p>}
              </div>
              <div>
                <p className="label">Microservice</p>
                {data.microservice ? (
                  <Link to={`/microservices/${data.microservice.id}`} className="mt-1 block rounded border border-border bg-base/40 px-2.5 py-2 hover:border-border-strong">
                    <p className="text-xs font-medium text-ink">{data.microservice.name}</p>
                    <p className="text-[10px] text-muted">{data.microservice.business_unit || "unassigned unit"}</p>
                  </Link>
                ) : <p className="mt-1 text-xs text-muted">No microservice linked</p>}
              </div>
              <div>
                <p className="label">Assignee</p>
                <p className="mt-1 text-xs text-ink">{data.assignee ? `${data.assignee.full_name} · ${data.assignee.email}` : "Unassigned"}</p>
              </div>
              <div>
                <p className="label">Location</p>
                <p className="mono mt-1 break-all text-[10px] text-muted">{data.location || "—"}</p>
              </div>
            </div>
          </Card>

          {data.vulnerability ? (
            <Card>
              <CardHeader title="Vulnerability record" description={data.vulnerability.identifier} action={<ShieldAlert className="h-4 w-4 text-muted" />} />
              <div className="space-y-2 p-3.5 text-xs">
                <p className="text-ink">{data.vulnerability.title}</p>
                <div className="flex flex-wrap gap-1">
                  <SeverityBadge severity={data.vulnerability.severity} />
                  {data.vulnerability.cvss_score !== null ? <Badge>CVSS {data.vulnerability.cvss_score?.toFixed(1)}</Badge> : null}
                  {data.vulnerability.known_exploited ? <Badge tone="border-critical/30 bg-critical/10 text-critical">Known exploited</Badge> : null}
                </div>
                <p className="text-muted">{data.vulnerability.description}</p>
                {data.vulnerability.fixed_versions?.length ? <p className="text-accent">Fixed in {data.vulnerability.fixed_versions.join(", ")}</p> : null}
              </div>
            </Card>
          ) : null}

          <Card>
            <CardHeader title="SLA & ageing" description="Documented remediation windows" />
            <div className="space-y-2 p-3.5 text-xs">
              <div className="flex items-center justify-between"><span className="text-muted">First seen</span><span className="text-ink">{formatDateTime(data.first_seen)}</span></div>
              <div className="flex items-center justify-between"><span className="text-muted">SLA due</span><span className={overdue ? "text-critical" : "text-ink"}>{formatDateTime(data.sla_due_at)}</span></div>
              <div className="flex items-center justify-between"><span className="text-muted">Age</span><span className="text-ink">{relativeTime(data.first_seen)}</span></div>
              <div className="flex items-center gap-1.5 text-2xs text-muted"><Clock className="h-3 w-3" /> Critical 7d · High 30d · Medium 90d · Low 180d</div>
            </div>
          </Card>
        </div>
      </div>

      <Modal
        open={evidenceOpen}
        onClose={() => setEvidenceOpen(false)}
        title="Attach evidence"
        description="Do not include live credentials or sensitive values. Evidence is stored as redacted context."
        footer={
          <>
            <Button variant="ghost" onClick={() => setEvidenceOpen(false)}>Cancel</Button>
            <Button variant="primary" disabled={!evidence.content.trim()} loading={addEvidence.isPending} onClick={() => addEvidence.mutate()}>Attach</Button>
          </>
        }
      >
        <div className="space-y-3">
          <Field label="Kind">
            <Select value={evidence.kind} onChange={(event) => setEvidence({ ...evidence, kind: event.target.value })}>
              {["text", "http_response", "scanner_output", "configuration", "screenshot_note"].map((kind) => <option key={kind} value={kind}>{kind}</option>)}
            </Select>
          </Field>
          <Field label="Content"><Textarea rows={6} value={evidence.content} onChange={(event) => setEvidence({ ...evidence, content: event.target.value })} placeholder="Redacted request/response, scanner output or analyst note…" /></Field>
          <Field label="Location"><Input value={evidence.location} onChange={(event) => setEvidence({ ...evidence, location: event.target.value })} placeholder="https://… or repository path" /></Field>
        </div>
      </Modal>
    </div>
  );
}
