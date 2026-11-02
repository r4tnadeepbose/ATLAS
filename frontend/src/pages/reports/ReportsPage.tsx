import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileBarChart2, FileText, Plus } from "lucide-react";
import { reportApi } from "@/api/endpoints";
import { useAuth } from "@/context/AuthContext";
import { PageHeader } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, Field, Modal, Pagination, Select, StatusBadge, useToast } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/table";
import { formatDateTime, relativeTime } from "@/utils";
import type { Report } from "@/types";

export function ReportsPage() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  const [type, setType] = useState("executive");
  const [format, setFormat] = useState("pdf");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const types = useQuery({ queryKey: ["reports", "types"], queryFn: reportApi.types });
  const list = useQuery({ queryKey: ["reports", page, pageSize], queryFn: () => reportApi.list({ page, page_size: pageSize }), placeholderData: (previous) => previous });

  const create = useMutation({
    mutationFn: () => reportApi.create({ report_type: type, format }),
    onSuccess: () => {
      toast.push({ title: "Report generated", description: "Download is available from the report list.", tone: "success" });
      setOpen(false);
      queryClient.invalidateQueries({ queryKey: ["reports"] });
    },
    onError: (error: Error) => toast.push({ title: "Report failed", description: error.message, tone: "error" }),
  });

  const columns: Column<Report>[] = [
    {
      key: "title",
      label: "Report",
      render: (report) => (
        <div>
          <p className="text-sm font-medium text-ink">{report.title}</p>
          <p className="mono text-muted">{report.report_type} · {report.format.toUpperCase()}</p>
        </div>
      ),
    },
    { key: "status", label: "Status", render: (report) => <StatusBadge status={report.status} /> },
    { key: "generated_at", label: "Generated", render: (report) => <span className="text-2xs text-muted">{relativeTime(report.generated_at)}</span> },
    { key: "created_at", label: "Created", render: (report) => <span className="text-2xs text-muted">{formatDateTime(report.created_at)}</span> },
    {
      key: "actions",
      label: "",
      align: "right",
      render: (report) => (
        <Button variant="outline" size="sm" onClick={async () => {
          try {
            await reportApi.download(report.id, `atlas-${report.report_type}-${report.id}.${report.format === "json" ? "json" : report.format}`);
          } catch (error) {
            toast.push({ title: "Download failed", description: (error as Error).message, tone: "error" });
          }
        }}>
          <Download className="h-3 w-3" /> Download
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Reporting"
        title="Security Reports"
        description="Traceable, exportable reporting across executive, vulnerability, SBOM, attack-surface, API and remediation domains."
        actions={can("reports:write") ? <Button variant="primary" size="sm" onClick={() => setOpen(true)}><Plus className="h-3.5 w-3.5" /> Generate report</Button> : undefined}
      />

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {(types.data?.items ?? []).map((item) => (
          <button key={item.key} onClick={() => { if (!can("reports:write")) return; setType(item.key); setOpen(true); }} className={`panel flex items-start gap-3 p-3.5 text-left transition-colors ${can("reports:write") ? "hover:border-border-strong" : "opacity-80"}`}>
            <FileBarChart2 className="mt-0.5 h-4 w-4 text-accent" />
            <div>
              <p className="text-xs font-semibold text-ink">{item.name}</p>
              <p className="mt-0.5 text-[10px] text-muted">PDF, CSV and JSON export</p>
            </div>
          </button>
        ))}
      </div>

      <Card>
        <CardHeader title="Generated reports" description="Every report is built from live organization data at download time" action={<Badge>{list.data?.pagination.total ?? 0} total</Badge>} />
        <DataTable
          columns={columns}
          rows={list.data?.items ?? []}
          rowKey={(report) => report.id}
          loading={list.isLoading}
          error={list.error}
          onRetry={() => list.refetch()}
          footer={list.data?.pagination ? <Pagination page={page} pages={list.data.pagination.pages} total={list.data.pagination.total} pageSize={pageSize} onPage={setPage} onPageSize={setPageSize} /> : null}
          emptyTitle="No reports generated"
          emptyDescription="Generate an executive or technical report to share security posture."
          emptyAction={can("reports:write") ? <Button variant="primary" size="sm" onClick={() => setOpen(true)}>Generate report</Button> : undefined}
        />
      </Card>

      <Card>
        <CardHeader title="Report definitions" description="Each metric is backed by a documented calculation" />
        <div className="grid gap-3 p-4 md:grid-cols-3">
          {[
            ["Executive", "Posture, business-unit risk, MTTD/MTTR, SBOM/API coverage."],
            ["Vulnerability", "Findings with severity, risk score, SLA and ownership."],
            ["SBOM", "Document inventory, component counts and vulnerability totals."],
            ["Attack surface", "Asset exposure, scan history and discovery status."],
            ["API security", "Authentication, exposure and static API issues."],
            ["Remediation", "Task completion, priority and deadlines."],
          ].map(([title, body]) => (
            <div key={title} className="rounded border border-border bg-base/40 p-3">
              <div className="flex items-center gap-1.5"><FileText className="h-3.5 w-3.5 text-muted" /><p className="text-xs font-medium text-ink">{title}</p></div>
              <p className="mt-1 text-[10px] text-muted">{body}</p>
            </div>
          ))}
        </div>
      </Card>

      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Generate report"
        description="Reports are generated server-side from scoped, live data."
        footer={<><Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" loading={create.isPending} onClick={() => create.mutate()}>Generate</Button></>}
      >
        <div className="grid grid-cols-2 gap-3">
          <Field label="Report type" className="col-span-2">
            <Select value={type} onChange={(event) => setType(event.target.value)}>
              {(types.data?.items ?? []).map((item) => <option key={item.key} value={item.key}>{item.name}</option>)}
            </Select>
          </Field>
          <Field label="Format" className="col-span-2">
            <Select value={format} onChange={(event) => setFormat(event.target.value)}>
              <option value="pdf">PDF</option>
              <option value="csv">CSV</option>
              <option value="json">JSON</option>
            </Select>
          </Field>
        </div>
      </Modal>
    </div>
  );
}
