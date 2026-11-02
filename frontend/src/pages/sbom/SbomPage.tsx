import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, GitCompare, HardDriveDownload, Upload } from "lucide-react";
import { sbomApi, serviceApi } from "@/api/endpoints";
import { useListQuery } from "@/hooks/useListQuery";
import { useAuth } from "@/context/AuthContext";
import { PageHeader, StatCard } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, Field, Input, Modal, Pagination, SearchInput, Select, StatusBadge, useToast } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/table";
import { HorizontalBars, SeverityDonut, SeverityLegend } from "@/components/charts";
import { formatDate, formatNumber, formatPercent, relativeTime } from "@/utils";
import type { SbomDocument } from "@/types";

export function SbomPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const queryClient = useQueryClient();
  const { can } = useAuth();
  const fileRef = useRef<HTMLInputElement>(null);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [compareOpen, setCompareOpen] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [microserviceId, setMicroserviceId] = useState("");
  const [versionLabel, setVersionLabel] = useState("");
  const [left, setLeft] = useState("");
  const [right, setRight] = useState("");

  const list = useListQuery<SbomDocument>(["sbom"], sbomApi.list, { initialSort: "created_at" });
  const dashboard = useQuery({ queryKey: ["sbom", "dashboard"], queryFn: sbomApi.dashboard });
  const services = useQuery({ queryKey: ["microservices", "options"], queryFn: () => serviceApi.list({ page_size: 200 }) });
  const compareDocs = useQuery({
    queryKey: ["sbom", "compare-options"],
    queryFn: () => sbomApi.list({ page_size: 200 }),
    enabled: compareOpen,
  });

  const upload = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error("Choose an SBOM file first");
      const form = new FormData();
      form.append("file", file);
      if (microserviceId) form.append("microservice_id", microserviceId);
      if (versionLabel) form.append("version_label", versionLabel);
      form.append("analyze", "true");
      return sbomApi.upload(form);
    },
    onSuccess: (document) => {
      toast.push({ title: "SBOM ingested", description: `${document.component_count} components parsed. Correlation queued.`, tone: "success" });
      setUploadOpen(false);
      setFile(null);
      setVersionLabel("");
      queryClient.invalidateQueries({ queryKey: ["sbom"] });
      navigate(`/sbom/${document.id}`);
    },
    onError: (error: Error) => toast.push({ title: "Upload rejected", description: error.message, tone: "error" }),
  });

  const compare = useQuery({
    queryKey: ["sbom", "compare", left, right],
    queryFn: () => sbomApi.compare(left, right),
    enabled: Boolean(left && right && left !== right),
  });

  const columns: Column<SbomDocument>[] = [
    {
      key: "name",
      label: "Document",
      render: (document) => (
        <div className="min-w-0 max-w-[240px]">
          <p className="truncate text-sm font-medium text-ink">{document.name}</p>
          <p className="mono truncate text-muted">{(document.file_name || document.source) + (document.version_label ? ` · ${document.version_label}` : "")}</p>
        </div>
      ),
    },
    { key: "microservice_name", label: "Service", render: (document) => <span className="block max-w-[140px] truncate whitespace-nowrap">{document.microservice_name || "Unlinked"}</span> },
    { key: "component_count", label: "Components", sortable: true, align: "right", render: (document) => <span className="tabular-nums">{formatNumber(document.component_count)}</span> },
    { key: "vulnerability_count", label: "Vulns", sortable: true, align: "right", render: (document) => <span className={`tabular-nums font-semibold ${document.vulnerability_count ? "text-critical" : "text-muted"}`}>{formatNumber(document.vulnerability_count)}</span> },
    { key: "status", label: "Status", render: (document) => <StatusBadge status={document.status} /> },
    { key: "created_at", label: "Uploaded", sortable: true, render: (document) => <span className="whitespace-nowrap text-2xs text-muted">{relativeTime(document.created_at)}</span> },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Intelligence"
        title="SBOM Intelligence"
        description="CycloneDX and SPDX ingestion, dependency vulnerability correlation and continuous monitoring."
        actions={
          <>
            <Button variant="ghost" size="sm" onClick={() => setCompareOpen(true)}><GitCompare className="h-3.5 w-3.5" /> Compare</Button>
            {can("sbom:write") ? <Button variant="primary" size="sm" onClick={() => setUploadOpen(true)}><Upload className="h-3.5 w-3.5" /> Upload SBOM</Button> : null}
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="SBOM documents" value={formatNumber(dashboard.data?.documents)} icon={<Boxes className="h-4 w-4" />} hint="CycloneDX + SPDX" />
        <StatCard label="Components" value={formatNumber(dashboard.data?.components)} hint="Normalized inventory" />
        <StatCard label="Vulnerable components" value={formatNumber(dashboard.data?.vulnerable_components)} tone="high" hint={`${dashboard.data?.critical_dependencies ?? 0} critical`} />
        <StatCard label="License concerns" value={formatNumber(dashboard.data?.license_concerns)} tone="medium" hint="Non-permissive licences" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-4">
        <Card className="xl:col-span-3">
          <CardHeader title="SBOM documents" description="Parsed documents and correlation status" />
          <DataTable
            columns={columns}
            rows={list.rows}
            rowKey={(document) => document.id}
            loading={list.isLoading}
            error={list.error}
            onRetry={() => list.refetch()}
            sortBy={list.sortBy}
            sortDir={list.sortDir}
            onSort={list.onSort}
            onRowClick={(document) => navigate(`/sbom/${document.id}`)}
            toolbar={
              <>
                <SearchInput value={list.q} onChange={list.setQ} placeholder="Search SBOMs…" className="w-64" />
                <span className="text-2xs text-muted">Supported: CycloneDX JSON/XML · SPDX JSON/tag-value</span>
              </>
            }
            footer={list.pagination ? <Pagination page={list.page} pages={list.pagination.pages} total={list.pagination.total} pageSize={list.pageSize} onPage={list.setPage} onPageSize={list.setPageSize} /> : null}
            emptyTitle="No SBOM documents"
            emptyDescription="Upload a CycloneDX or SPDX document, or generate one with Syft."
            emptyAction={can("sbom:write") ? <Button variant="primary" size="sm" onClick={() => setUploadOpen(true)}>Upload SBOM</Button> : undefined}
          />
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader title="Vulnerability mix" description="Across all SBOM components" />
            <div className="p-3">
              <SeverityDonut data={dashboard.data?.severity_distribution ?? []} height={170} />
              <div className="mt-1"><SeverityLegend data={dashboard.data?.severity_distribution ?? []} /></div>
            </div>
          </Card>
          <Card>
            <CardHeader title="Formats ingested" description="Parser coverage" />
            <div className="p-3"><HorizontalBars data={dashboard.data?.formats ?? []} dataKey="value" labelKey="name" height={150} /></div>
          </Card>
        </div>
      </div>

      <Modal
        open={uploadOpen}
        onClose={() => setUploadOpen(false)}
        title="Upload SBOM"
        description="CycloneDX JSON/XML or SPDX JSON/tag-value. Files are parsed, never executed."
        footer={
          <>
            <Button variant="ghost" onClick={() => setUploadOpen(false)}>Cancel</Button>
            <Button variant="primary" loading={upload.isPending} disabled={!file} onClick={() => upload.mutate()}>Upload &amp; analyze</Button>
          </>
        }
      >
        <div className="space-y-3">
          <div
            onClick={() => fileRef.current?.click()}
            className="flex cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed border-border-strong bg-base/40 px-4 py-8 text-center hover:border-accent/40"
          >
            <HardDriveDownload className="mb-2 h-6 w-6 text-muted" />
            <p className="text-sm text-ink">{file ? file.name : "Select an SBOM file"}</p>
            <p className="mt-0.5 text-2xs text-muted">{file ? `${(file.size / 1024).toFixed(1)} KB` : "Maximum 25 MB"}</p>
            <input ref={fileRef} type="file" className="hidden" accept=".json,.xml,.spdx,.txt" onChange={(event) => setFile(event.target.files?.[0] ?? null)} />
          </div>
          <Field label="Attach to microservice">
            <Select value={microserviceId} onChange={(event) => setMicroserviceId(event.target.value)}>
              <option value="">Unlinked document</option>
              {(services.data?.items ?? []).map((service) => <option key={service.id} value={service.id}>{service.name}</option>)}
            </Select>
          </Field>
          <Field label="Version label"><Input value={versionLabel} onChange={(event) => setVersionLabel(event.target.value)} placeholder="2026.11" /></Field>
          <p className="text-2xs text-muted">Correlation runs in the background and queries OSV for new intelligence. Offline matching against existing records always runs.</p>
        </div>
      </Modal>

      <Modal
        open={compareOpen}
        onClose={() => setCompareOpen(false)}
        title="Compare SBOM versions"
        description="Identify added, removed and changed components between two documents."
        size="lg"
        footer={<Button variant="ghost" onClick={() => setCompareOpen(false)}>Close</Button>}
      >
        <div className="grid grid-cols-2 gap-3">
          <Field label="Baseline">
            <Select value={left} onChange={(event) => setLeft(event.target.value)}>
              <option value="">Select document</option>
              {(compareDocs.data?.items ?? list.rows).map((document) => <option key={document.id} value={document.id}>{document.name} · {formatDate(document.created_at)}</option>)}
            </Select>
          </Field>
          <Field label="Comparison">
            <Select value={right} onChange={(event) => setRight(event.target.value)}>
              <option value="">Select document</option>
              {(compareDocs.data?.items ?? list.rows).map((document) => <option key={document.id} value={document.id}>{document.name} · {formatDate(document.created_at)}</option>)}
            </Select>
          </Field>
        </div>
        {compare.isLoading ? <p className="mt-4 text-xs text-muted">Comparing…</p> : null}
        {compare.data ? (
          <div className="mt-4 space-y-3">
            <div className="flex gap-2">
              <Badge tone="border-accent/30 bg-accent/10 text-accent">+{compare.data.summary.added} added</Badge>
              <Badge tone="border-critical/30 bg-critical/10 text-critical">−{compare.data.summary.removed} removed</Badge>
              <Badge>{compare.data.summary.changed} changed</Badge>
            </div>
            <div className="grid grid-cols-3 gap-2 text-2xs">
              <div><p className="label mb-1">Added</p><div className="max-h-48 space-y-0.5 overflow-y-auto">{compare.data.added.map((item: string) => <p key={item} className="mono truncate text-accent">{item}</p>)}{compare.data.added.length === 0 ? <p className="text-muted">None</p> : null}</div></div>
              <div><p className="label mb-1">Removed</p><div className="max-h-48 space-y-0.5 overflow-y-auto">{compare.data.removed.map((item: string) => <p key={item} className="mono truncate text-critical">{item}</p>)}{compare.data.removed.length === 0 ? <p className="text-muted">None</p> : null}</div></div>
              <div><p className="label mb-1">Changed</p><div className="max-h-48 space-y-0.5 overflow-y-auto">{compare.data.changed.map((item: string) => <p key={item} className="mono truncate text-medium">{item}</p>)}{compare.data.changed.length === 0 ? <p className="text-muted">None</p> : null}</div></div>
            </div>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
