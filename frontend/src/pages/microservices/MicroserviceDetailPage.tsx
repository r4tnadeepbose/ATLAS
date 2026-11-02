import { useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Boxes, ExternalLink, GitBranch, ShieldAlert, Waypoints } from "lucide-react";
import { serviceApi } from "@/api/endpoints";
import { PageHeader } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, EmptyState, SeverityBadge, StatusBadge } from "@/components/ui/primitives";
import { formatDate, formatNumber, relativeTime, riskTone, titleCase } from "@/utils";

export function MicroserviceDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const service = useQuery({ queryKey: ["microservices", id], queryFn: () => serviceApi.get(id) });

  if (service.isLoading) return <div className="panel mt-4 h-72 animate-pulse" />;
  if (service.isError) return <div className="panel mt-4 p-6 text-sm text-critical">{(service.error as Error).message}</div>;
  const data = service.data!;
  const openFindings = (data.findings ?? []).filter((finding) => !["resolved", "closed", "risk_accepted"].includes(finding.status));

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Microservice Intelligence"
        title={data.name}
        description={data.description || `${data.service_ref} · ${data.deployment_location || "deployment location not recorded"}`}
        actions={
          <>
            <Button variant="ghost" size="sm" onClick={() => navigate("/microservices")}>Back to map</Button>
            {data.repository_url ? (
              <a href={data.repository_url} target="_blank" rel="noreferrer">
                <Button variant="outline" size="sm"><ExternalLink className="h-3.5 w-3.5" /> Repository</Button>
              </a>
            ) : null}
          </>
        }
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Service record" description="Ownership and deployment metadata" />
          <div className="grid grid-cols-2 gap-4 p-4 md:grid-cols-3">
            {[
              ["Service ID", data.service_ref],
              ["Version", data.version || "—"],
              ["Language", data.language || "—"],
              ["Business unit", data.business_unit || "—"],
              ["Environment", data.environment_name || "—"],
              ["Deployment", data.deployment_location || "—"],
              ["Status", data.status],
              ["Last assessed", formatDate(data.last_assessed_at)],
              ["Risk level", titleCase(data.risk_level)],
            ].map(([label, value]) => (
              <div key={String(label)}>
                <p className="label">{label}</p>
                <p className="mt-0.5 truncate text-sm text-ink">{String(value)}</p>
              </div>
            ))}
            <div className="col-span-2 md:col-span-3">
              <p className="label">Technology stack</p>
              <div className="mt-1.5 flex flex-wrap gap-1">
                {(data.tech_stack ?? []).map((tech) => <Badge key={tech}>{tech}</Badge>)}
                {(data.tech_stack ?? []).length === 0 ? <span className="text-sm text-muted">None recorded</span> : null}
              </div>
            </div>
          </div>
        </Card>

        <Card>
          <CardHeader title="Risk posture" description="Weighted open findings" />
          <div className="p-4">
            <div className="flex items-end justify-between">
              <p className={`text-4xl font-semibold tabular-nums ${riskTone(data.risk_score)}`}>{formatNumber(data.risk_score, 0)}</p>
              <StatusBadge status={data.security_posture} />
            </div>
            <div className="mt-4 space-y-1.5 text-sm">
              <div className="flex items-center justify-between"><span className="text-muted">Open findings</span><span className="text-ink">{openFindings.length}</span></div>
              <div className="flex items-center justify-between"><span className="text-muted">SBOM documents</span><span className="text-ink">{data.sboms?.length ?? 0}</span></div>
              <div className="flex items-center justify-between"><span className="text-muted">APIs</span><span className="text-ink">{data.apis?.length ?? 0}</span></div>
              <div className="flex items-center justify-between"><span className="text-muted">Criticality</span><Badge>{data.criticality}</Badge></div>
            </div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader title="Dependencies" description="Services this service calls" action={<GitBranch className="h-4 w-4 text-muted" />} />
          <div className="p-3">
            {(data.dependencies ?? []).length === 0 ? <EmptyState title="No outbound dependencies mapped" className="py-6" /> : (
              <div className="space-y-1.5">
                {data.dependencies!.map((dependency) => (
                  <div key={dependency.id} className="flex items-center justify-between rounded border border-border bg-base/40 px-2.5 py-2">
                    <span className="mono text-xs text-ink">{dependency.target_external || dependency.target_service_id?.slice(0, 8) || "unknown"}</span>
                    <Badge>{dependency.dependency_type}</Badge>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="Dependents" description="Services that depend on this service" action={<Waypoints className="h-4 w-4 text-muted" />} />
          <div className="p-3">
            {(data.dependents ?? []).length === 0 ? <EmptyState title="No inbound dependents mapped" className="py-6" /> : (
              <div className="space-y-1.5">
                {data.dependents!.map((dependency) => (
                  <button key={dependency.id} onClick={() => navigate(`/microservices/${dependency.source_service_id}`)} className="flex w-full items-center justify-between rounded border border-border bg-base/40 px-2.5 py-2 text-left hover:border-border-strong">
                    <span className="mono text-xs text-ink">{dependency.source_service_id.slice(0, 8)}</span>
                    <Badge>{dependency.dependency_type}</Badge>
                  </button>
                ))}
              </div>
            )}
          </div>
        </Card>
      </div>

      <Card>
        <CardHeader title="Linked findings" description="Findings correlated to this service" action={<ShieldAlert className="h-4 w-4 text-muted" />} />
        {(data.findings ?? []).length === 0 ? <EmptyState title="No findings linked" description="SBOM and assessment findings will appear here." /> : (
          <div className="divide-y divide-border/50">
            {data.findings!.map((finding) => (
              <button key={finding.id} onClick={() => navigate(`/vulnerabilities/${finding.id}`)} className="flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left hover:bg-raised/50">
                <div className="min-w-0">
                  <p className="truncate text-xs font-medium text-ink">{finding.title}</p>
                  <p className="text-[10px] text-muted">{finding.finding_ref} · {relativeTime(finding.first_seen)}</p>
                </div>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={finding.severity} />
                  <StatusBadge status={finding.status} />
                  <span className={`w-8 text-right text-xs font-semibold ${riskTone(finding.risk_score)}`}>{formatNumber(finding.risk_score, 0)}</span>
                </div>
              </button>
            ))}
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader title="SBOM documents" description="Attached software bills of materials" action={<Boxes className="h-4 w-4 text-muted" />} />
          <div className="p-3">
            {(data.sboms ?? []).length === 0 ? <EmptyState title="No SBOM attached" className="py-6" /> : (
              <div className="space-y-1.5">
                {data.sboms!.map((sbom) => (
                  <button key={sbom.id} onClick={() => navigate(`/sbom/${sbom.id}`)} className="flex w-full items-center justify-between rounded border border-border bg-base/40 px-2.5 py-2 text-left hover:border-border-strong">
                    <div><p className="text-xs text-ink">{sbom.name}</p><p className="text-[10px] text-muted">{sbom.component_count} components · {sbom.vulnerability_count} vulnerabilities</p></div>
                    <StatusBadge status={sbom.status} />
                  </button>
                ))}
              </div>
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="APIs" description="Registered APIs owned by this service" />
          <div className="p-3">
            {(data.apis ?? []).length === 0 ? <EmptyState title="No APIs registered" className="py-6" /> : (
              <div className="space-y-1.5">
                {data.apis!.map((api) => (
                  <button key={api.id} onClick={() => navigate(`/api-inventory/${api.id}`)} className="flex w-full items-center justify-between rounded border border-border bg-base/40 px-2.5 py-2 text-left hover:border-border-strong">
                    <div><p className="text-xs text-ink">{api.name}</p><p className="mono text-[10px] text-muted">{api.base_url || "no base URL"}</p></div>
                    <StatusBadge status={api.security_status} />
                  </button>
                ))}
              </div>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
