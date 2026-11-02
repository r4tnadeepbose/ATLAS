import { useQuery } from "@tanstack/react-query";
import { KeyRound, Lock, ShieldCheck } from "lucide-react";
import { adminApi } from "@/api/endpoints";
import { PageHeader } from "@/components/common/PageHeader";
import { Badge, Card, CardHeader, EmptyState } from "@/components/ui/primitives";
import { formatDate } from "@/utils";

export function RbacPage() {
  const rbac = useQuery({ queryKey: ["rbac"], queryFn: adminApi.rbac });

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Administration"
        title="Role-Based Access Control"
        description="Server-enforced roles and permissions. Frontend visibility is never treated as authorization."
        actions={<Badge tone="border-accent/30 bg-accent/10 text-accent"><ShieldCheck className="h-3 w-3" /> Enforced server-side</Badge>}
      />

      <div className="grid gap-3 md:grid-cols-3">
        <div className="panel flex items-start gap-2.5 p-3.5"><Lock className="mt-0.5 h-4 w-4 text-accent" /><div><p className="text-xs font-semibold text-ink">Permission dependencies</p><p className="mt-0.5 text-[10px] text-muted">Every protected route declares required permissions; missing grants return HTTP 403.</p></div></div>
        <div className="panel flex items-start gap-2.5 p-3.5"><KeyRound className="mt-0.5 h-4 w-4 text-cyan" /><div><p className="text-xs font-semibold text-ink">Tenant scoping</p><p className="mt-0.5 text-[10px] text-muted">Queries are filtered by organization; cross-tenant object access returns 404.</p></div></div>
        <div className="panel flex items-start gap-2.5 p-3.5"><ShieldCheck className="mt-0.5 h-4 w-4 text-high" /><div><p className="text-xs font-semibold text-ink">Auditability</p><p className="mt-0.5 text-[10px] text-muted">Role changes, scans, uploads and privileged actions are recorded in the audit log.</p></div></div>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        {(rbac.data?.roles ?? []).map((role: any) => (
          <Card key={role.key}>
            <CardHeader
              title={role.name}
              description={`Key: ${role.key}${role.is_system ? " · built-in" : " · custom"}`}
              action={<Badge>{role.permissions.length} permissions</Badge>}
            />
            <div className="flex flex-wrap gap-1 p-3.5">
              {role.permissions.map((permission: string) => <Badge key={permission} tone="border-border-strong bg-raised text-muted">{permission}</Badge>)}
            </div>
          </Card>
        ))}
        {(rbac.data?.roles ?? []).length === 0 ? <EmptyState title="No roles configured" description="Built-in roles are seeded at startup." /> : null}
      </div>

      <Card>
        <CardHeader title="Permission catalog" description={rbac.data?.enforcement} />
        <div className="grid gap-2 p-3.5 md:grid-cols-2 xl:grid-cols-3">
          {(rbac.data?.permission_catalog ?? []).map((permission: any) => (
            <div key={permission.id} className="flex items-center justify-between rounded border border-border bg-base/40 px-2.5 py-1.5">
              <span className="mono text-[10px] text-ink">{permission.key}</span>
              <Badge>{permission.category}</Badge>
            </div>
          ))}
        </div>
      </Card>

      <p className="text-[10px] text-muted/70">Built-in role definitions are versioned in code (ROLE_PERMISSIONS) and synchronized to the permissions catalog at startup. Seeded {formatDate(new Date().toISOString())}.</p>
    </div>
  );
}
