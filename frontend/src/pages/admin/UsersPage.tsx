import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, UserCog, Users } from "lucide-react";
import { adminApi } from "@/api/endpoints";
import { useAuth } from "@/context/AuthContext";
import { PageHeader } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, ConfirmDialog, Field, Input, Modal, Pagination, SearchInput, Select, StatusBadge, Switch, useToast } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/table";
import { formatDateTime, initials, relativeTime, roleLabel } from "@/utils";
import type { UserProfile } from "@/types";

export function UsersPage() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const { user: currentUser, can } = useAuth();
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [q, setQ] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [pendingDeactivate, setPendingDeactivate] = useState<(UserProfile & Record<string, any>) | null>(null);
  const [form, setForm] = useState({ full_name: "", email: "", password: "", role: "developer", title: "" });

  const users = useQuery({ queryKey: ["users", page, pageSize, q], queryFn: () => adminApi.users({ page, page_size: pageSize, q: q || undefined }), placeholderData: (previous) => previous });
  const roles = useQuery({ queryKey: ["roles"], queryFn: adminApi.roles });

  const create = useMutation({
    mutationFn: () => adminApi.createUser(form),
    onSuccess: () => {
      toast.push({ title: "User invited", description: "Share the temporary password through a secure channel.", tone: "success" });
      setCreateOpen(false);
      setForm({ full_name: "", email: "", password: "", role: "developer", title: "" });
      queryClient.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (error: Error) => toast.push({ title: "Could not create user", description: error.message, tone: "error" }),
  });

  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) => adminApi.updateUser(id, body),
    onSuccess: () => {
      toast.push({ title: "User updated", tone: "success" });
      queryClient.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (error: Error) => toast.push({ title: "Update failed", description: error.message, tone: "error" }),
  });

  const columns: Column<UserProfile & Record<string, any>>[] = [
    {
      key: "full_name",
      label: "User",
      render: (user) => (
        <div className="flex items-center gap-2.5">
          <span className="flex h-7 w-7 items-center justify-center rounded bg-raised text-2xs font-semibold text-muted">{initials(user.full_name)}</span>
          <div>
            <p className="text-sm text-ink">{user.full_name}</p>
            <p className="text-2xs text-muted">{user.email}</p>
          </div>
        </div>
      ),
    },
    { key: "title", label: "Title", render: (user) => user.title || "—" },
    { key: "roles", label: "Role", render: (user) => <Badge tone="border-accent/30 bg-accent/10 text-accent">{roleLabel(user.roles?.[0])}</Badge> },
    { key: "mfa_enabled", label: "MFA", render: (user) => user.mfa_enabled ? <Badge tone="border-accent/30 bg-accent/10 text-accent">enabled</Badge> : <Badge tone="border-medium/30 bg-medium/10 text-medium">not enabled</Badge> },
    { key: "last_login_at", label: "Last login", render: (user) => <span className="text-2xs text-muted">{relativeTime(user.last_login_at)}</span> },
    { key: "created_at", label: "Created", render: (user) => <span className="text-2xs text-muted">{formatDateTime(user.created_at)}</span> },
    {
      key: "status",
      label: "Active",
      render: (user) => can("users:write") ? (
        <Switch
          checked={user.is_active}
          onChange={(value) => {
            if (!value) setPendingDeactivate(user);
            else update.mutate({ id: user.id, body: { is_active: true } });
          }}
        />
      ) : <Badge>{user.is_active ? "active" : "inactive"}</Badge>,
    },
    {
      key: "role_change",
      label: "Change role",
      render: (user) => (
        <Select
          value={user.roles?.[0] || ""}
          disabled={user.id === currentUser?.id || !can("users:write")}
          onChange={async (event) => {
            try {
              await adminApi.changeRole(user.id, event.target.value);
              toast.push({ title: "Role updated", tone: "success" });
              users.refetch();
            } catch (error) {
              toast.push({ title: "Role change failed", description: (error as Error).message, tone: "error" });
            }
          }}
          className="h-7 w-[160px] text-2xs"
        >
          <option value="">Change role</option>
          {(roles.data?.items ?? []).map((role: any) => <option key={role.key} value={role.key}>{role.name}</option>)}
        </Select>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Administration"
        title="User Management"
        description="Organization members, role assignment, MFA state and access lifecycle."
        actions={can("users:write") ? <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}><Plus className="h-3.5 w-3.5" /> Invite user</Button> : undefined}
      />

      <Card>
        <DataTable
          columns={columns}
          rows={users.data?.items ?? []}
          rowKey={(user) => user.id}
          loading={users.isLoading}
          error={users.error}
          onRetry={() => users.refetch()}
          toolbar={<SearchInput value={q} onChange={(value) => { setQ(value); setPage(1); }} placeholder="Search users…" className="w-64" />}
          footer={users.data?.pagination ? <Pagination page={page} pages={users.data.pagination.pages} total={users.data.pagination.total} pageSize={pageSize} onPage={setPage} onPageSize={setPageSize} /> : null}
          emptyTitle="No users"
        />
      </Card>

      <div className="grid gap-3 md:grid-cols-3">
        {[
          { icon: Users, title: "Tenant isolation", body: "Every user record is scoped to the active organization; cross-tenant access is rejected server-side." },
          { icon: UserCog, title: "Role enforcement", body: "Permissions are checked on every protected endpoint, not merely hidden in the UI." },
          { icon: Users, title: "MFA", body: "Users can enrol TOTP from account settings; MFA is verified at sign-in when enabled." },
        ].map((item) => (
          <div key={item.title} className="panel flex items-start gap-2.5 p-3.5">
            <item.icon className="mt-0.5 h-4 w-4 text-accent" />
            <div><p className="text-xs font-semibold text-ink">{item.title}</p><p className="mt-0.5 text-[10px] text-muted">{item.body}</p></div>
          </div>
        ))}
      </div>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Invite organization user"
        description="The user is created immediately with the selected role. Deliver credentials over a secure channel."
        footer={<><Button variant="ghost" onClick={() => setCreateOpen(false)}>Cancel</Button><Button variant="primary" loading={create.isPending} disabled={!form.full_name || !form.email || form.password.length < 12} onClick={() => create.mutate()}>Create user</Button></>}
      >
        <div className="grid grid-cols-2 gap-3">
          <Field label="Full name"><Input value={form.full_name} onChange={(event) => setForm({ ...form, full_name: event.target.value })} /></Field>
          <Field label="Title"><Input value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} placeholder="SOC Analyst" /></Field>
          <Field label="Email" className="col-span-2"><Input type="email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} /></Field>
          <Field label="Temporary password" hint="Minimum 12 characters" className="col-span-2"><Input type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} /></Field>
          <Field label="Role" className="col-span-2">
            <Select value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value })}>
              {(roles.data?.items ?? []).map((role: any) => <option key={role.key} value={role.key}>{role.name}</option>)}
            </Select>
          </Field>
        </div>
      </Modal>

      <ConfirmDialog
        open={Boolean(pendingDeactivate)}
        onClose={() => setPendingDeactivate(null)}
        onConfirm={() => {
          if (!pendingDeactivate) return;
          update.mutate(
            { id: pendingDeactivate.id, body: { is_active: false } },
            { onSettled: () => setPendingDeactivate(null) },
          );
        }}
        title="Deactivate user"
        description={pendingDeactivate ? `${pendingDeactivate.full_name} will lose access immediately. Existing sessions are invalidated on their next request.` : ""}
        confirmLabel="Deactivate"
        destructive
        loading={update.isPending}
      />
    </div>
  );
}
