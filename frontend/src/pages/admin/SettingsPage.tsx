import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Lock, ShieldCheck, Users } from "lucide-react";
import { adminApi, authApi } from "@/api/endpoints";
import { useAuth } from "@/context/AuthContext";
import { PageHeader } from "@/components/common/PageHeader";
import { Badge, Button, Card, CardHeader, Field, Input, Modal, StatusBadge, useToast } from "@/components/ui/primitives";
import { formatDateTime } from "@/utils";

export function SettingsPage() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const { user, refresh, can } = useAuth();
  const [orgName, setOrgName] = useState("");
  const [mfaOpen, setMfaOpen] = useState(false);
  const [mfaSecret, setMfaSecret] = useState("");
  const [mfaUri, setMfaUri] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [disableOpen, setDisableOpen] = useState(false);
  const [disablePassword, setDisablePassword] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [passwords, setPasswords] = useState({ current: "", next: "" });

  const organization = useQuery({ queryKey: ["organization"], queryFn: adminApi.organization });
  const teams = useQuery({ queryKey: ["teams"], queryFn: adminApi.teams });
  const settings = useQuery({ queryKey: ["settings"], queryFn: adminApi.settings });

  const updateOrg = useMutation({
    mutationFn: () => adminApi.updateOrganization({ name: orgName }),
    onSuccess: () => {
      toast.push({ title: "Organization updated", tone: "success" });
      queryClient.invalidateQueries({ queryKey: ["organization"] });
    },
    onError: (error: Error) => toast.push({ title: "Update failed", description: error.message, tone: "error" }),
  });

  const startMfa = async () => {
    try {
      const result = await authApi.mfaSetup();
      setMfaSecret(result.secret);
      setMfaUri(result.otpauth_uri);
      setMfaOpen(true);
    } catch (error) {
      toast.push({ title: "MFA setup failed", description: (error as Error).message, tone: "error" });
    }
  };

  const enableMfa = useMutation({
    mutationFn: () => authApi.mfaEnable(mfaCode),
    onSuccess: async () => {
      toast.push({ title: "MFA enabled", tone: "success" });
      setMfaOpen(false);
      setMfaCode("");
      await refresh();
    },
    onError: (error: Error) => toast.push({ title: "Invalid code", description: error.message, tone: "error" }),
  });

  const disableMfa = useMutation({
    mutationFn: () => authApi.mfaDisable(disablePassword, disableCode),
    onSuccess: async () => {
      toast.push({ title: "MFA disabled", tone: "info" });
      setDisableOpen(false);
      setDisablePassword("");
      setDisableCode("");
      await refresh();
    },
    onError: (error: Error) => toast.push({ title: "Could not disable MFA", description: error.message, tone: "error" }),
  });

  const changePassword = useMutation({
    mutationFn: () => authApi.changePassword(passwords.current, passwords.next),
    onSuccess: () => {
      toast.push({ title: "Password updated", tone: "success" });
      setPasswords({ current: "", next: "" });
    },
    onError: (error: Error) => toast.push({ title: "Password change failed", description: error.message, tone: "error" }),
  });

  const runtime = settings.data?.runtime ?? {};

  return (
    <div className="space-y-4">
      <PageHeader eyebrow="Administration" title="Organization Settings" description="Tenant profile, teams, runtime configuration and your account security." />

      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Organization profile" description={organization.data?.slug ? `Tenant slug: ${organization.data.slug}` : ""} />
          <div className="space-y-3 p-4">
            <Field label="Organization name">
              {can("org:admin") ? (
                <div className="flex gap-2">
                  <Input value={orgName || organization.data?.name || ""} onChange={(event) => setOrgName(event.target.value)} />
                  <Button variant="secondary" loading={updateOrg.isPending} disabled={!orgName || orgName === organization.data?.name} onClick={() => updateOrg.mutate()}>Save</Button>
                </div>
              ) : (
                <p className="rounded-md border border-border bg-base/40 px-3 py-2 text-sm text-ink">{organization.data?.name || "—"}</p>
              )}
            </Field>
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
              {[
                ["Plan", organization.data?.plan || "—"],
                ["Members", organization.data?.member_count ?? "—"],
                ["Created", formatDateTime(organization.data?.created_at)],
                ["Demo", (organization.data?.settings as any)?.demo ? "Yes — synthetic data" : "No"],
              ].map(([label, value]) => (
                <div key={label}><p className="label">{label}</p><p className="mt-1 text-sm text-ink">{String(value)}</p></div>
              ))}
            </div>
          </div>
        </Card>

        <Card>
          <CardHeader title="Account security" description={user?.email} action={<Lock className="h-4 w-4 text-muted" />} />
          <div className="space-y-3 p-4">
            <div className="flex items-center justify-between rounded border border-border bg-base/40 px-3 py-2">
              <div className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-accent" /><div><p className="text-xs text-ink">Multi-factor authentication</p><p className="text-[10px] text-muted">TOTP · {user?.mfa_enabled ? "enabled" : "not enabled"}</p></div></div>
              {user?.mfa_enabled ? <Button variant="ghost" size="sm" onClick={() => setDisableOpen(true)}>Disable</Button> : <Button variant="outline" size="sm" onClick={startMfa}>Enable</Button>}
            </div>
            <div className="rounded border border-border bg-base/40 p-3">
              <p className="label mb-2">Change password</p>
              <div className="space-y-2">
                <Input type="password" placeholder="Current password" value={passwords.current} onChange={(event) => setPasswords({ ...passwords, current: event.target.value })} />
                <Input type="password" placeholder="New password (min 12 characters)" value={passwords.next} onChange={(event) => setPasswords({ ...passwords, next: event.target.value })} />
                <Button variant="secondary" size="sm" className="w-full" disabled={!passwords.current || passwords.next.length < 12} loading={changePassword.isPending} onClick={() => changePassword.mutate()}>Update password</Button>
              </div>
            </div>
            <div className="flex gap-1">
              {(user?.roles ?? []).map((role) => <Badge key={role} tone="border-accent/30 bg-accent/10 text-accent">{role.replace("_", " ")}</Badge>)}
            </div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader title="Teams" description="Business-unit ownership groups" action={<Users className="h-4 w-4 text-muted" />} />
          <div className="divide-y divide-border/50">
            {(teams.data?.items ?? []).map((team: any) => (
              <div key={team.id} className="flex items-center justify-between px-4 py-2.5">
                <div><p className="text-xs text-ink">{team.name}</p><p className="text-[10px] text-muted">{team.description || "No description"} · {team.business_unit || "unassigned"}</p></div>
                <Badge>{team.slug}</Badge>
              </div>
            ))}
            {(teams.data?.items ?? []).length === 0 ? <p className="px-4 py-6 text-xs text-muted">No teams defined.</p> : null}
          </div>
        </Card>
        <Card>
          <CardHeader title="Runtime configuration" description="Environment-driven, read-only in the UI" action={<KeyRound className="h-4 w-4 text-muted" />} />
          <div className="grid grid-cols-2 gap-3 p-4">
            {[
              ["Environment", runtime.environment],
              ["Demo mode", runtime.demo_mode ? "enabled" : "disabled"],
              ["AI provider", runtime.ai_provider],
              ["OIDC", runtime.oidc_enabled ? "enabled" : "disabled"],
              ["Scan authorization", runtime.require_scan_authorization ? "required" : "optional"],
              ["Upload limit", `${runtime.max_upload_mb} MB`],
              ["Rate limit", `${runtime.rate_limit_per_minute}/min`],
              ["Celery eager", runtime.celery_eager ? "yes (local)" : "no (broker)"],
            ].map(([label, value]) => (
              <div key={String(label)} className="rounded border border-border bg-base/40 p-2"><p className="label">{String(label)}</p><p className="mt-1 text-xs text-ink">{String(value ?? "—")}</p></div>
            ))}
          </div>
        </Card>
      </div>

      <Modal
        open={mfaOpen}
        onClose={() => setMfaOpen(false)}
        title="Enable multi-factor authentication"
        description="Add the secret to your authenticator app, then confirm a code."
        footer={<><Button variant="ghost" onClick={() => setMfaOpen(false)}>Cancel</Button><Button variant="primary" loading={enableMfa.isPending} disabled={mfaCode.length !== 6} onClick={() => enableMfa.mutate()}>Enable MFA</Button></>}
      >
        <div className="space-y-3">
          <div className="rounded border border-border bg-base/50 p-3">
            <p className="label mb-1">Secret</p>
            <p className="mono break-all text-sm text-accent">{mfaSecret}</p>
          </div>
          <div className="rounded border border-border bg-base/50 p-3">
            <p className="label mb-1">otpauth URI</p>
            <p className="mono break-all text-[10px] text-muted">{mfaUri}</p>
          </div>
          <Field label="Verification code"><Input value={mfaCode} onChange={(event) => setMfaCode(event.target.value)} inputMode="numeric" maxLength={6} className="font-mono tracking-[0.3em]" /></Field>
        </div>
      </Modal>

      <Modal
        open={disableOpen}
        onClose={() => setDisableOpen(false)}
        title="Disable MFA"
        description="Confirm your password and a current authenticator code."
        footer={<><Button variant="ghost" onClick={() => setDisableOpen(false)}>Cancel</Button><Button variant="danger" loading={disableMfa.isPending} onClick={() => disableMfa.mutate()}>Disable</Button></>}
      >
        <div className="space-y-3">
          <Field label="Password"><Input type="password" value={disablePassword} onChange={(event) => setDisablePassword(event.target.value)} /></Field>
          <Field label="Authenticator code"><Input value={disableCode} onChange={(event) => setDisableCode(event.target.value)} maxLength={6} className="font-mono tracking-[0.3em]" /></Field>
        </div>
      </Modal>
    </div>
  );
}
