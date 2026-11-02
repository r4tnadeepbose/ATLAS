import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, Building2, Eye, EyeOff, LockKeyhole, ShieldCheck } from "lucide-react";
import { AuthLayout } from "@/layouts/AuthLayout";
import { useAuth } from "@/context/AuthContext";
import { authApi } from "@/api/endpoints";
import { ApiRequestError } from "@/api/client";
import { Button, Field, Input, Spinner } from "@/components/ui/primitives";

const DEMO_ACCOUNTS = [
  ["admin@atlas.demo", "Aarav Sharma", "Super Administrator"],
  ["security@atlas.demo", "Ananya Iyer", "Security Administrator"],
  ["soc@atlas.demo", "Rohan Mehta", "SOC Analyst"],
  ["vapt@atlas.demo", "Ishita Nair", "VAPT Analyst"],
  ["dev@atlas.demo", "Arjun Patel", "Developer"],
  ["exec@atlas.demo", "Meera Krishnan", "Executive"],
];

export function LoginPage() {
  const { login, bootstrap, requiresBootstrap, user } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState<"login" | "bootstrap">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showMfa, setShowMfa] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [fullName, setFullName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [demo, setDemo] = useState(false);

  useEffect(() => {
    authApi
      .bootstrapStatus()
      .then((status) => setDemo(Boolean((status as Record<string, unknown>).demo)))
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (requiresBootstrap) setMode("bootstrap");
  }, [requiresBootstrap]);

  useEffect(() => {
    if (user) navigate("/", { replace: true });
  }, [user, navigate]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === "bootstrap") {
        await bootstrap({ organization_name: organizationName, full_name: fullName, email, password });
      } else {
        await login(email, password, mfaCode || undefined);
      }
      navigate("/", { replace: true });
    } catch (err) {
      setError(err instanceof ApiRequestError ? err.message : "Sign-in failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthLayout>
      <div className="mb-3">
        <h2 className="text-base font-semibold text-ink">{mode === "bootstrap" ? "Initialize your ATLAS workspace" : "Sign in to ATLAS"}</h2>
        <p className="mt-0.5 text-[11px] leading-snug text-muted">
          {mode === "bootstrap"
            ? "Create the first organization and platform owner. This screen is only available before any account exists."
            : "Use your organization credentials. MFA is available when enabled for your account."}
        </p>
      </div>

      {mode === "bootstrap" ? (
        <div className="mb-4 flex items-start gap-2 rounded border border-medium/30 bg-medium/5 px-3 py-2 text-2xs text-medium">
          <Building2 className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          First-run bootstrap creates a super administrator. Subsequent users are invited by an administrator.
        </div>
      ) : null}

      <form onSubmit={submit} className="space-y-2">
        {mode === "bootstrap" ? (
          <>
            <Field label="Organization name">
              <Input value={organizationName} onChange={(event) => setOrganizationName(event.target.value)} placeholder="Acme Security" required minLength={2} />
            </Field>
            <Field label="Full name">
              <Input value={fullName} onChange={(event) => setFullName(event.target.value)} placeholder="Alex Morgan" required minLength={2} />
            </Field>
          </>
        ) : null}

        <Field label="Work email">
          <Input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" autoComplete="username" required />
        </Field>
        <Field label={mode === "bootstrap" ? "Password (minimum 12 characters)" : "Password"}>
          <div className="relative">
            <Input type={showPassword ? "text" : "password"} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="••••••••••••" autoComplete={mode === "bootstrap" ? "new-password" : "current-password"} required minLength={mode === "bootstrap" ? 12 : 1} className="pr-10" />
            <button
              type="button"
              onClick={() => setShowPassword((value) => !value)}
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-muted hover:text-ink"
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
        </Field>
        {mode === "login" ? (
          showMfa ? (
            <Field label="MFA code" hint="Required only when MFA is enabled for your account.">
              <Input autoFocus value={mfaCode} onChange={(event) => setMfaCode(event.target.value)} placeholder="000000" inputMode="numeric" maxLength={6} className="font-mono tracking-[0.3em]" />
            </Field>
          ) : (
            <button
              type="button"
              onClick={() => setShowMfa(true)}
              className="text-2xs text-muted underline-offset-2 hover:text-accent hover:underline"
            >
              Have an MFA code?
            </button>
          )
        ) : null}

        {error ? <div className="rounded border border-critical/30 bg-critical/10 px-3 py-2 text-xs text-critical">{error}</div> : null}

        <Button type="submit" variant="primary" className="w-full" loading={busy}>
          {mode === "bootstrap" ? "Create workspace" : "Sign in"} <ArrowRight className="h-4 w-4" />
        </Button>
      </form>

      {mode === "login" && requiresBootstrap ? (
        <button onClick={() => setMode("bootstrap")} className="mt-3 w-full text-center text-2xs text-accent hover:underline">
          This instance has no users — initialize ATLAS
        </button>
      ) : null}

      {demo && mode === "login" ? (
        <div className="mt-3 rounded border border-border bg-base/50 p-2.5">
          <div className="mb-1.5 flex flex-wrap items-center justify-between gap-1">
            <span className="flex items-center gap-1">
              <ShieldCheck className="h-3 w-3 text-accent" />
              <span className="text-[9px] font-medium uppercase tracking-wide text-muted">Demo Accounts</span>
            </span>
            <span className="text-[9px] text-muted">Password: <span className="font-mono text-ink">AtlasDemo!2026</span></span>
          </div>
          <div className="grid grid-cols-2 gap-1 sm:grid-cols-3">
            {DEMO_ACCOUNTS.map(([demoEmail, demoName, role]) => (
              <button
                key={demoEmail}
                type="button"
                title={`${demoName} · ${demoEmail}`}
                onClick={() => {
                  setEmail(demoEmail);
                  setPassword("AtlasDemo!2026");
                }}
                className="min-w-0 rounded border border-border/70 bg-base/40 px-1.5 py-1 text-left transition-colors hover:border-accent/40 hover:bg-raised"
              >
                <span className="block truncate text-[10px] font-semibold text-ink">{demoName}</span>
                <span className="block truncate text-[9px] text-muted">{role}</span>
                <span className="mt-0.5 block truncate font-mono text-[8px] text-muted/80">{demoEmail}</span>
              </button>
            ))}
          </div>
          <p className="mt-1.5 text-[9px] leading-snug text-muted/80">
            Click a card to fill credentials. Other users sign in with their own email.
          </p>
        </div>
      ) : null}

      <div className="mt-3 flex items-center justify-center gap-1.5 text-[9px] text-muted/70">
        <LockKeyhole className="h-3 w-3" /> Server-side RBAC · JWT sessions · tenant isolation
      </div>
    </AuthLayout>
  );
}
