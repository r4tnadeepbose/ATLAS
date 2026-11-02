import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { ShieldCheck } from "lucide-react";

export function AuthLayout({ children, footer }: { children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-base px-4 py-10">
      <div className="pointer-events-none absolute inset-0 grid-lines opacity-40" />
      <div className="pointer-events-none absolute -left-40 top-0 h-[480px] w-[480px] rounded-full bg-accent/[0.06] blur-[120px]" />
      <div className="pointer-events-none absolute -right-40 bottom-0 h-[520px] w-[520px] rounded-full bg-cyan/[0.05] blur-[140px]" />
      <div className="relative w-full max-w-[400px] animate-fade-in">
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-lg border border-accent/30 bg-accent/10">
            <ShieldCheck className="h-6 w-6 text-accent" />
          </div>
          <h1 className="text-2xl font-bold tracking-[0.3em] text-ink">ATLAS</h1>
          <p className="mt-1 text-[10px] uppercase tracking-[0.16em] text-muted">Advanced Threat &amp; Asset Lifecycle Security</p>
        </div>
        <div className="panel p-6">{children}</div>
        <p className="mt-4 text-center text-[10px] text-muted/70">
          Unified Intelligence. Complete Visibility. Proactive Defence.
        </p>
        {footer}
        <div className="mt-3 text-center">
          <Link to="/" className="text-[10px] text-muted/60 hover:text-accent">
            ATLAS v1.0 · Enterprise Security Orchestration
          </Link>
        </div>
      </div>
    </div>
  );
}

export function ExecutiveLayout({ children }: { children: ReactNode }) {
  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-3 rounded-md border border-cyan/20 bg-cyan/[0.04] px-3.5 py-2">
        <p className="text-2xs text-cyan/90">Executive view · business risk and posture metrics, with drill-through to technical detail.</p>
        <span className="rounded border border-cyan/25 px-1.5 py-0.5 text-[9px] uppercase tracking-widest text-cyan/80">Board Mode</span>
      </div>
      {children}
    </div>
  );
}
