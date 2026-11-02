import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Moon, ShieldCheck, Sun } from "lucide-react";
import { useTheme } from "@/context/ThemeContext";

export function AuthLayout({ children, footer }: { children: ReactNode; footer?: ReactNode }) {
  const { theme, toggleTheme } = useTheme();
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-base px-4 py-3">
      <button
        onClick={toggleTheme}
        className="absolute right-4 top-4 z-10 rounded-md border border-border bg-surface/80 p-2 text-muted hover:text-ink"
        aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
        title={theme === "dark" ? "Light mode" : "Dark mode"}
      >
        {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
      </button>
      <div className="pointer-events-none absolute inset-0 grid-lines opacity-40" />
      <div className="pointer-events-none absolute -left-40 top-0 h-[480px] w-[480px] rounded-full bg-accent/[0.06] blur-[120px]" />
      <div className="pointer-events-none absolute -right-40 bottom-0 h-[520px] w-[520px] rounded-full bg-cyan/[0.05] blur-[140px]" />
      <div className="relative w-full max-w-[430px] animate-fade-in">
        <div className="mb-3 flex flex-col items-center text-center">
          <div className="mb-2 flex h-10 w-10 items-center justify-center rounded-lg border border-accent/30 bg-accent/10">
            <ShieldCheck className="h-5 w-5 text-accent" />
          </div>
          <h1 className="text-xl font-bold tracking-[0.3em] text-ink">ATLAS</h1>
          <p className="mt-1 text-[9px] uppercase tracking-[0.16em] text-muted">Advanced Threat &amp; Asset Lifecycle Security</p>
        </div>
        <div className="panel p-5">{children}</div>
        <p className="mt-3 text-center text-[10px] text-muted/70">
          Unified Intelligence. Complete Visibility. Proactive Defence.
        </p>
        {footer}
        <div className="mt-2 text-center">
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
