import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight, ChevronRight } from "lucide-react";
import { cn } from "@/utils";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  className,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-end justify-between gap-4", className)}>
      <div className="min-w-0">
        {eyebrow ? <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-accent/80">{eyebrow}</p> : null}
        <h1 className="text-xl font-semibold tracking-tight text-ink">{title}</h1>
        {description ? <p className="mt-1 max-w-3xl text-xs text-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function Breadcrumbs({ items }: { items: { label: string; to?: string }[] }) {
  return (
    <nav className="flex flex-wrap items-center gap-1 text-2xs text-muted">
      {items.map((item, index) => (
        <span key={`${item.label}-${index}`} className="flex items-center gap-1">
          {index > 0 ? <ChevronRight className="h-3 w-3 opacity-50" /> : null}
          {item.to ? (
            <Link to={item.to} className="hover:text-accent">
              {item.label}
            </Link>
          ) : (
            <span className="text-ink/80">{item.label}</span>
          )}
        </span>
      ))}
    </nav>
  );
}

export function StatCard({
  label,
  value,
  hint,
  icon,
  to,
  tone = "default",
  onClick,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon?: ReactNode;
  to?: string;
  tone?: "default" | "critical" | "high" | "medium" | "accent" | "cyan" | string;
  onClick?: () => void;
}) {
  const toneMap: Record<string, string> = {
    default: "text-ink",
    critical: "text-critical",
    high: "text-high",
    medium: "text-medium",
    accent: "text-accent",
    cyan: "text-cyan",
  };
  const toneClass = toneMap[tone] || tone;

  const content = (
    <div className="panel group flex h-full flex-col justify-between p-3.5 transition-colors hover:border-border-strong">
      <div className="flex items-start justify-between gap-2">
        <span className="label">{label}</span>
        <span className="text-muted transition-colors group-hover:text-accent">{icon}</span>
      </div>
      <div className="mt-3">
        <p className={cn("text-2xl font-semibold tabular-nums tracking-tight", toneClass)}>{value}</p>
        {hint ? <p className="mt-0.5 text-2xs text-muted">{hint}</p> : null}
      </div>
      {to ? (
        <span className="mt-2 inline-flex items-center gap-1 text-[10px] text-muted opacity-0 transition-opacity group-hover:opacity-100">
          Open <ArrowUpRight className="h-3 w-3" />
        </span>
      ) : null}
    </div>
  );

  if (to) return <Link to={to}>{content}</Link>;
  if (onClick) return <button onClick={onClick} className="text-left">{content}</button>;
  return content;
}

export function InlineStat({ label, value, tone }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-border/50 py-1.5 last:border-0">
      <span className="text-2xs text-muted">{label}</span>
      <span className={cn("text-sm font-medium tabular-nums text-ink", tone)}>{value}</span>
    </div>
  );
}

export function DemoBanner() {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-medium/30 bg-medium/5 px-3 py-2">
      <p className="text-2xs text-medium">
        Demo environment · all records are synthetic and clearly isolated from production data.
      </p>
      <span className="text-[10px] uppercase tracking-wider text-medium/70">Demo</span>
    </div>
  );
}

export function KeyValue({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={cn("min-w-0", className)}>
      <p className="label">{label}</p>
      <div className="mt-1 truncate text-sm text-ink">{children}</div>
    </div>
  );
}
