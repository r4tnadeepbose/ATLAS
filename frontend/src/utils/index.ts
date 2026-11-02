import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { UserProfile } from "@/types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" });
}

export function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function relativeTime(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const ranges: [Intl.RelativeTimeFormatUnit, number][] = [
    ["year", 60 * 60 * 24 * 365],
    ["month", 60 * 60 * 24 * 30],
    ["week", 60 * 60 * 24 * 7],
    ["day", 60 * 60 * 24],
    ["hour", 60 * 60],
    ["minute", 60],
  ];
  for (const [unit, secondsInUnit] of ranges) {
    if (Math.abs(seconds) >= secondsInUnit) return formatter.format(Math.round(seconds / secondsInUnit), unit);
  }
  return formatter.format(seconds, "second");
}

export function formatNumber(value?: number | null, digits = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return value.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: digits });
}

export function formatPercent(value?: number | null, digits = 0): string {
  if (value === null || value === undefined) return "—";
  return `${value.toFixed(digits)}%`;
}

export function titleCase(value?: string | null): string {
  if (!value) return "—";
  return value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

const ACRONYMS: Record<string, string> = {
  api: "API",
  apis: "APIs",
  cve: "CVE",
  cvss: "CVSS",
  dns: "DNS",
  http: "HTTP",
  https: "HTTPS",
  id: "ID",
  ids: "IDs",
  jwt: "JWT",
  mfa: "MFA",
  mttd: "MTTD",
  mttr: "MTTR",
  osv: "OSV",
  pii: "PII",
  rbac: "RBAC",
  sbom: "SBOM",
  sla: "SLA",
  tls: "TLS",
  url: "URL",
  vapt: "VAPT",
};

export function humanize(value?: string | null): string {
  if (!value) return "—";
  return value
    .replace(/[_-]+/g, " ")
    .split(" ")
    .filter(Boolean)
    .map((word) => ACRONYMS[word.toLowerCase()] || word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

const CATEGORY_LABELS: Record<string, string> = {
  pii: "PII",
  api_keys: "API keys",
  access_tokens: "Access tokens",
  credentials: "Credentials",
  financial: "Financial data",
  internal: "Internal",
  confidential: "Confidential",
  public: "Public",
};

export function categoryLabel(value?: string | null): string {
  if (!value) return "—";
  return CATEGORY_LABELS[value] || humanize(value);
}

const ROLE_LABELS: Record<string, string> = {
  super_admin: "Super Administrator",
  security_admin: "Security Administrator",
  soc_analyst: "SOC Analyst",
  vapt_analyst: "VAPT Analyst",
  developer: "Developer",
  executive: "Executive",
};

export function roleLabel(value?: string | null): string {
  if (!value) return "—";
  return ROLE_LABELS[value] || humanize(value);
}

export function humanizeAdapterStatus(status?: string | null): string {
  switch (status) {
    case "unavailable":
      return "Not installed";
    case "heuristic_only":
      return "Heuristic only";
    case "configured":
      return "Configured";
    case "unconfigured":
      return "Not configured";
    default:
      return humanize(status);
  }
}

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export function severityTone(severity?: string | null): string {
  switch ((severity || "").toLowerCase()) {
    case "critical":
      return "border-critical/40 bg-critical/10 text-critical";
    case "high":
      return "border-high/40 bg-high/10 text-high";
    case "medium":
      return "border-medium/40 bg-medium/10 text-medium";
    case "low":
      return "border-low/40 bg-low/10 text-low";
    default:
      return "border-border-strong bg-raised text-muted";
  }
}

export function statusTone(status?: string | null): string {
  switch ((status || "").toLowerCase()) {
    case "resolved":
    case "completed":
    case "healthy":
    case "available":
    case "analyzed":
    case "active":
    case "configured":
      return "border-accent/35 bg-accent/10 text-accent";
    case "running":
    case "in_progress":
    case "triaged":
    case "assigned":
      return "border-cyan/35 bg-cyan/10 text-cyan";
    case "failed":
    case "critical":
    case "open":
      return "border-critical/40 bg-critical/10 text-critical";
    case "queued":
    case "pending":
      return "border-medium/35 bg-medium/10 text-medium";
    case "cancelled":
    case "closed":
    case "risk_accepted":
      return "border-border-strong bg-raised text-muted";
    default:
      return "border-border-strong bg-raised text-muted";
  }
}

export function riskTone(score: number): string {
  if (score >= 85) return "text-critical";
  if (score >= 65) return "text-high";
  if (score >= 40) return "text-medium";
  if (score > 0) return "text-low";
  return "text-muted";
}

export function permissionsOf(user: UserProfile | null): Set<string> {
  return new Set(user?.permissions || []);
}

export function can(user: UserProfile | null, permission: string): boolean {
  return permissionsOf(user).has(permission);
}

export function initials(name?: string | null): string {
  if (!name) return "AT";
  return name
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("");
}

export function downloadCsv(filename: string, rows: Record<string, unknown>[], columns?: { key: string; label: string }[]) {
  const headers = columns ? columns.map((column) => column.label) : Object.keys(rows[0] || {});
  const keys = columns ? columns.map((column) => column.key) : Object.keys(rows[0] || {});
  const escape = (value: unknown) => {
    const text = value === null || value === undefined ? "" : String(value);
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  const content = [headers.map(escape).join(","), ...rows.map((row) => keys.map((key) => escape(row[key])).join(","))].join("\n");
  const blob = new Blob([content], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export function truncate(value?: string | null, length = 80): string {
  if (!value) return "—";
  return value.length > length ? `${value.slice(0, length)}…` : value;
}

export function shortId(value?: string | null): string {
  if (!value) return "—";
  return value.slice(0, 8);
}
