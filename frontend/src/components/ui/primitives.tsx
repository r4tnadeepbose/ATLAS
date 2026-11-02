import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";
import { createPortal } from "react-dom";
import { X, Search, Loader2, AlertTriangle, Inbox, ChevronLeft, ChevronRight, Check } from "lucide-react";
import { cn, severityTone, statusTone, titleCase } from "@/utils";

/* ---------------------------------- Button --------------------------------- */

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "outline";
type ButtonSize = "sm" | "md" | "lg" | "icon";

const buttonVariants: Record<ButtonVariant, string> = {
  primary: "bg-accent text-on-accent hover:brightness-110 border border-accent/60",
  secondary: "bg-raised text-ink border border-border-strong hover:bg-border/40",
  ghost: "bg-transparent text-muted hover:text-ink hover:bg-raised/70 border border-transparent",
  danger: "bg-critical/15 text-critical border border-critical/35 hover:bg-critical/25",
  outline: "bg-transparent text-ink border border-border-strong hover:border-accent/50 hover:text-accent",
};

const buttonSizes: Record<ButtonSize, string> = {
  sm: "h-8 px-3 text-xs gap-1.5",
  md: "h-9 px-3.5 text-sm gap-2",
  lg: "h-11 px-5 text-sm gap-2",
  icon: "h-8 w-8 p-0",
};

export function Button({
  variant = "secondary",
  size = "md",
  className,
  loading,
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; size?: ButtonSize; loading?: boolean }) {
  return (
    <button
      className={cn(
        "inline-flex shrink-0 items-center justify-center rounded-md font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        buttonVariants[variant],
        buttonSizes[size],
        className,
      )}
      disabled={props.disabled || loading}
      {...props}
    >
      {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
      {children}
    </button>
  );
}

/* ----------------------------------- Card ---------------------------------- */

export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("panel", className)}>{children}</div>;
}

export function CardHeader({
  title,
  description,
  action,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-start justify-between gap-4 border-b border-border/70 px-4 py-3", className)}>
      <div className="min-w-0">
        <h3 className="text-sm font-semibold text-ink">{title}</h3>
        {description ? <p className="mt-0.5 text-xs text-muted">{description}</p> : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

/* ---------------------------------- Badges --------------------------------- */

export function Badge({
  children,
  className,
  tone,
}: {
  children: ReactNode;
  className?: string;
  tone?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 whitespace-nowrap rounded border px-1.5 py-0.5 text-2xs font-medium uppercase tracking-wide",
        tone || "border-border-strong bg-raised text-muted",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ severity, className }: { severity?: string | null; className?: string }) {
  return (
    <Badge tone={severityTone(severity)} className={className}>
      {severity || "unknown"}
    </Badge>
  );
}

export function StatusBadge({ status, className }: { status?: string | null; className?: string }) {
  return (
    <Badge tone={statusTone(status)} className={className}>
      {titleCase(status)}
    </Badge>
  );
}

/* ---------------------------------- Inputs --------------------------------- */

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-9 w-full rounded-md border border-border-strong bg-base px-3 text-sm text-ink placeholder:text-muted/70 focus:border-accent/60 focus:outline-none",
        className,
      )}
      {...props}
    />
  );
}

export function Textarea({ className, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={cn(
        "w-full rounded-md border border-border-strong bg-base px-3 py-2 text-sm text-ink placeholder:text-muted/70 focus:border-accent/60 focus:outline-none",
        className,
      )}
      {...props}
    />
  );
}

export function Select({ className, children, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn(
        "h-9 w-full appearance-none rounded-md border border-border-strong bg-base px-3 pr-8 text-sm text-ink focus:border-accent/60 focus:outline-none",
        "bg-[url('data:image/svg+xml;charset=US-ASCII,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2212%22%20height%3D%2212%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%238995A5%22%20stroke-width%3D%222%22%3E%3Cpath%20d%3D%22m6%209%206%206%206-6%22%2F%3E%3C%2Fsvg%3E')] bg-[length:12px] bg-[right_0.75rem_center] bg-no-repeat",
        className,
      )}
      {...props}
    >
      {children}
    </select>
  );
}

export function Field({ label, hint, children, className }: { label: string; hint?: string; children: ReactNode; className?: string }) {
  return (
    <label className={cn("block space-y-1.5", className)}>
      <span className="label block">{label}</span>
      {children}
      {hint ? <span className="block text-2xs text-muted/80">{hint}</span> : null}
    </label>
  );
}

export function Checkbox({
  checked,
  onChange,
  label,
  className,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: ReactNode;
  className?: string;
}) {
  return (
    <label className={cn("flex cursor-pointer items-center gap-2 text-sm text-ink", className)}>
      <span className={cn("relative flex h-4 w-4 items-center justify-center")}>
        <input
          type="checkbox"
          checked={checked}
          onChange={(event) => onChange(event.target.checked)}
          className="peer h-4 w-4 cursor-pointer appearance-none rounded border border-border-strong bg-base checked:border-accent checked:bg-accent"
        />
        <Check className="pointer-events-none absolute h-3 w-3 text-on-accent opacity-0 peer-checked:opacity-100" strokeWidth={3} />
      </span>
      {label}
    </label>
  );
}

export function Switch({
  checked,
  onChange,
  label,
  disabled,
  className,
  ariaLabel,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label?: string;
  disabled?: boolean;
  className?: string;
  ariaLabel?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel || (!label ? "Toggle setting" : undefined)}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        "inline-flex shrink-0 items-center gap-2 text-sm text-ink transition-opacity disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors duration-150",
          checked ? "border-accent/60 bg-accent" : "border-border-strong bg-base",
        )}
      >
        <span
          className={cn(
            "pointer-events-none absolute left-[3px] top-1/2 h-3.5 w-3.5 -translate-y-1/2 rounded-full shadow-sm transition-transform duration-150",
            checked ? "translate-x-[16px] bg-on-accent" : "translate-x-0 bg-muted",
          )}
        />
      </span>
      {label ? <span className="whitespace-nowrap leading-none">{label}</span> : null}
    </button>
  );
}

/* --------------------------------- Feedback -------------------------------- */

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn("h-4 w-4 animate-spin text-muted", className)} />;
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("relative overflow-hidden rounded bg-raised/80", className)}><div className="absolute inset-0 -translate-x-full animate-shimmer bg-gradient-to-r from-transparent via-white/5 to-transparent" /></div>;
}

export function EmptyState({ icon, title, description, action, className }: { icon?: ReactNode; title: string; description?: string; action?: ReactNode; className?: string }) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-3 px-6 py-14 text-center", className)}>
      <div className="flex h-11 w-11 items-center justify-center rounded-lg border border-border bg-raised text-muted">
        {icon || <Inbox className="h-5 w-5" />}
      </div>
      <div>
        <p className="text-sm font-medium text-ink">{title}</p>
        {description ? <p className="mx-auto mt-1 max-w-md text-xs text-muted">{description}</p> : null}
      </div>
      {action}
    </div>
  );
}

export function ErrorState({ message, retry, className }: { message: string; retry?: () => void; className?: string }) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-3 px-6 py-12 text-center", className)}>
      <div className="flex h-11 w-11 items-center justify-center rounded-lg border border-critical/30 bg-critical/10 text-critical">
        <AlertTriangle className="h-5 w-5" />
      </div>
      <div>
        <p className="text-sm font-medium text-ink">Unable to load data</p>
        <p className="mx-auto mt-1 max-w-md text-xs text-muted">{message}</p>
      </div>
      {retry ? (
        <Button variant="outline" size="sm" onClick={retry}>
          Try again
        </Button>
      ) : null}
    </div>
  );
}

/* --------------------------------- Progress -------------------------------- */

export function ProgressBar({ value, tone, className }: { value: number; tone?: string; className?: string }) {
  return (
    <div className={cn("h-1.5 w-full overflow-hidden rounded-full bg-raised", className)}>
      <div className={cn("h-full rounded-full transition-all", tone || "bg-accent")} style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
    </div>
  );
}

/* ---------------------------------- Modal ---------------------------------- */

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  size = "md",
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  size?: "sm" | "md" | "lg" | "xl";
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  if (!open) return null;
  const widths = { sm: "max-w-sm", md: "max-w-lg", lg: "max-w-2xl", xl: "max-w-4xl" };
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/65 backdrop-blur-[2px]" onClick={onClose} />
      <div className={cn("relative z-10 w-full animate-fade-in overflow-hidden rounded-lg border border-border-strong bg-panel shadow-2xl", widths[size])}>
        <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
          <div>
            <h2 className="text-base font-semibold text-ink">{title}</h2>
            {description ? <p className="mt-0.5 text-xs text-muted">{description}</p> : null}
          </div>
          <button onClick={onClose} className="rounded p-1 text-muted hover:bg-raised hover:text-ink" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="max-h-[70vh] overflow-y-auto px-5 py-4">{children}</div>
        {footer ? <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">{footer}</div> : null}
      </div>
    </div>,
    document.body,
  );
}

export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel = "Confirm",
  destructive,
  loading,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  description: string;
  confirmLabel?: string;
  destructive?: boolean;
  loading?: boolean;
}) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      description={description}
      size="sm"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant={destructive ? "danger" : "primary"} onClick={onConfirm} loading={loading}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <p className="text-sm text-muted">This action is recorded in the organization audit trail.</p>
    </Modal>
  );
}

/* ----------------------------------- Tabs ---------------------------------- */

export function Tabs({
  tabs,
  value,
  onChange,
  className,
}: {
  tabs: { key: string; label: string; count?: number }[];
  value: string;
  onChange: (key: string) => void;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-center gap-1 border-b border-border", className)}>
      {tabs.map((tab) => (
        <button
          key={tab.key}
          onClick={() => onChange(tab.key)}
          className={cn(
            "relative -mb-px flex items-center gap-2 border-b-2 px-3 py-2 text-sm transition-colors",
            value === tab.key ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink",
          )}
        >
          {tab.label}
          {tab.count !== undefined ? <span className="rounded bg-raised px-1.5 py-0.5 text-2xs text-muted">{tab.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

/* --------------------------------- Search ---------------------------------- */

export function SearchInput({
  value,
  onChange,
  placeholder = "Search…",
  className,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
}) {
  return (
    <div className={cn("relative", className)}>
      <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
      <Input value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} className="h-8 pl-8 text-xs" />
    </div>
  );
}

/* -------------------------------- Pagination -------------------------------- */

export function Pagination({
  page,
  pages,
  total,
  pageSize,
  onPage,
  onPageSize,
}: {
  page: number;
  pages: number;
  total: number;
  pageSize: number;
  onPage: (page: number) => void;
  onPageSize?: (size: number) => void;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border/70 px-4 py-2.5">
      <span className="text-2xs text-muted">
        {total.toLocaleString()} record{total === 1 ? "" : "s"} · page {page} of {Math.max(1, pages)}
      </span>
      <div className="flex items-center gap-2">
        {onPageSize ? (
          <Select
            value={pageSize}
            onChange={(event) => onPageSize(Number(event.target.value))}
            className="h-7 w-[86px] text-2xs"
            aria-label="Rows per page"
          >
            {[10, 25, 50, 100].map((size) => (
              <option key={size} value={size}>
                {size} / page
              </option>
            ))}
          </Select>
        ) : null}
        <Button variant="ghost" size="icon" onClick={() => onPage(page - 1)} disabled={page <= 1} aria-label="Previous page">
          <ChevronLeft className="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="icon" onClick={() => onPage(page + 1)} disabled={page >= pages} aria-label="Next page">
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

/* ---------------------------------- Toast ---------------------------------- */

interface ToastItem {
  id: string;
  title: string;
  description?: string;
  tone: "success" | "error" | "info";
}

const ToastContext = createContext<{
  push: (toast: Omit<ToastItem, "id">) => void;
} | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const timers = useRef<Record<string, number>>({});

  const push = useCallback((toast: Omit<ToastItem, "id">) => {
    const id = Math.random().toString(36).slice(2);
    setToasts((current) => [...current, { ...toast, id }]);
    timers.current[id] = window.setTimeout(() => {
      setToasts((current) => current.filter((item) => item.id !== id));
    }, 4500);
  }, []);

  useEffect(() => () => Object.values(timers.current).forEach(clearTimeout), []);

  const value = useMemo(() => ({ push }), [push]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-80 flex-col gap-2">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={cn(
              "pointer-events-auto animate-fade-in rounded-md border bg-panel px-4 py-3 shadow-xl",
              toast.tone === "error" ? "border-critical/40" : toast.tone === "success" ? "border-accent/40" : "border-cyan/30",
            )}
          >
            <div className="flex items-start gap-2">
              <span className={cn("mt-1 h-1.5 w-1.5 shrink-0 rounded-full", toast.tone === "error" ? "bg-critical" : toast.tone === "success" ? "bg-accent" : "bg-cyan")} />
              <div>
                <p className="text-sm font-medium text-ink">{toast.title}</p>
                {toast.description ? <p className="mt-0.5 text-xs text-muted">{toast.description}</p> : null}
              </div>
            </div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used inside ToastProvider");
  return context;
}
