import type { ReactNode } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { cn } from "@/utils";
import { EmptyState, ErrorState, Skeleton, Spinner } from "@/components/ui/primitives";

export interface Column<T> {
  key: string;
  label: string;
  sortable?: boolean;
  className?: string;
  render?: (row: T) => ReactNode;
  align?: "left" | "right" | "center";
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading,
  error,
  onRetry,
  onRowClick,
  sortBy,
  sortDir,
  onSort,
  emptyTitle = "No records",
  emptyDescription,
  emptyAction,
  footer,
  toolbar,
  dense,
  className,
}: {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  onRowClick?: (row: T) => void;
  sortBy?: string;
  sortDir?: "asc" | "desc";
  onSort?: (column: string) => void;
  emptyTitle?: string;
  emptyDescription?: string;
  emptyAction?: ReactNode;
  footer?: ReactNode;
  toolbar?: ReactNode;
  dense?: boolean;
  className?: string;
}) {
  if (error) {
    return <ErrorState message={(error as Error)?.message || "Request failed"} retry={onRetry} />;
  }

  return (
    <div className={cn("flex min-w-0 flex-col", className)}>
      {toolbar ? <div className="flex flex-wrap items-center gap-2 border-b border-border/70 px-3 py-2">{toolbar}</div> : null}
      <div className="hidden min-w-0 overflow-x-auto md:block">
        <table className="w-full min-w-[720px] border-collapse text-left">
          <thead>
            <tr className="border-b border-border bg-base/40">
              {columns.map((column) => {
                const active = sortBy === column.key;
                return (
                  <th
                    key={column.key}
                    className={cn(
                      "whitespace-nowrap px-3 py-2 text-2xs font-semibold uppercase tracking-[0.07em] text-muted",
                      column.align === "right" && "text-right",
                      column.align === "center" && "text-center",
                      column.sortable && onSort ? "cursor-pointer select-none hover:text-ink" : "",
                      column.className,
                    )}
                    onClick={() => column.sortable && onSort?.(column.key)}
                  >
                    <span className={cn("inline-flex items-center gap-1", column.align === "right" && "flex-row-reverse")}>
                      {column.label}
                      {column.sortable ? (
                        active ? (
                          sortDir === "asc" ? <ArrowUp className="h-3 w-3 text-accent" /> : <ArrowDown className="h-3 w-3 text-accent" />
                        ) : (
                          <ArrowUpDown className="h-3 w-3 opacity-50" />
                        )
                      ) : null}
                    </span>
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {loading
              ? Array.from({ length: 6 }).map((_, index) => (
                  <tr key={`skeleton-${index}`} className="border-b border-border/50">
                    {columns.map((column) => (
                      <td key={column.key} className="px-3 py-3">
                        <Skeleton className="h-3.5 w-full max-w-[160px]" />
                      </td>
                    ))}
                  </tr>
                ))
              : rows.map((row) => (
                  <tr
                    key={rowKey(row)}
                    onClick={() => onRowClick?.(row)}
                    className={cn(
                      "border-b border-border/50 transition-colors last:border-0",
                      onRowClick ? "cursor-pointer hover:bg-raised/60" : "hover:bg-raised/30",
                    )}
                  >
                    {columns.map((column) => (
                      <td
                        key={column.key}
                        className={cn(
                          "px-3 align-middle text-sm text-ink",
                          dense ? "py-1.5" : "py-2.5",
                          column.align === "right" && "text-right",
                          column.align === "center" && "text-center",
                          column.className,
                        )}
                      >
                        {column.render ? column.render(row) : (row as Record<string, ReactNode>)[column.key]}
                      </td>
                    ))}
                  </tr>
                ))}
          </tbody>
        </table>
      </div>

      {/* Mobile: stacked records so no column is hidden behind horizontal scroll. */}
      <div className="divide-y divide-border/50 md:hidden">
        {loading
          ? Array.from({ length: 4 }).map((_, index) => (
              <div key={`mobile-skeleton-${index}`} className="space-y-2 px-3 py-3">
                <Skeleton className="h-4 w-2/3" />
                <Skeleton className="h-3 w-1/2" />
              </div>
            ))
          : rows.map((row) => {
              const primary = columns[0];
              const actions = columns.filter((column) => !column.label);
              const details = columns.slice(1).filter((column) => column.label);
              return (
                <div
                  key={`mobile-${rowKey(row)}`}
                  role={onRowClick ? "button" : undefined}
                  tabIndex={onRowClick ? 0 : undefined}
                  onClick={() => onRowClick?.(row)}
                  onKeyDown={(event) => {
                    if (onRowClick && (event.key === "Enter" || event.key === " ")) {
                      event.preventDefault();
                      onRowClick(row);
                    }
                  }}
                  className={cn("px-3 py-2.5", onRowClick && "cursor-pointer hover:bg-raised/40")}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1 text-sm text-ink">
                      {primary.render ? primary.render(row) : (row as Record<string, ReactNode>)[primary.key]}
                    </div>
                    {actions.length ? (
                      <div className="flex shrink-0 gap-1" onClick={(event) => event.stopPropagation()}>
                        {actions.map((column) => <div key={column.key}>{column.render?.(row)}</div>)}
                      </div>
                    ) : null}
                  </div>
                  <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1">
                    {details.map((column) => (
                      <div key={column.key} className="flex items-center gap-1 text-[10px] text-muted">
                        <span>{column.label}:</span>
                        <span className="text-ink">{column.render ? column.render(row) : (row as Record<string, ReactNode>)[column.key]}</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
      </div>
      {!loading && rows.length === 0 ? (
        <EmptyState title={emptyTitle} description={emptyDescription} action={emptyAction} />
      ) : null}
      {footer}
    </div>
  );
}

export function TableLoadingOverlay({ visible }: { visible: boolean }) {
  if (!visible) return null;
  return (
    <div className="flex items-center justify-center gap-2 py-2 text-xs text-muted">
      <Spinner /> Refreshing…
    </div>
  );
}
