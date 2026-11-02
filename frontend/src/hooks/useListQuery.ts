import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { Page } from "@/types";

export interface ListState {
  page: number;
  pageSize: number;
  q: string;
  sortBy?: string;
  sortDir: "asc" | "desc";
}

export function useListQuery<T>(
  key: string[],
  fetcher: (params: Record<string, unknown>) => Promise<Page<T>>,
  options?: {
    initialSort?: string;
    initialDir?: "asc" | "desc";
    initialPageSize?: number;
    filters?: Record<string, unknown>;
    enabled?: boolean;
  },
) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(options?.initialPageSize ?? 25);
  const [q, setQ] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");
  const [sortBy, setSortBy] = useState<string | undefined>(options?.initialSort);
  const [sortDir, setSortDir] = useState<"asc" | "desc">(options?.initialDir ?? "desc");

  useEffect(() => {
    const handle = window.setTimeout(() => setDebouncedQ(q), 300);
    return () => clearTimeout(handle);
  }, [q]);

  useEffect(() => {
    setPage(1);
  }, [debouncedQ, pageSize, sortBy, sortDir, JSON.stringify(options?.filters ?? {})]);

  const filtersKey = JSON.stringify(options?.filters ?? {});
  const params = useMemo(
    () => ({
      page,
      page_size: pageSize,
      q: debouncedQ || undefined,
      sort_by: sortBy,
      sort_dir: sortDir,
      ...(JSON.parse(filtersKey) as Record<string, unknown>),
    }),
    [page, pageSize, debouncedQ, sortBy, sortDir, filtersKey],
  );

  const query = useQuery({
    queryKey: [...key, params],
    queryFn: () => fetcher(params),
    enabled: options?.enabled ?? true,
    placeholderData: (previous) => previous,
  });

  const onSort = (column: string) => {
    if (sortBy === column) setSortDir((direction) => (direction === "asc" ? "desc" : "asc"));
    else {
      setSortBy(column);
      setSortDir("desc");
    }
  };

  return {
    ...query,
    rows: query.data?.items ?? [],
    pagination: query.data?.pagination,
    page,
    pageSize,
    q,
    setPage,
    setPageSize,
    setQ,
    sortBy,
    sortDir,
    onSort,
    state: { page, pageSize, q, sortBy, sortDir } as ListState,
  };
}
