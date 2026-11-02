import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { assetApi } from "@/api/endpoints";
import { useAuth } from "@/context/AuthContext";
import type { Environment } from "@/types";

interface EnvironmentContextValue {
  environments: Environment[];
  selectedEnvironment: Environment | null;
  selectedEnvironmentId: string;
  setSelectedEnvironmentId: (id: string) => void;
}

const EnvironmentContext = createContext<EnvironmentContextValue | null>(null);

export function EnvironmentProvider({ children }: { children: ReactNode }) {
  const { user, can } = useAuth();
  const { data } = useQuery({
    queryKey: ["environments", user?.organization_id],
    queryFn: assetApi.environments,
    enabled: Boolean(user) && can("assets:read"),
  });
  const environments = useMemo(() => data?.items ?? [], [data]);
  const [selectedEnvironmentId, setSelectedEnvironmentId] = useState<string>(
    () => localStorage.getItem("atlas.environment") || "",
  );

  useEffect(() => {
    if (selectedEnvironmentId && !environments.some((environment) => environment.id === selectedEnvironmentId)) {
      setSelectedEnvironmentId("");
    }
  }, [environments, selectedEnvironmentId]);

  useEffect(() => {
    if (selectedEnvironmentId) localStorage.setItem("atlas.environment", selectedEnvironmentId);
  }, [selectedEnvironmentId]);

  const selectedEnvironment = environments.find((environment) => environment.id === selectedEnvironmentId) || null;

  const value = useMemo(
    () => ({ environments, selectedEnvironment, selectedEnvironmentId, setSelectedEnvironmentId }),
    [environments, selectedEnvironment, selectedEnvironmentId],
  );

  return <EnvironmentContext.Provider value={value}>{children}</EnvironmentContext.Provider>;
}

export function useEnvironment() {
  const context = useContext(EnvironmentContext);
  if (!context) throw new Error("useEnvironment must be used within EnvironmentProvider");
  return context;
}
