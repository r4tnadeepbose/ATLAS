import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { authApi } from "@/api/endpoints";
import { tokenStore } from "@/api/client";
import type { UserProfile } from "@/types";
import { can as checkPermission } from "@/utils";

interface AuthContextValue {
  user: UserProfile | null;
  loading: boolean;
  requiresBootstrap: boolean;
  login: (email: string, password: string, mfaCode?: string) => Promise<void>;
  bootstrap: (payload: { organization_name: string; full_name: string; email: string; password: string }) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(tokenStore.user);
  const [loading, setLoading] = useState(true);
  const [requiresBootstrap, setRequiresBootstrap] = useState(false);

  const refresh = useCallback(async () => {
    if (!tokenStore.access) {
      setUser(null);
      return;
    }
    try {
      const profile = await authApi.me();
      setUser(profile);
      tokenStore.saveUser(profile);
    } catch {
      setUser(null);
    }
  }, []);

  useEffect(() => {
    let active = true;
    (async () => {
      if (tokenStore.access) {
        await refresh();
        if (active) setLoading(false);
        return;
      }
      try {
        const status = await authApi.bootstrapStatus();
        if (active) setRequiresBootstrap(status.requires_bootstrap);
      } catch {
        /* backend unreachable; login screen still renders */
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [refresh]);

  useEffect(() => {
    const handler = () => setUser(null);
    window.addEventListener("atlas:unauthenticated", handler);
    return () => window.removeEventListener("atlas:unauthenticated", handler);
  }, []);

  const login = useCallback(async (email: string, password: string, mfaCode?: string) => {
    const response = await authApi.login(email, password, mfaCode);
    tokenStore.save(response.access_token, response.refresh_token, response.user);
    setUser(response.user);
    setRequiresBootstrap(false);
  }, []);

  const bootstrap = useCallback(async (payload: { organization_name: string; full_name: string; email: string; password: string }) => {
    await authApi.bootstrap(payload);
    const response = await authApi.login(payload.email, payload.password);
    tokenStore.save(response.access_token, response.refresh_token, response.user);
    setUser(response.user);
    setRequiresBootstrap(false);
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch {
      /* logout is idempotent */
    }
    tokenStore.clear();
    setUser(null);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      loading,
      requiresBootstrap,
      login,
      bootstrap,
      logout,
      refresh,
      can: (permission: string) => checkPermission(user, permission),
    }),
    [user, loading, requiresBootstrap, login, bootstrap, logout, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
}
