export const API_BASE = "/api/v1";

const ACCESS_KEY = "atlas.access_token";
const REFRESH_KEY = "atlas.refresh_token";
const USER_KEY = "atlas.user";

export class ApiRequestError extends Error {
  status: number;
  code: string;
  details: unknown;

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export const tokenStore = {
  get access() {
    return localStorage.getItem(ACCESS_KEY);
  },
  get refresh() {
    return localStorage.getItem(REFRESH_KEY);
  },
  get user() {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  },
  save(access: string, refresh: string, user?: unknown) {
    localStorage.setItem(ACCESS_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
    if (user) localStorage.setItem(USER_KEY, JSON.stringify(user));
  },
  saveUser(user: unknown) {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  },
  clear() {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(USER_KEY);
  },
};

let refreshPromise: Promise<boolean> | null = null;

async function refreshTokens(): Promise<boolean> {
  if (!tokenStore.refresh) return false;
  if (!refreshPromise) {
    refreshPromise = (async () => {
      try {
        const response = await fetch(`${API_BASE}/auth/refresh`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: tokenStore.refresh }),
        });
        if (!response.ok) return false;
        const data = await response.json();
        tokenStore.save(data.access_token, data.refresh_token, data.user);
        return true;
      } catch {
        return false;
      } finally {
        refreshPromise = null;
      }
    })();
  }
  return refreshPromise;
}

async function request<T>(path: string, options: RequestInit = {}, retry = true): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (tokenStore.access) headers.set("Authorization", `Bearer ${tokenStore.access}`);
  if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  } catch {
    throw new ApiRequestError(0, "network_error", "ATLAS API is unreachable. Check that the backend is running.");
  }

  if (response.status === 401 && retry && tokenStore.refresh) {
    const refreshed = await refreshTokens();
    if (refreshed) return request<T>(path, options, false);
    tokenStore.clear();
    window.dispatchEvent(new Event("atlas:unauthenticated"));
  }

  if (response.status === 204) return undefined as T;

  const text = await response.text();
  let payload: any = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = { message: text };
    }
  }

  if (!response.ok) {
    if (response.status === 401) {
      tokenStore.clear();
      window.dispatchEvent(new Event("atlas:unauthenticated"));
    }
    const body = payload || {};
    throw new ApiRequestError(
      response.status,
      body.error || "request_failed",
      body.message || body.detail?.message || `Request failed (${response.status})`,
      body.details || body.detail?.details,
    );
  }
  return payload as T;
}

function qs(params: Record<string, unknown> | undefined): string {
  if (!params) return "";
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "" || value === false) return;
    if (Array.isArray(value)) value.forEach((item) => search.append(key, String(item)));
    else search.set(key, String(value));
  });
  const result = search.toString();
  return result ? `?${result}` : "";
}

export const api = {
  get: <T>(path: string, params?: Record<string, unknown>) => request<T>(`${path}${qs(params)}`),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PATCH", body: body === undefined ? undefined : JSON.stringify(body) }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PUT", body: body === undefined ? undefined : JSON.stringify(body) }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
  upload: <T>(path: string, formData: FormData) => request<T>(path, { method: "POST", body: formData }),
  download: async (path: string, filename: string) => {
    const headers = new Headers();
    if (tokenStore.access) headers.set("Authorization", `Bearer ${tokenStore.access}`);
    const response = await fetch(`${API_BASE}${path}`, { headers });
    if (!response.ok) throw new ApiRequestError(response.status, "download_failed", "Export failed");
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  },
};
