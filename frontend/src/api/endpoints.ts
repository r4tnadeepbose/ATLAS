import { api } from "./client";
import type {
  ApiRecord,
  Asset,
  AuthResponse,
  Classification,
  ClassificationRule,
  DashboardOverview,
  Environment,
  Finding,
  GraphEdge,
  GraphNode,
  Integration,
  Microservice,
  Notification,
  Organization,
  Page,
  RemediationTask,
  Report,
  RiskAssessment,
  ScanJob,
  ScanSchedule,
  SbomDocument,
  TriageResult,
  UserProfile,
  Vulnerability,
} from "@/types";

export const authApi = {
  bootstrapStatus: () => api.get<{ requires_bootstrap: boolean; registration_open: boolean }>("/auth/bootstrap-status"),
  bootstrap: (body: { organization_name: string; full_name: string; email: string; password: string }) =>
    api.post<{ organization: { id: string; name: string }; user: UserProfile }>("/auth/bootstrap", body),
  login: (email: string, password: string, mfa_code?: string) =>
    api.post<AuthResponse>("/auth/login", { email, password, mfa_code }),
  logout: () => api.post("/auth/logout"),
  me: () => api.get<UserProfile>("/auth/me"),
  sessions: () => api.get<{ items: Record<string, unknown>[] }>("/auth/sessions"),
  revokeSession: (id: string) => api.delete(`/auth/sessions/${id}`),
  mfaSetup: () => api.post<{ secret: string; otpauth_uri: string }>("/auth/mfa/setup"),
  mfaEnable: (code: string) => api.post("/auth/mfa/enable", { code }),
  mfaDisable: (password: string, code: string) => api.post("/auth/mfa/disable", { password, code }),
  changePassword: (current_password: string, new_password: string) =>
    api.post("/auth/password", { current_password, new_password }),
};

export const dashboardApi = {
  overview: () => api.get<DashboardOverview>("/dashboard/overview"),
  activity: (limit = 15) => api.get<{ items: import("@/types").ActivityItem[] }>("/dashboard/activity", { limit }),
  riskTrends: () => api.get<Record<string, unknown>>("/dashboard/risk-trends"),
  executive: () => api.get<Record<string, any>>("/dashboard/executive"),
  jobs: () => api.get<{ items: Record<string, any>[] }>("/dashboard/background-jobs"),
};

export const assetApi = {
  list: (params: Record<string, unknown>) => api.get<Page<Asset>>("/assets", params),
  get: (id: string) => api.get<Asset>(`/assets/${id}`),
  summary: () => api.get<Record<string, any>>("/assets/summary"),
  discovered: (days = 30) => api.get<{ items: Asset[] }>("/assets/discovered", { days }),
  create: (body: Record<string, unknown>) => api.post<Asset>("/assets", body),
  update: (id: string, body: Record<string, unknown>) => api.patch<Asset>(`/assets/${id}`, body),
  remove: (id: string) => api.delete(`/assets/${id}`),
  environments: () => api.get<{ items: Environment[] }>("/environments"),
  createEnvironment: (body: Record<string, unknown>) => api.post<Environment>("/environments", body),
};

export const serviceApi = {
  list: (params: Record<string, unknown>) => api.get<Page<Microservice>>("/microservices", params),
  get: (id: string) => api.get<Microservice>(`/microservices/${id}`),
  summary: () => api.get<Record<string, any>>("/microservices/summary"),
  create: (body: Record<string, unknown>) => api.post<Microservice>("/microservices", body),
  update: (id: string, body: Record<string, unknown>) => api.patch<Microservice>(`/microservices/${id}`, body),
  remove: (id: string) => api.delete(`/microservices/${id}`),
  dependencies: (id: string) => api.get<{ items: Record<string, unknown>[] }>(`/microservices/${id}/dependencies`),
  addDependency: (id: string, body: Record<string, unknown>) =>
    api.post(`/microservices/${id}/dependencies`, body),
  graph: (params: Record<string, unknown>) =>
    api.get<{ nodes: GraphNode[]; edges: GraphEdge[] }>("/microservices/graph/relationship-map", params),
};

export const sbomApi = {
  list: (params: Record<string, unknown>) => api.get<Page<SbomDocument>>("/sbom", params),
  dashboard: () => api.get<Record<string, any>>("/sbom/dashboard"),
  get: (id: string) => api.get<SbomDocument>(`/sbom/${id}`),
  components: (id: string, params: Record<string, unknown>) => api.get<Page<any>>(`/sbom/${id}/components`, params),
  vulnerabilities: (id: string) => api.get<{ items: Vulnerability[] }>(`/sbom/${id}/vulnerabilities`),
  upload: (formData: FormData) => api.upload<SbomDocument>("/sbom/upload", formData),
  analyze: (id: string, online = true) => api.post(`/sbom/${id}/analyze?online=${online}`),
  remove: (id: string) => api.delete(`/sbom/${id}`),
  compare: (left: string, right: string) => api.get<Record<string, any>>("/sbom/compare", { left, right }),
  exportCsv: (id: string) => api.download(`/sbom/${id}/export`, `atlas-sbom-${id}.csv`),
};

export const triageApi = {
  queue: (params: Record<string, unknown>) => api.get<Page<Finding>>("/triage/queue", params),
  results: (params: Record<string, unknown>) => api.get<Page<TriageResult>>("/triage/results", params),
  dashboard: () => api.get<Record<string, any>>("/triage/dashboard"),
  analyze: (finding_id: string) => api.post<TriageResult>("/triage/analyze", { finding_id }),
  batch: (finding_ids: string[]) => api.post<{ items: TriageResult[] }>("/triage/batch", { finding_ids }),
  get: (id: string) => api.get<TriageResult & Record<string, any>>(`/triage/${id}`),
  config: () => api.get<Record<string, any>>("/triage/config"),
  saveConfig: (body: Record<string, unknown>) => api.post("/triage/config", body),
};

export const findingApi = {
  list: (params: Record<string, unknown>) => api.get<Page<Finding>>("/findings", params),
  get: (id: string) => api.get<Finding>(`/findings/${id}`),
  summary: () => api.get<Record<string, any>>("/findings/summary"),
  update: (id: string, body: Record<string, unknown>) => api.patch<Finding>(`/findings/${id}`, body),
  comment: (id: string, body: string) => api.post(`/findings/${id}/comments`, { body }),
  evidence: (id: string, body: Record<string, unknown>) => api.post(`/findings/${id}/evidence`, body),
  assign: (id: string, assignee_id: string, note?: string) =>
    api.post(`/findings/${id}/assign`, { assignee_id, note }),
  exception: (id: string, body: Record<string, unknown>) => api.post(`/findings/${id}/exception`, body),
  vulnerabilities: (params: Record<string, unknown>) => api.get<Page<Vulnerability>>("/vulnerabilities", params),
  vulnerability: (id: string) => api.get<Vulnerability & { affected_findings: Finding[] }>(`/vulnerabilities/${id}`),
  lookup: (identifier: string) => api.post<Vulnerability>(`/vulnerabilities/lookup/${identifier}`),
};

export const scanApi = {
  list: (params: Record<string, unknown>) => api.get<Page<ScanJob>>("/scans", params),
  get: (id: string) => api.get<ScanJob>(`/scans/${id}`),
  dashboard: () => api.get<Record<string, any>>("/scans/dashboard"),
  tools: () => api.get<{ items: Record<string, any>[] }>("/scans/tools"),
  create: (body: Record<string, unknown>) => api.post<ScanJob>("/scans", body),
  cancel: (id: string) => api.post(`/scans/${id}/cancel`),
  results: (id: string) => api.get<{ items: Record<string, any>[] }>(`/scans/${id}/results`),
  schedules: () => api.get<{ items: ScanSchedule[] }>("/scan-schedules"),
  createSchedule: (body: Record<string, unknown>) => api.post<ScanSchedule>("/scan-schedules", body),
  updateSchedule: (id: string, body: Record<string, unknown>) => api.patch(`/scan-schedules/${id}`, body),
  deleteSchedule: (id: string) => api.delete(`/scan-schedules/${id}`),
};

export const apiInventoryApi = {
  list: (params: Record<string, unknown>) => api.get<Page<ApiRecord>>("/apis", params),
  get: (id: string) => api.get<ApiRecord>(`/apis/${id}`),
  dashboard: () => api.get<Record<string, any>>("/apis/dashboard"),
  create: (body: Record<string, unknown>) => api.post<ApiRecord>("/apis", body),
  update: (id: string, body: Record<string, unknown>) => api.patch<ApiRecord>(`/apis/${id}`, body),
  importSpec: (formData: FormData) => api.upload<ApiRecord & { endpoints_imported: number }>("/apis/import", formData),
  rerunChecks: (id: string) => api.post<{ status: string; new_findings: number }>(`/apis/${id}/checks`),
  exportCsv: (id: string) => api.download(`/apis/${id}/export`, `atlas-api-${id}.csv`),
};

export const classificationApi = {
  list: (params: Record<string, unknown>) => api.get<Page<Classification>>("/classification", params),
  dashboard: () => api.get<Record<string, any>>("/classification/dashboard"),
  get: (id: string) => api.get<Classification & Record<string, any>>(`/classification/${id}`),
  analyze: (body: Record<string, unknown>) => api.post<Record<string, any>>("/classification/analyze", body),
  rules: () => api.get<{ items: ClassificationRule[] }>("/classification/rules"),
  createRule: (body: Record<string, unknown>) => api.post<ClassificationRule>("/classification/rules", body),
  updateRule: (id: string, body: Record<string, unknown>) => api.patch<ClassificationRule>(`/classification/rules/${id}`, body),
  seedRules: () => api.post("/classification/seed-rules"),
};

export const riskApi = {
  list: (params: Record<string, unknown>) => api.get<Page<RiskAssessment>>("/risks", params),
  get: (id: string) => api.get<RiskAssessment>(`/risks/${id}`),
  summary: () => api.get<Record<string, any>>("/risks/summary"),
  recompute: () => api.post<{ updated: number }>("/risks/recompute"),
  accept: (id: string, reason: string, expires_at?: string) =>
    api.post(`/risks/${id}/accept`, { reason, expires_at }),
  assign: (id: string, body: Record<string, unknown>) => api.patch(`/risks/${id}`, body),
  exceptions: () => api.get<{ items: Record<string, any>[] }>("/risks/exceptions"),
  createException: (body: Record<string, unknown>) => api.post("/risks/exceptions", body),
  tasks: (params: Record<string, unknown>) => api.get<Page<RemediationTask>>("/remediation-tasks", params),
  createTask: (body: Record<string, unknown>) => api.post<RemediationTask>("/remediation-tasks", body),
  updateTask: (id: string, body: Record<string, unknown>) => api.patch<RemediationTask>(`/remediation-tasks/${id}`, body),
};

export const notificationApi = {
  list: (params: Record<string, unknown>) => api.get<Page<Notification>>("/notifications", params),
  unread: () => api.get<{ unread: number }>("/notifications/unread-count"),
  markRead: (id: string) => api.post(`/notifications/${id}/read`),
  markAll: () => api.post<{ updated: number }>("/notifications/read-all"),
  rules: () => api.get<{ items: Record<string, any>[] }>("/notifications/rules"),
  createRule: (body: Record<string, unknown>) => api.post("/notifications/rules", body),
  updateRule: (id: string, body: Record<string, unknown>) => api.patch(`/notifications/rules/${id}`, body),
  test: () => api.post("/notifications/test", {}),
};

export const reportApi = {
  list: (params: Record<string, unknown>) => api.get<Page<Report>>("/reports", params),
  types: () => api.get<{ items: { key: string; name: string }[] }>("/reports/types"),
  create: (body: Record<string, unknown>) => api.post<Report>("/reports", body),
  get: (id: string) => api.get<Report>(`/reports/${id}`),
  download: (id: string, filename: string) => api.download(`/reports/${id}/download`, filename),
};

export const adminApi = {
  users: (params: Record<string, unknown>) => api.get<Page<UserProfile & Record<string, any>>>("/users", params),
  createUser: (body: Record<string, unknown>) => api.post("/users", body),
  updateUser: (id: string, body: Record<string, unknown>) => api.patch(`/users/${id}`, body),
  changeRole: (id: string, role: string) => api.patch(`/users/${id}/role`, { role }),
  roles: () => api.get<{ items: Record<string, any>[] }>("/users/roles/catalog"),
  rbac: () => api.get<Record<string, any>>("/rbac"),
  integrations: () => api.get<{ items: Integration[] }>("/integrations"),
  updateIntegration: (id: string, body: Record<string, unknown>) => api.patch<Integration>(`/integrations/${id}`, body),
  testIntegration: (id: string) => api.post<Record<string, any>>(`/integrations/${id}/test`),
  settings: () => api.get<Record<string, any>>("/settings"),
  saveSetting: (body: Record<string, unknown>) => api.put("/settings", body),
  organization: () => api.get<Organization>("/organizations/current"),
  updateOrganization: (body: Record<string, unknown>) => api.patch<Organization>("/organizations/current", body),
  teams: () => api.get<{ items: Record<string, any>[] }>("/organizations/teams"),
  auditLogs: (params: Record<string, unknown>) => api.get<Page<any>>("/admin/audit-logs", params),
  jobs: (params: Record<string, unknown>) => api.get<Page<any>>("/admin/background-jobs", params),
  metrics: () => api.get<Record<string, any>>("/admin/metrics"),
};
