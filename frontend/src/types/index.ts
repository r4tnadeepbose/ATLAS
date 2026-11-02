export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";

export interface ApiError {
  error: string;
  message: string;
  details?: unknown;
  required?: string[];
}

export interface Pagination {
  page: number;
  page_size: number;
  total: number;
  pages: number;
  has_next: boolean;
  has_prev: boolean;
}

export interface Page<T> {
  items: T[];
  pagination: Pagination;
}

export interface UserProfile {
  id: string;
  email: string;
  full_name: string;
  title: string | null;
  organization_id: string;
  roles: string[];
  role_labels: string[];
  permissions: string[];
  mfa_enabled: boolean;
  is_active: boolean;
  last_login_at: string | null;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: UserProfile;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  plan: string;
  settings: Record<string, unknown>;
  created_at: string;
  member_count?: number;
}

export interface Environment {
  id: string;
  name: string;
  key: string;
  is_production: boolean;
}

export interface Asset {
  id: string;
  asset_ref: string;
  name: string;
  domain: string | null;
  subdomain: string | null;
  ip_address: string | null;
  port: number | null;
  url: string | null;
  http_status: number | null;
  technology_summary: string[];
  hosting_provider: string | null;
  first_seen: string | null;
  last_seen: string | null;
  business_unit: string | null;
  environment_id: string | null;
  criticality: string;
  exposure: string;
  risk_score: number;
  status: string;
  source: string;
  tags: string[];
  description?: string | null;
  network_services?: NetworkService[];
  technologies?: Technology[];
  certificates?: Certificate[];
  relationships?: unknown[];
  findings?: Finding[];
}

export interface NetworkService {
  id: string;
  port: number;
  protocol: string;
  service_name: string | null;
  product: string | null;
  version: string | null;
  state: string;
}

export interface Technology {
  id: string;
  name: string;
  version: string | null;
  category: string | null;
  confidence: number;
}

export interface Certificate {
  id: string;
  common_name: string;
  issuer: string | null;
  not_after: string | null;
  status: string;
}

export interface Microservice {
  id: string;
  service_ref: string;
  name: string;
  description: string | null;
  repository_url: string | null;
  business_unit: string | null;
  environment_id: string | null;
  environment_name?: string | null;
  deployment_location: string | null;
  version: string | null;
  language: string | null;
  tech_stack: string[];
  criticality: string;
  security_posture: string;
  risk_level: string;
  risk_score: number;
  last_assessed_at: string | null;
  status: string;
  open_findings?: number;
  sboms?: SbomDocument[];
  apis?: ApiRecord[];
  dependencies?: ServiceDependency[];
  dependents?: ServiceDependency[];
  findings?: Finding[];
}

export interface ServiceDependency {
  id: string;
  source_service_id: string;
  target_service_id: string | null;
  target_external: string | null;
  dependency_type: string;
}

export interface GraphNode {
  id: string;
  label: string;
  criticality?: string;
  risk_score: number;
  risk_level?: string;
  business_unit?: string | null;
  language?: string | null;
  exposure?: string;
  open_findings: number;
  external?: boolean;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
}

export interface SbomDocument {
  id: string;
  name: string;
  microservice_id: string | null;
  microservice_name?: string | null;
  asset_id: string | null;
  format: string;
  spec_version: string | null;
  source: string;
  file_name: string | null;
  checksum: string | null;
  size_bytes: number;
  component_count: number;
  vulnerability_count: number;
  status: string;
  version_label: string | null;
  analyzed_at: string | null;
  created_at: string;
  error_message?: string | null;
  components?: SbomComponent[];
  vulnerabilities?: Vulnerability[];
  scan_history?: SbomScanHistory[];
}

export interface SbomComponent {
  id: string;
  name: string;
  version: string | null;
  ecosystem: string | null;
  purl: string | null;
  license: string | null;
  component_type: string;
  vulnerability_count: number;
  highest_severity: Severity | null;
  supplier: string | null;
}

export interface SbomScanHistory {
  id: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  components_processed: number;
  findings_count: number;
}

export interface Vulnerability {
  id: string;
  identifier: string;
  cve_id: string | null;
  title: string | null;
  description: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  severity: Severity;
  published_at: string | null;
  modified_at: string | null;
  exploit_available: boolean | null;
  known_exploited: boolean | null;
  source: string;
  fixed_versions: string[];
  remediation: string | null;
  component?: string;
  component_version?: string | null;
  fixed_version?: string | null;
}

export interface Finding {
  id: string;
  finding_ref: string;
  title: string;
  description: string | null;
  category: string;
  source_module: string;
  severity: Severity;
  cvss_score: number | null;
  status: string;
  risk_score: number;
  asset_id: string | null;
  microservice_id: string | null;
  cve_id: string | null;
  assigned_to: string | null;
  business_unit: string | null;
  exposure: string;
  exploitability: string;
  confidence: number;
  remediation: string | null;
  first_seen: string | null;
  last_seen: string | null;
  resolved_at: string | null;
  sla_due_at: string | null;
  location: string | null;
  tags: string[];
  asset_name?: string | null;
  microservice_name?: string | null;
  asset?: { id: string; name: string; domain: string | null; exposure: string } | null;
  microservice?: { id: string; name: string; business_unit: string | null } | null;
  vulnerability?: Vulnerability | null;
  assignee?: { id: string; full_name: string; email: string } | null;
  evidence?: Evidence[];
  comments?: Comment[];
  history?: HistoryEntry[];
  assignments?: unknown[];
  exceptions?: unknown[];
  ai_triage?: TriageResult[];
}

export interface Evidence {
  id: string;
  kind: string;
  content: string | null;
  location: string | null;
  redacted: boolean;
  created_at: string;
}

export interface Comment {
  id: string;
  body: string;
  author_id: string | null;
  created_at: string;
}

export interface HistoryEntry {
  id: string;
  from_status: string | null;
  to_status: string;
  changed_by: string | null;
  note: string | null;
  created_at: string;
}

export interface TriageResult {
  id: string;
  finding_id: string;
  provider: string;
  model: string | null;
  advisory_only: boolean;
  classification: string | null;
  summary: string | null;
  technical_impact: string | null;
  business_impact: string | null;
  recommendation: string | null;
  priority: string;
  false_positive_likelihood: number;
  confidence: number;
  tokens_input: number;
  tokens_output: number;
  latency_ms: number;
  created_at: string;
  finding_title?: string | null;
  finding_ref?: string | null;
  finding_severity?: Severity | null;
}

export interface ScanJob {
  id: string;
  name: string;
  scan_type: string;
  target: string;
  scope: Record<string, unknown>;
  status: string;
  progress: number;
  current_step: string | null;
  findings_count: number;
  started_at: string | null;
  finished_at: string | null;
  error_message: string | null;
  authorization_reference: string | null;
  created_at: string;
  results?: ScanResult[];
  logs?: ScanLog[];
  history?: ScanHistoryEntry[];
}

export interface ScanResult {
  id: string;
  tool: string;
  result_type: string;
  payload: Record<string, unknown>;
  severity: string | null;
  target: string | null;
}

export interface ScanLog {
  id: string;
  level: string;
  message: string;
  created_at: string;
}

export interface ScanHistoryEntry {
  id: string;
  event: string;
  message: string | null;
  created_at: string;
}

export interface ScanSchedule {
  id: string;
  name: string;
  scan_type: string;
  target: string;
  cron: string;
  enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
}

export interface ApiRecord {
  id: string;
  api_ref: string;
  name: string;
  base_url: string | null;
  service_id: string | null;
  version: string | null;
  auth_type: string;
  authorization_model?: string | null;
  content_type?: string;
  description?: string | null;
  data_sensitivity: string;
  exposure: string;
  status: string;
  security_status: string;
  deprecated: boolean;
  last_observed: string | null;
  endpoint_count?: number;
  security_findings?: number | ApiSecurityFinding[];
  endpoints?: ApiEndpoint[];
  specifications?: unknown[];
}

export interface ApiEndpoint {
  id: string;
  method: string;
  path: string;
  summary: string | null;
  auth_required: boolean | null;
  data_sensitivity: string;
  deprecated: boolean;
  status: string;
}

export interface ApiSecurityFinding {
  id: string;
  check_key: string;
  severity: Severity;
  status: string;
  description: string | null;
  confidence: number;
}

export interface Classification {
  id: string;
  category: string;
  detection_method: string;
  confidence: number;
  exposure_location: string | null;
  service_name: string | null;
  risk_classification: string;
  remediation: string | null;
  last_seen: string | null;
  created_at: string;
}

export interface ClassificationRule {
  id: string;
  name: string;
  category: string;
  detection_method: string;
  pattern: string | null;
  severity: string;
  confidence_weight: number;
  enabled: boolean;
  description: string | null;
}

export interface RiskAssessment {
  id: string;
  finding_id: string | null;
  asset_id: string | null;
  microservice_id: string | null;
  score: number;
  severity: string;
  business_impact: string | null;
  business_unit: string | null;
  responsible_team: string | null;
  remediation_deadline: string | null;
  status: string;
  rationale: { factors?: Record<string, number>; explanation?: string };
  finding_ref?: string | null;
  finding_title?: string | null;
  status_finding?: string | null;
  score_history?: { id: string; score: number; computed_at: string }[];
  exceptions?: unknown[];
  finding?: Finding | null;
}

export interface RemediationTask {
  id: string;
  finding_id: string | null;
  title: string;
  description: string | null;
  assigned_to: string | null;
  priority: string;
  due_at: string | null;
  status: string;
  completed_at: string | null;
  evidence: string | null;
}

export interface Notification {
  id: string;
  channel: string;
  event_key: string;
  subject: string;
  body: string;
  severity: Severity;
  status: string;
  sent_at: string | null;
  read_at: string | null;
  created_at: string;
}

export interface Report {
  id: string;
  report_type: string;
  title: string;
  format: string;
  status: string;
  summary: Record<string, unknown>;
  generated_at: string | null;
  created_at: string;
  content?: Record<string, unknown>;
}

export interface Integration {
  id: string | null;
  key: string;
  name: string;
  category: string;
  capabilities: string[];
  status: string;
  version: string | null;
  enabled: boolean;
  config: Record<string, unknown>;
  last_checked_at: string | null;
  last_error: string | null;
  managed: boolean;
}

export interface DashboardOverview {
  counts: Record<string, number | null>;
  severity_distribution: { severity: string; count: number }[];
  status_distribution: { status: string; count: number }[];
}

export interface ActivityItem {
  type: string;
  title: string;
  severity: string;
  status: string;
  timestamp: string | null;
  reference: string | null;
  link: string | null;
}

export interface TrendPoint {
  week?: string;
  date?: string;
  posture?: number;
  open_findings?: number;
  new_findings?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
  average_score?: number;
}
