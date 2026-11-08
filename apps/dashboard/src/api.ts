// Same-origin admin API client. The session cookie is HttpOnly and sent by the
// browser; the CSRF token lives only in memory for the life of the tab.
import type {
  Action,
  AuditEvent,
  Decision,
  DestinationTier,
  FallbackMode,
  Finding,
  PendingApproval,
  PolicyRule,
  ProviderConfig,
  Sensitivity,
} from './generated/types';

export const BASE = '/api/admin/v1';

let csrf: string | null = null;

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, message: string, code: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

type Listener = () => void;
const unauthListeners = new Set<Listener>();
export function onUnauthorized(fn: Listener): () => void {
  unauthListeners.add(fn);
  return () => unauthListeners.delete(fn);
}

async function parseError(res: Response): Promise<ApiError> {
  let message = `${res.status} ${res.statusText}`;
  let code = 'HTTP_' + res.status;
  try {
    const body = await res.json();
    if (body?.error?.message) message = body.error.message;
    if (body?.error?.code) code = body.error.code;
  } catch {
    /* non-JSON error body */
  }
  return new ApiError(res.status, message, code);
}

async function raw(method: string, path: string, body?: unknown): Promise<Response> {
  const headers: Record<string, string> = { accept: 'application/json' };
  if (method !== 'GET' && method !== 'HEAD') {
    headers['content-type'] = 'application/json';
    if (csrf) headers['X-PV-CSRF'] = csrf;
  }
  const res = await fetch(BASE + path, {
    method,
    headers,
    credentials: 'same-origin',
    cache: 'no-store',
    body: body === undefined ? (method === 'GET' || method === 'HEAD' ? undefined : '{}') : JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await parseError(res);
    if (res.status === 401) unauthListeners.forEach((fn) => fn());
    throw err;
  }
  return res;
}

export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await raw(method, path, body);
  return (await res.json()) as T;
}

export const get = <T>(path: string) => api<T>('GET', path);
export const post = <T>(path: string, body?: unknown) => api<T>('POST', path, body);
export const put = <T>(path: string, body?: unknown) => api<T>('PUT', path, body);
export const patch = <T>(path: string, body?: unknown) => api<T>('PATCH', path, body);
export const del = <T>(path: string) => api<T>('DELETE', path);

export async function getText(path: string): Promise<string> {
  const res = await raw('GET', path);
  return res.text();
}

export interface SessionInfo {
  authenticated: boolean;
  csrf: string | null;
  version: string;
}

export async function loadSession(): Promise<SessionInfo> {
  const s = await get<SessionInfo>('/session');
  csrf = s.csrf;
  return s;
}

export async function logout(): Promise<void> {
  await post('/session/logout');
  csrf = null;
}

// ------------------------------------------------------------------ response shapes
// Shapes the generated schema types do not cover (admin envelopes).

export type { Action, AuditEvent, Decision, DestinationTier, FallbackMode, Finding, PendingApproval, PolicyRule, ProviderConfig, Sensitivity };

export const ACTIONS: Action[] = ['ALLOW', 'TOKENIZE', 'REDACT', 'GENERALIZE', 'PRIVATE_ROUTE', 'REQUIRE_APPROVAL', 'BLOCK', 'FALLBACK'];

export interface Stats {
  total_requests: number;
  transformed: number;
  blocked: number;
  review: number;
  private_routed: number;
  errors: number;
}

export interface Overview {
  stats: Stats;
  recent: AuditEvent[];
  pending_approvals: number;
  protected: boolean;
  emergency_stop: boolean;
  base_url: string;
}

export interface CategoryInfo {
  id: string;
  label: string;
  description: string;
  critical: boolean;
  sensitivity: Sensitivity;
  examples: string[];
}

export interface CategoryState extends CategoryInfo {
  action: Action | null;
  protected: boolean;
  exception: boolean;
  rule_id: string;
  rule_version: number | null;
}

export interface NormOpts {
  unicode: boolean;
  casefold: boolean;
  whitespace: boolean;
  separators: boolean;
}

export type SecretKind = 'value' | 'pattern' | 'file_fingerprint';

export interface SecretMeta {
  secret_id: string;
  kind: SecretKind;
  label: string;
  norm: NormOpts;
  allow: boolean;
  action: string;
  created_at: string;
}

export interface StoredConcept {
  concept: { id: string; name: string; description: string; safe_examples: string[]; sensitive_examples: string[] };
  action: Action;
  created_at: string;
}

export interface GuidanceNote {
  id: string;
  text: string;
  created_at: string;
}

export interface AppRecord {
  app_id: string;
  name: string;
  agent_id: string | null;
  destination_id: string | null;
  created_at: string;
  revoked_at: string | null;
}

export interface NearVerification {
  provider_id?: string;
  model: string;
  eligible: boolean;
  tier: DestinationTier;
  gateway_signer: string | null;
  gateway_tcb: string | null;
  gateway_tls_spki: string | null;
  model_signers: string[];
  model_tcb: string[];
  gpu_verified: boolean;
  e2ee_key: boolean;
  verifier: string;
  error: string | null;
  checked_at: string;
  expires_at?: string;
}

export interface ProviderEntry {
  config: ProviderConfig;
  has_credential: boolean;
}

export type NearPrivacyTier = 'PRIVATE_TEE' | 'PRIVATE_3P_TEE' | 'INCOGNITO';

export interface NearModel {
  id: string;
  name: string;
  provider_type: string;
  attestation_supported: boolean;
  aliases: string[];
  privacy_tier: NearPrivacyTier;
}

export interface ProviderTest {
  ok: boolean;
  tier: DestinationTier;
  model: string;
  verification: NearVerification | null;
  latency_ms: number;
  detail: { reply?: string | null; receipt?: unknown; error?: string };
}

export type ClassifierKindName = 'qwen3guard' | 'lfm3' | 'none';

export interface OllamaStatus {
  url: string;
  reachable: boolean;
  version?: string | null;
  installed?: { qwen3guard?: boolean; lfm3?: boolean };
  models?: string[];
  install?: string;
  error?: string;
}

export interface ClassifierStatus {
  selected: string;
  active: boolean;
  model: string | null;
  verified_digest: string | null;
  error: string | null;
}

export interface SpanStatus {
  compiled: boolean;
  provisioned: boolean;
  loaded: boolean;
  revision: string | null;
  error: string | null;
}

export interface PullJob {
  id: string;
  model: string;
  status: string;
  completed: number;
  total: number;
  done: boolean;
  error: string | null;
  verified_digest: string | null;
}

export interface GenerativeLock {
  display_name: string;
  purpose?: string;
  upstream?: string;
  license?: string;
  ollama_pull?: string;
}

export interface DetectorSettings {
  semantic_mode: string;
  span_enabled: boolean;
  span_required: boolean;
  semantic_timeout_ms: number;
}

export interface ModelsStatus {
  classifier: ClassifierStatus;
  span: SpanStatus;
  jobs: PullJob[];
  lock: { generative?: Record<string, GenerativeLock>; span?: Record<string, { source?: string; license?: string; revision?: string }> };
  selection: { kind: ClassifierKindName; ollama_url: string };
  ollama: OllamaStatus;
  detector: DetectorSettings;
}

export interface EngineSettings {
  owner_id?: string;
  fallback: { mode: FallbackMode; tee_consent: boolean; local_private_handling: boolean; uncertain_threshold: number };
  default_destination: string | null;
  private_destination: string | null;
  private_model: string | null;
  failover: string[];
  mapping_ttl_minutes?: number;
  pending_ttl_minutes: number;
  retention_days: number;
  outbound_semantic: boolean;
  restore_placeholders: boolean;
  emergency_stop: boolean;
}

export interface NotificationSettings {
  enabled: boolean;
  kinds: string[];
  min_interval_secs: number;
}

export interface OnboardingStateInfo {
  completed: boolean;
  completed_at: string | null;
  version: number;
  near_skipped: boolean;
}

export interface Consent {
  kind: string;
  granted: boolean;
  details: unknown;
  policy_hash: string | null;
  created_at: string;
}

export interface SettingsResponse {
  engine: EngineSettings;
  detector: DetectorSettings;
  notifications: NotificationSettings;
  classifier: { kind: ClassifierKindName; ollama_url: string };
  onboarding: OnboardingStateInfo;
  consents: Consent[];
}

export interface OnboardingInfo {
  state: OnboardingStateInfo;
  categories: CategoryInfo[];
  defaults: Record<string, Action>;
  classifier: { kind: ClassifierKindName; ollama_url: string };
  ollama: OllamaStatus;
  near_default_base: string;
  spec_preferred_model: string;
  base_url: string;
  platform: string;
}

export interface OnboardingComplete {
  ok: boolean;
  policy_hash: string;
  base_url: string;
  api_key: string | null;
  near_status: string;
}

export interface Health {
  status: string;
  version: string;
  uptime_secs: number;
  base_url: string;
  database: { schema_version: number | null; integrity_ok: boolean };
  vault: { backend: string; secure: boolean; active_key: string };
  audit_chain: { ok: boolean; events?: number; error?: string };
  near: { status: string; verifications: NearVerification[] };
  classifier: ClassifierStatus;
  span: SpanStatus;
  destinations: { id: string; kind: string; declared_tier: DestinationTier; enabled: boolean }[];
  default_destination: string | null;
  fallback: EngineSettings['fallback'];
  pending_approvals: number;
  emergency_stop: boolean;
  coverage: string;
  warnings: string[];
}

export interface PlaygroundResult {
  findings: { finding: Finding; text: string; action: Action | null }[];
  decision: Decision;
  failures: string[];
  recognizers: string[];
}

export interface ApprovalDetail {
  approval: PendingApproval;
  event: AuditEvent | null;
  payload_available: boolean;
}

export interface PolicyHistoryEntry {
  rule: PolicyRule;
  created_at: string;
  actor: string;
  active: boolean;
}
