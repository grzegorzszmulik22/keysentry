// Shared contracts for every keysentry module. Owned by the orchestrator: modules implement these interfaces and
// must not change them. If a module needs a contract change, it writes the request to notes/<module>.md.

// ---------------------------------------------------------------- HTTP (all network goes through this)
export interface HttpRequest {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  url: string;
  headers?: Record<string, string>;
  /** Already-serialized body (JSON string, form-encoded string). */
  body?: string;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  text: string;
  /** Parses `text` as JSON; throws on invalid JSON. */
  json<T = unknown>(): T;
}

export interface HttpClient {
  request(req: HttpRequest): Promise<HttpResponse>;
}

// ---------------------------------------------------------------- logging and redaction
export interface Logger {
  info(msg: string, data?: Record<string, unknown>): void;
  warn(msg: string, data?: Record<string, unknown>): void;
  error(msg: string, data?: Record<string, unknown>): void;
  debug(msg: string, data?: Record<string, unknown>): void;
}

/** Masks every registered secret value in any text before it is printed or written. */
export interface Redactor {
  register(secret: string): void;
  redact(text: string): string;
}

// ---------------------------------------------------------------- hosts (where secrets are consumed)
export type HostId = 'railway' | 'vercel' | 'render' | 'fly' | 'github-actions' | 'dotenv';

export interface ServiceRef {
  host: HostId;
  /** Host project / app / repo id (dotenv: absolute directory). */
  projectId: string;
  projectName: string;
  /** Host service id (Railway service, Vercel project, Render service, Fly app, GitHub repo, dotenv file path). */
  serviceId: string;
  serviceName: string;
  /** Railway environment, Vercel target ("production" | "preview" | "development"); empty when not applicable. */
  environmentId: string;
  environmentName: string;
}

export interface RawVariable {
  name: string;
  /** Plaintext value; undefined when the host never returns it (sealed / sensitive / write-only). */
  value?: string;
  /** True when the value exists but cannot be read back (Railway sealed, Vercel sensitive, Fly, GitHub Actions). */
  sealed: boolean;
}

export interface HostCapabilities {
  /** Can return plaintext values for at least non-sealed variables. */
  readValues: boolean;
  /** Can write several variables in one call without deploying per variable. */
  batchWrite: boolean;
  /** Has a deploy step that must run for running instances to pick up new values. */
  redeploy: boolean;
}

export type DeployState = 'pending' | 'success' | 'failed';

export interface HostAdapter {
  readonly id: HostId;
  readonly capabilities: HostCapabilities;
  listServices(): Promise<ServiceRef[]>;
  readVariables(service: ServiceRef): Promise<RawVariable[]>;
  /**
   * Upsert exactly the given variables. MUST NOT delete or alter any other variable (hosts whose API replaces the
   * full set must read-modify-write). With skipDeploy the host must not start a deployment for this write.
   */
  writeVariables(service: ServiceRef, vars: Record<string, string>, opts: { skipDeploy: boolean }): Promise<void>;
  /** Start one deployment so running instances pick up current values. Returns a deployment id, or null if none. */
  redeploy(service: ServiceRef): Promise<string | null>;
  deploymentStatus(service: ServiceRef, deploymentId: string): Promise<DeployState>;
}

// ---------------------------------------------------------------- classification
export type ProviderId =
  | 'openai'
  | 'anthropic'
  | 'openrouter'
  | 'stripe'
  | 'resend'
  | 'cloudflare'
  | 'github'
  | 'aws'
  | 'supabase'
  | 'database'
  | 'slack'
  | 'sendgrid'
  | 'twilio'
  | 'google'
  | 'private-key'
  | 'crypto-wallet'
  | 'app-secret'
  /** Data-encryption keys (ENCRYPTION_KEY, *_ENCRYPTION_KEY, MASTER_KEY…): replacing one needs a data migration. */
  | 'encryption-key'
  | 'unknown';

/** Damage class; also the default rotation order (index 0 first). */
export type RiskTier = 'crypto' | 'cloud' | 'database' | 'payments' | 'ai' | 'comms' | 'app' | 'unknown';
export const TIER_ORDER: readonly RiskTier[] = ['crypto', 'cloud', 'database', 'payments', 'ai', 'comms', 'app', 'unknown'];

/**
 * auto: provider API creates a new key; old key stays valid until revoked (overlap, safest).
 * atomic-roll: provider rolls in place; old key dies when the new one is created (write + redeploy fast).
 * generate: keysentry generates a random value itself (app/session secrets).
 * guided: a human creates the key in the provider dashboard and pastes it.
 */
export type RotationMethod = 'auto' | 'atomic-roll' | 'generate' | 'guided';

export interface Classification {
  provider: ProviderId;
  tier: RiskTier;
  /** False for config that is not a secret (PORT, NODE_ENV, NEXT_PUBLIC_*, pk_ publishable keys, plain URLs). */
  isSecret: boolean;
  confidence: 'high' | 'medium' | 'low';
}

// ---------------------------------------------------------------- inventory
export interface Consumer {
  service: ServiceRef;
  varName: string;
  /** Keyed HMAC of the value (hex). null when sealed. Never the plaintext. */
  fingerprint: string | null;
  /** Human hint: prefix (≤ 7 chars) + "…" + last 4 chars, only when value length ≥ 16; else null. */
  hint: string | null;
  sealed: boolean;
  /**
   * The service receives this value through a host reference (e.g. Railway `${{api.OPENAI_API_KEY}}`) rather than
   * holding its own copy: it must be redeployed when the referenced variable changes, but never written to.
   */
  reference?: boolean;
}

export interface SecretFinding extends Consumer, Classification {}

export interface Cluster {
  /** fingerprint for readable values; "sealed:<serviceKey>:<varName>" for sealed ones. */
  id: string;
  fingerprint: string | null;
  provider: ProviderId;
  tier: RiskTier;
  method: RotationMethod;
  hint: string | null;
  /** Every place this same value is used (same fingerprint), possibly under different variable names. */
  consumers: Consumer[];
}

export interface Inventory {
  version: 1;
  scannedAt: string;
  hosts: HostId[];
  services: ServiceRef[];
  findings: SecretFinding[];
  clusters: Cluster[];
  /** Per-host scan errors (e.g. missing token); a partial scan is still useful. */
  errors: { host: HostId; message: string }[];
}

// ---------------------------------------------------------------- providers (where secrets are issued)
export interface ProviderContext {
  http: HttpClient;
  /** Admin / management credentials by name (OPENAI_ADMIN_KEY, ANTHROPIC_ADMIN_KEY, OPENROUTER_PROVISIONING_KEY…). */
  credentials: Record<string, string | undefined>;
  /** Other variables of the same service, for paired secrets (AWS_ACCESS_KEY_ID with the secret, SUPABASE_URL…). */
  siblingVars?: Record<string, string>;
  log: Logger;
}

export interface VerifyResult {
  ok: boolean;
  /** e.g. account / key name returned by the provider's whoami call. */
  identity?: string;
  /** HTTP status of the verify call, when there was one. */
  status?: number;
  error?: string;
}

export interface RotationResult {
  newValue: string;
  /** Provider id/hash of the OLD key, needed to revoke it later; null if the provider cannot identify it. */
  oldKeyRef: string | null;
  /** Provider id/hash of the NEW key (stored for the next rotation and for monitoring). */
  newKeyRef: string | null;
  /** True for atomic-roll providers: the old key is already dead. */
  oldRevoked: boolean;
  /** Extra values that must be written together (e.g. AWS_ACCESS_KEY_ID when rotating the secret). varName → value */
  companions?: Record<string, string>;
  notes?: string;
}

export interface ProviderKeyInfo {
  keyRef: string;
  name?: string;
  /** Partial value as the provider shows it (e.g. "sk-or-v1-abc...f00"), used to map inventory hints to keys. */
  hint?: string;
  createdAt?: string;
  disabled?: boolean;
  limitUsd?: number | null;
}

export interface UsageSample {
  keyRef: string;
  from: string;
  to: string;
  costUsd: number;
  /** Lifetime spend when the provider only reports running totals (OpenRouter); the monitor diffs successive polls. */
  cumulativeCostUsd?: number;
  requests?: number;
  /** Cost (USD) by model over the window, when the provider reports it. */
  byModel?: Record<string, number>;
}

export interface Guidance {
  /** Dashboard URL where a human creates/rolls the key. */
  url: string;
  steps: string[];
}

export interface ProviderAdapter {
  readonly id: ProviderId;
  readonly method: RotationMethod;
  /** Cheap authenticated call with the key itself ("whoami"/list). Never logs the key. */
  verify(value: string, ctx: ProviderContext): Promise<VerifyResult>;
  /** Required for auto, atomic-roll and generate methods. */
  rotate?(oldValue: string, ctx: ProviderContext): Promise<RotationResult>;
  /** Revoke/disable a key by provider ref. Required for auto. */
  revoke?(keyRef: string, ctx: ProviderContext): Promise<void>;
  /** Shown for guided rotation and as a fallback when an automatic step fails. */
  guidance(): Guidance;
  /**
   * Map a plaintext key to the provider's key ref (via listKeys hints or a whoami call), so a key that was rotated
   * by hand (guided) or by atomic roll can still be revoked / monitored. null when not identifiable.
   */
  resolveKeyRef?(value: string, ctx: ProviderContext): Promise<string | null>;
  /** Monitoring: keys visible to the admin credential. */
  listKeys?(ctx: ProviderContext): Promise<ProviderKeyInfo[]>;
  /** Monitoring: spend/requests for one key over a window. */
  usage?(keyRef: string, window: { from: Date; to: Date }, ctx: ProviderContext): Promise<UsageSample>;
  /** Containment without rotation: disable the key or set its limit to ~0 at the provider. */
  cap?(keyRef: string, ctx: ProviderContext): Promise<void>;
}

// ---------------------------------------------------------------- planning
export interface PlanStep {
  clusterId: string;
  provider: ProviderId;
  tier: RiskTier;
  method: RotationMethod;
  hint: string | null;
  consumers: Consumer[];
}

export interface RotationPlan {
  id: string;
  createdAt: string;
  /** Ordered: TIER_ORDER first, then by number of consumers (desc), then cluster id. */
  steps: PlanStep[];
  /** Every service that will be written to; each is redeployed exactly once. */
  services: ServiceRef[];
}

// ---------------------------------------------------------------- execution
export interface GuidedPrompt {
  clusterId: string;
  provider: ProviderId;
  hint: string | null;
  guidance: Guidance;
  consumers: Consumer[];
}

export type StepStatus = 'pending' | 'created' | 'written' | 'deployed' | 'verified' | 'revoked' | 'skipped' | 'failed';

export interface StepReport {
  clusterId: string;
  status: StepStatus;
  /** Fingerprint of the new value (never the value). */
  newFingerprint?: string;
  newKeyRef?: string | null;
  oldKeyRef?: string | null;
  error?: string;
  warnings: string[];
}

export interface RotationReport {
  planId: string;
  dryRun: boolean;
  startedAt: string;
  finishedAt: string;
  steps: StepReport[];
  /**
   * skipped: service not written. unconfirmed: written, but activation can't be confirmed (host without redeploy,
   * next-deploy targets, null deployment id, manual restart needed).
   */
  deployments: { serviceKey: string; deploymentId: string | null; state: DeployState | 'skipped' | 'unconfirmed' }[];
  /** Human-readable diff of planned writes (names and hints only). */
  diff: string[];
  /** Overall outcome (phase 1: optional until every producer sets it). */
  status?: 'complete' | 'grace-pending' | 'partial' | 'failed' | 'dry-run';
  /** Old keys kept valid during the grace period; `keysentry finish` or `undo` settles them. */
  pendingRevocations?: { clusterId: string; deadline: string; undoAvailable: boolean }[];
  /** Keys that may exist at a provider without being recorded (crash between create and store). Never revoked by guesswork. */
  orphanSuspects?: { clusterId: string; provider: ProviderId; keyRef: string; createdAt?: string }[];
}

export interface JournalEntry {
  at: string;
  planId: string;
  clusterId?: string;
  serviceKey?: string;
  event:
    | 'plan-start'
    | 'created'
    | 'written'
    | 'redeploy'
    | 'deploy-result'
    | 'verified'
    | 'revoked'
    | 'failed'
    | 'plan-end'
    | 'value-stored'
    | 'grace-start'
    | 'grace-end'
    | 'undo'
    | 'resume'
    | 'shredded'
    | 'orphan-suspected';
  data?: Record<string, unknown>;
}

export interface Journal {
  append(entry: JournalEntry): Promise<void>;
  read(planId?: string): Promise<JournalEntry[]>;
}

// ---------------------------------------------------------------- monitoring
export type SignalKind =
  | 'canary_triggered' // a decoy key planted in a host was used: that host/service is compromised (high confidence)
  | 'usage_anomaly' // spend/requests far above the key's baseline, or a never-seen expensive model
  | 'leak_detected' // the value appeared in a leak source (e.g. GitHub secret scanning alert)
  | 'revoked_upstream' // the provider rejects a key that used to work (provider revoked it)
  | 'host_breach_advisory'; // a host published a security advisory (Railway, Vercel, Render, Fly, Zeabur…)

export interface Signal {
  id: string;
  kind: SignalKind;
  at: string;
  confidence: 'high' | 'medium' | 'low';
  /** Inventory clusters directly implicated. */
  clusterIds: string[];
  host?: HostId;
  serviceKeys?: string[];
  summary: string;
  evidence: Record<string, unknown>;
}

export type ActionKind = 'alert' | 'cap' | 'rotate' | 'breach-mode';

export interface PolicyRule {
  action: ActionKind;
  /** What to rotate when action is rotate: the implicated clusters, every secret of the implicated services, or every secret on the host. */
  scope: 'cluster' | 'service' | 'host';
  /** Ignore signals below this confidence (they are still alerted). */
  minConfidence: 'high' | 'medium' | 'low';
}

export interface Policy {
  /** If false, rotate/breach-mode create a pending action that a human approves (`keysentry approve <id>`). */
  autoExecute: boolean;
  rules: Record<SignalKind, PolicyRule>;
  /** No automatic re-rotation of the same cluster within this window. */
  cooldownMinutes: number;
  maxAutoRotationsPerDay: number;
  /**
   * If false (default), `cap` (provider-side disable) also waits for human approval like rotations do. Containment
   * can break consumers (Anthropic cap = deactivate), so it is opt-in.
   */
  autoContain: boolean;
  /** No repeated automatic containment of the same key within this window. */
  containCooldownMinutes: number;
  /**
   * For high-confidence signals (canary, leak, upstream revocation): revoke the old key even when some consumer's
   * activation cannot be confirmed (next-deploy targets, manual restarts). A leaked key must die; default true.
   */
  revokeUnconfirmedOnHighConfidence: boolean;
}

export interface PendingAction {
  id: string;
  createdAt: string;
  signalId: string;
  action: ActionKind;
  clusterIds: string[];
  status: 'pending' | 'approved' | 'executed' | 'dismissed' | 'failed';
  note?: string;
}

/** Thrown by an interactive prompt when the human cancels (Ctrl-C): the engine aborts the whole run. */
export class RotationAbortedError extends Error {
  readonly code = 'ROTATION_ABORTED';
  constructor(message = 'Rotation aborted by the operator before any further changes.') {
    super(message);
    this.name = 'RotationAbortedError';
  }
}

export interface Notifier {
  notify(title: string, body: string, signal?: Signal): Promise<void>;
}

// ---------------------------------------------------------------- phase 1: vault
export type VaultBackendId = 'macos-keychain' | 'windows-dpapi' | 'linux-secret-service' | 'encrypted-file' | 'env' | 'memory';

/** Where keysentry keeps its own keys and the user's tokens. Values are opaque bytes. */
export interface Vault {
  readonly backend: VaultBackendId;
  /** Plain-English note shown by doctor when the backend is weaker than an OS credential store. */
  readonly weakness?: string;
  get(name: string): Promise<Buffer | null>;
  set(name: string, value: Buffer): Promise<void>;
  delete(name: string): Promise<boolean>;
  list(prefix?: string): Promise<string[]>;
}

/** read: tokens used for scan and monitor; write: tokens used only after a human approves a change. */
export type TokenRole = 'read' | 'write';

export interface CredentialSource {
  get(name: string, role: TokenRole): Promise<{ value: string; source: 'vault' | 'env' } | null>;
}

// ---------------------------------------------------------------- phase 1: security
export interface StateCipher {
  seal(kind: string, plaintext: Buffer): Buffer;
  open(kind: string, sealed: Buffer): Buffer;
}

export interface AuditEvent {
  kind: string;
  summary: string;
  data?: Record<string, unknown>;
}

export interface AuditVerifyResult {
  ok: boolean;
  entries: number;
  checkpoints: number;
  firstBadSeq?: number;
  problem?: string;
  truncatedSinceLastKnownHead?: boolean;
}

export interface AuditLog {
  append(e: AuditEvent): Promise<void>;
  checkpoint(): Promise<void>;
  verify(): Promise<AuditVerifyResult>;
}

// ---------------------------------------------------------------- phase 1: network
export interface EgressRule {
  /** Exact host, or `*.example.com` for subdomains on a dot boundary. */
  host: string;
  purpose: string;
  /** Host or provider id, `'feed'`, `'release'` or `'user'`. Redirects may only stay within one owner. */
  owner: string;
}

export interface NetworkReceiptEntry {
  at: string;
  host: string;
  method: string;
  purpose: string;
  allowed: boolean;
  status?: number;
}

export interface NetworkReceipt {
  record(e: NetworkReceiptEntry): Promise<void>;
  summarize(sinceIso?: string): Promise<{ host: string; purpose: string; count: number; blocked: number; lastAt: string }[]>;
}

// ---------------------------------------------------------------- phase 1: in-flight values
/** New and old secret values during a rotation, encrypted under a per-plan key and shredded when the plan ends. */
export interface InFlightStore {
  put(planId: string, slot: string, value: string): Promise<void>;
  get(planId: string, slot: string): Promise<string | null>;
  slots(planId: string): Promise<string[]>;
  shred(planId: string): Promise<void>;
}

// ---------------------------------------------------------------- phase 1: rotation recovery
export type GraceDecision = 'revoke' | 'undo' | 'defer';

export interface GraceInfo {
  planId: string;
  deadline: string;
  clusters: { clusterId: string; hint: string | null; undoAvailable: boolean }[];
}

export type CrashPoint =
  | 'after-create'
  | 'after-store'
  | 'after-write'
  | 'after-redeploy'
  | 'after-deploy-result'
  | 'after-verify'
  | 'before-revoke'
  | 'after-revoke';

// ---------------------------------------------------------------- phase 2: autopilot
export type AutopilotMethod = 'auto' | 'generate';

export interface ArmedCluster {
  clusterId: string;
  provider: ProviderId;
  method: AutopilotMethod;
  /** Every consumer at arming time; a new, removed or changed consumer downgrades the cluster to "ask". */
  consumers: { serviceKey: string; varName: string; fingerprint: string | null }[];
  /** Write-only consumers adopted at arming: keysentry wrote this value (by fingerprint) and knows its key ref. */
  adopted?: { fingerprint: string; keyRef: string | null; at: string };
}

/** Signed by the device key; the watcher executes automatic rotations only inside it. */
export interface ArmedPlan {
  v: 1;
  id: string;
  projectId: string;
  createdAt: string;
  expiresAt: string;
  /** Incidents on these hosts may trigger automatic rotation. */
  hosts: HostId[];
  clusters: ArmedCluster[];
  maxServicesPerWave: number;
  graceSeconds: number;
  healthChecks: { serviceKey: string; url: string; expectStatus?: number }[];
  /** The user accepted that activation on these hosts is confirmed at the next deploy (Vercel preview, GitHub Actions). */
  nextDeployAcceptance: { host: HostId; maxHours: number; revokeAfterMax: boolean }[];
  quiet: { lowPriorityHours?: { start: string; end: string; timeZone: string } };
  signer: { keyId: string; publicKeyDer: string };
  sig: string;
}

export interface ScopeDecision {
  execute: string[];
  ask: { clusterId: string; reasons: string[] }[];
}

// ---------------------------------------------------------------- phase 2: incidents
export type SourceKind = 'official' | 'news';

export interface FeedSource {
  id: string;
  kind: SourceKind;
  url: string;
  /** Platforms an official source speaks for; news sources list the platforms they may report on (all). */
  hosts: HostId[];
  outlet: string;
  /** Publishing company: two news items corroborate each other only when their owners differ. */
  owner: string;
  maxBytes?: number;
  /** Keep only items whose link starts with this prefix (e.g. Vercel security bulletins inside the KB feed). */
  linkPrefix?: string;
}

export interface IncidentEvidence {
  sourceId: string;
  kind: SourceKind;
  outlet: string;
  owner: string;
  /** Keyed hash of the item id; raw ids and bodies are not kept. */
  itemKey: string;
  /** Sanitized, at most 200 characters. */
  title: string;
  link: string | null;
  publishedAt: string | null;
  credentialExposure: boolean;
  confidence: 'high' | 'medium' | 'low';
}

export interface Incident {
  id: string;
  host: HostId;
  openedAt: string;
  evidence: IncidentEvidence[];
  status: 'watching' | 'alerted' | 'triggered' | 'closed';
  trigger?: { at: string; rule: 'official' | 'official+news' | 'corroborated-news' };
  waveId?: string;
}

// ---------------------------------------------------------------- phase 2: notifications
export type NotifySeverity = 'info' | 'warning' | 'urgent';

/** Never contains a secret value; key hints only when the user enabled them. */
export interface NotifyMessage {
  id: string;
  at: string;
  kind: string;
  severity: NotifySeverity;
  title: string;
  lines: string[];
  actionId?: string;
  approveUrl?: string;
}

export interface SignedNotifyMessage extends NotifyMessage {
  keyId: string;
  sig: string;
  /** Short verification code shown in the message, e.g. "K7QM-2XRA". */
  code: string;
}

export type NotifyChannelKind = 'telegram' | 'discord' | 'slack' | 'ntfy' | 'webhook' | 'resend' | 'smtp' | 'console';

export interface NotifyChannel {
  readonly id: string;
  readonly kind: NotifyChannelKind;
  send(m: SignedNotifyMessage): Promise<void>;
}

// ---------------------------------------------------------------- phase 2: approvals
export interface PasskeyCredential {
  /** base64url credential id. */
  id: string;
  /** base64url COSE public key. */
  publicKeyCose: string;
  alg: -7 | -8 | -257;
  signCount: number;
  backupEligible: boolean;
  rpId: string;
  origins: string[];
  label: string;
  createdAt: string;
}

export interface ApprovalRequest {
  actionId: string;
  /** sha256 hex of the canonical action description. */
  digest: string;
  createdAt: string;
  expiresAt: string;
  /** base64url, single use. */
  challenge: string;
  /** Policy-widening actions can only be approved on a registered device with the local CLI. */
  widening: boolean;
}

export interface ApprovalGrant {
  actionId: string;
  digest: string;
  at: string;
  by: { kind: 'passkey'; credentialId: string } | { kind: 'device'; keyId: string };
}
