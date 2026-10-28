import { createPrivateKey, sign, timingSafeEqual, type KeyObject } from 'node:crypto';
import type {
  Guidance, HttpRequest, HttpResponse, ProviderAdapter, ProviderContext, ProviderKeyInfo, RotationResult, VerifyResult,
} from '../types.js';
import { ensureOk, ProviderMutationUncertainError, readJson, safeIdentity } from './shared.js';

// Google Cloud API keys (AIza…, used by Gemini, Maps and other Google APIs) are managed through the API Keys API
// (https://docs.cloud.google.com/api-keys/docs/reference/rest). Service-account JSON keys share this provider id
// and always use guided rotation. Endpoint facts and gaps: notes/providers-b.md.

const PROVIDER = 'Google';
const API_KEYS = 'https://apikeys.googleapis.com/v2';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GEMINI_MODELS = 'https://generativelanguage.googleapis.com/v1beta/models?pageSize=1';
const CLOUD_SCOPE = 'https://www.googleapis.com/auth/cloud-platform';
const READ_ONLY_SCOPE = 'https://www.googleapis.com/auth/cloud-platform.read-only';
const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

/** Service-account JSON key with the API Keys Admin role (preferred: works unattended). */
export const GOOGLE_ADMIN_KEY = 'GOOGLE_API_KEYS_ADMIN_KEY';
/** Alternative short-lived OAuth access token with the cloud-platform scope (for example from gcloud). */
export const GOOGLE_ACCESS_TOKEN = 'GOOGLE_OAUTH_ACCESS_TOKEN';
/** Not secret: the project searched when only the key value is known. Defaults to the admin key's project_id. */
export const GOOGLE_PROJECT = 'GOOGLE_API_KEYS_PROJECT';
export const GOOGLE_CREDENTIALS = [GOOGLE_ADMIN_KEY, GOOGLE_ACCESS_TOKEN, GOOGLE_PROJECT] as const;

const KEY_NAME = /^projects\/([a-z0-9][a-z0-9-]{0,62})\/locations\/global\/keys\/([a-z0-9][a-z0-9-]{0,62})$/;
const PROJECT = /^(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20})$/;
const OPERATION = /^operations\/[A-Za-z0-9._~-]{1,256}$/;
const KEY_STRING = /^[A-Za-z0-9._-]{20,512}$/;
const ACCESS_TOKEN = /^[\x21-\x7E]{16,4096}$/;
/** Shared safeIdentity does not know Google key shapes; provider-controlled labels must not carry a key. */
const GOOGLE_KEY_SHAPE = /AIza[0-9A-Za-z_-]{30,}/;
const SERVICE_ACCOUNT_EMAIL = /^[a-z0-9][a-z0-9._-]{0,99}@[a-z0-9][a-z0-9.-]{0,252}\.gserviceaccount\.com$/i;
const MAX_KEYS = 500;
const MAX_PAGES = 50;
/** About 50 seconds in total; the documented example operation is already done when create returns. */
const POLL_DELAYS_MS = [500, 1_000, 2_000, 3_000, 5_000, 5_000, 5_000, 5_000, 5_000, 5_000, 5_000, 5_000, 5_000];

/** Fields the API Keys API documents for Key. Anything new might restrict the key, so it stops reference copying. */
const KEY_FIELDS = new Set(['name', 'uid', 'displayName', 'keyString', 'createTime', 'updateTime', 'deleteTime',
  'annotations', 'restrictions', 'etag', 'serviceAccountEmail']);
const CLIENT_RESTRICTIONS = ['browserKeyRestrictions', 'serverKeyRestrictions', 'androidKeyRestrictions', 'iosKeyRestrictions'] as const;
/** Application restrictions of keys that ship inside web pages or mobile apps. */
const SHIPPED_CLIENT_RESTRICTIONS = ['browserKeyRestrictions', 'androidKeyRestrictions', 'iosKeyRestrictions'] as const;
/** google.api.ErrorReason values meaning the key itself is valid but may not call the Gemini API from here. */
const LIMITED_REASONS = new Set(['API_KEY_SERVICE_BLOCKED', 'API_KEY_HTTP_REFERRER_BLOCKED', 'API_KEY_IP_ADDRESS_BLOCKED',
  'API_KEY_ANDROID_APP_BLOCKED', 'API_KEY_IOS_APP_BLOCKED', 'SERVICE_DISABLED']);

const MESSAGES = {
  restrictions: 'Google API key restrictions could not be copied safely; use guided rotation.',
  serviceAccountKey: 'Google service-account keys need guided rotation: create a new JSON key for the same service account.',
  credentials: `Google API key automation needs ${GOOGLE_ADMIN_KEY} or ${GOOGLE_ACCESS_TOKEN}; use guided rotation.`,
  project: `Google API key automation needs ${GOOGLE_PROJECT} (or a project_id in ${GOOGLE_ADMIN_KEY}) to find the key; use guided rotation.`,
  notFound: 'The Google API key was not found in the configured project; use guided rotation.',
  reference: 'Google API key reference is not valid; use guided rotation.',
  createRejected: 'Google rejected the replacement API key request; no key was created. Use guided rotation.',
  clientKey: 'This Google API key is restricted to websites or mobile apps, so it ships inside clients keysentry cannot redeploy. Use guided rotation and delete the old key only after those clients have updated.',
  createUnanswered: 'Google did not answer the API key creation request; an unused replacement may appear in the project. Check the Google Cloud console.',
  createUnknown: 'Google API key creation did not finish with a usable result; an unused replacement may appear in the project. Check the Google Cloud console.',
  createRunning: 'Google API key creation is still running; an unused replacement may appear in the project without keysentry recording it.',
} as const;

export class GoogleGuidedRotationRequiredError extends Error {
  readonly code = 'GUIDED_ROTATION_REQUIRED';
  readonly provider = 'google';
  /**
   * True when the old key lives in shipped clients (browser, Android or iOS restrictions): after a guided replacement
   * the engine keeps the old key instead of deleting it, and the person deletes it once those clients have updated.
   */
  readonly retainOldKey: boolean;

  constructor(message: string = MESSAGES.restrictions, options: { retainOldKey?: boolean } = {}) {
    super(message);
    this.name = 'GoogleGuidedRotationRequiredError';
    this.retainOldKey = options.retainOldKey === true;
  }
}

class OperationFailedError extends Error {}
class OperationRunningError extends Error {}

/**
 * Guided steps for a public Google API key (Firebase web config, Maps keys for browsers and apps, keys in variables a
 * build tool ships to clients). Such a key is restricted, not secret, and rotating it breaks shipped clients.
 */
export function publicGoogleKeyGuidance(): Guidance {
  return {
    url: 'https://console.cloud.google.com/apis/credentials',
    steps: [
      'This key is public by design: it ships inside web pages or mobile apps, so its restrictions protect it, not secrecy. Rotating it breaks every installed app and cached page that still uses the old key.',
      'Usually the right fix is to tighten its restrictions: allow only your websites or app IDs, and only the APIs it needs.',
      'If it must be replaced, create a new key with the same restrictions, paste it here, and publish new web and app builds.',
      'Delete the old key yourself, only after the shipped apps and pages that used it have updated. keysentry does not delete it.',
    ],
  };
}

type Row = Record<string, unknown>;

interface ServiceAccount {
  email: string;
  key: KeyObject;
  privateKey: string;
  keyId?: string;
  projectId?: string;
}

interface Session {
  token: string;
  secrets: string[];
  project?: string;
}

interface CreateBody {
  displayName: string;
  restrictions?: Row;
  annotations?: Record<string, string>;
  serviceAccountEmail?: string;
}

export interface GoogleProviderOptions {
  /** Waits between long-running operation polls (tests inject a no-op). */
  sleep?: (ms: number) => Promise<void>;
  /** Clock for JWT issue times and default display names. */
  now?: () => Date;
}

function record(value: unknown): Row | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Row : undefined;
}

function safeLabel(value: unknown, secrets: readonly string[]): string {
  const label = safeIdentity(value, '', [...secrets]);
  return GOOGLE_KEY_SHAPE.test(label) ? '' : label;
}

function nonEmpty(value: string | undefined): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value : undefined;
}

/** Every configured credential except the (public) project id, plus extra values such as the key being rotated. */
function secretValues(ctx: ProviderContext, extra: (string | undefined)[] = []): string[] {
  const configured = Object.entries(ctx.credentials)
    .filter(([name, value]) => name !== GOOGLE_PROJECT && typeof value === 'string')
    .map(([, value]) => value as string);
  return [...configured, ...extra.filter((value): value is string => typeof value === 'string')]
    .filter(value => value.length >= 8);
}

/** Short values are not secrets worth guarding and would block ordinary URLs. */
function protect(s: Session, value: string): void {
  if (value.length >= 8) s.secrets.push(value);
}

/** Like shared.request, but the configured project id may appear in paths; errors never echo upstream text. */
async function call(ctx: ProviderContext, req: HttpRequest, secrets: readonly string[]): Promise<HttpResponse> {
  let decoded: string;
  try { decoded = decodeURIComponent(req.url); } catch { throw new Error(`${PROVIDER} request failed`); }
  if (secrets.some(secret => req.url.includes(secret) || decoded.includes(secret))) throw new Error(`${PROVIDER} request failed`);
  try {
    return await ctx.http.request(req);
  } catch {
    throw new Error(`${PROVIDER} request failed`);
  }
}

function looksLikeServiceAccount(value: string): boolean {
  const text = value.trim();
  if (!text.startsWith('{')) return false;
  try {
    return record(JSON.parse(text))?.type === 'service_account';
  } catch {
    return false;
  }
}

function parseServiceAccount(text: string, label: string): ServiceAccount {
  const invalid = () => new Error(`${label} is not a usable Google service-account key`);
  let data: Row | undefined;
  try { data = record(JSON.parse(text)); } catch { throw invalid(); }
  if (!data || data.type !== 'service_account') throw invalid();
  const email = data.client_email;
  const pem = data.private_key;
  if (typeof email !== 'string' || !/^[^\s@]{1,128}@[A-Za-z0-9.-]{1,253}$/.test(email) || typeof pem !== 'string') throw invalid();
  let key: KeyObject;
  try { key = createPrivateKey(pem); } catch { throw invalid(); }
  if (key.asymmetricKeyType !== 'rsa') throw invalid();
  const keyId = data.private_key_id;
  if (keyId !== undefined && (typeof keyId !== 'string' || !/^[A-Za-z0-9]{1,128}$/.test(keyId))) throw invalid();
  // keysentry only ever sends assertions to the documented token endpoint of the public Google universe.
  if (data.token_uri !== undefined && data.token_uri !== TOKEN_URL) throw invalid();
  if (data.universe_domain !== undefined && data.universe_domain !== 'googleapis.com') throw invalid();
  const projectId = typeof data.project_id === 'string' && PROJECT.test(data.project_id) ? data.project_id : undefined;
  return { email, key, privateKey: pem, ...(keyId ? { keyId } : {}), ...(projectId ? { projectId } : {}) };
}

/** RS256 JWT for the OAuth 2.0 JWT bearer grant (developers.google.com/identity/protocols/oauth2/service-account). */
function assertion(account: ServiceAccount, scope: string, now: Date): string {
  const iat = Math.floor(now.getTime() / 1000);
  const encode = (value: object) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
  const unsigned = `${encode({ alg: 'RS256', typ: 'JWT', ...(account.keyId ? { kid: account.keyId } : {}) })}.${
    encode({ iss: account.email, scope, aud: TOKEN_URL, iat, exp: iat + 3600 })}`;
  return `${unsigned}.${sign('sha256', Buffer.from(unsigned, 'utf8'), account.key).toString('base64url')}`;
}

function tokenRequest(ctx: ProviderContext, account: ServiceAccount, scope: string, now: Date,
  secrets: readonly string[]): Promise<HttpResponse> {
  return call(ctx, {
    method: 'POST',
    url: TOKEN_URL,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: JWT_BEARER, assertion: assertion(account, scope, now) }).toString(),
  }, secrets);
}

function accessToken(response: HttpResponse): string {
  const data = record(readJson<unknown>(response, PROVIDER));
  const token = data?.access_token;
  if (typeof token !== 'string' || !ACCESS_TOKEN.test(token)
    || (data?.token_type !== undefined && (typeof data.token_type !== 'string' || !/^bearer$/i.test(data.token_type)))) {
    throw new Error(`${PROVIDER} returned an invalid OAuth token response`);
  }
  return token;
}

function keyName(value: unknown, secrets: readonly string[]): string | undefined {
  return typeof value === 'string' && KEY_NAME.test(value) && safeIdentity(value, '', [...secrets]) === value ? value : undefined;
}

function sameSecret(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function strings(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 1_000
    || !value.every(item => typeof item === 'string' && item.length > 0 && item.length <= 4_096)) {
    throw new GoogleGuidedRotationRequiredError();
  }
  return [...value] as string[];
}

function only(row: Row, allowed: readonly string[]): Row {
  if (Object.keys(row).some(field => !allowed.includes(field))) throw new GoogleGuidedRotationRequiredError();
  return row;
}

function child(value: unknown, allowed: readonly string[]): Row {
  const row = record(value);
  if (!row) throw new GoogleGuidedRotationRequiredError();
  return only(row, allowed);
}

/** Rebuild documented restrictions field by field; any shape keysentry does not understand stops the rotation. */
function copyRestrictions(value: unknown): Row {
  const source = child(value, ['apiTargets', ...CLIENT_RESTRICTIONS]);
  if (CLIENT_RESTRICTIONS.filter(field => source[field] !== undefined).length > 1) throw new GoogleGuidedRotationRequiredError();
  const copy: Row = {};
  if (source.apiTargets !== undefined) {
    if (!Array.isArray(source.apiTargets)) throw new GoogleGuidedRotationRequiredError();
    copy.apiTargets = source.apiTargets.map((entry) => {
      const target = child(entry, ['service', 'methods']);
      if (typeof target.service !== 'string' || !target.service.trim() || target.service.length > 256) {
        throw new GoogleGuidedRotationRequiredError();
      }
      return { service: target.service, ...(target.methods === undefined ? {} : { methods: strings(target.methods) }) };
    });
  }
  const list = (field: string, value: unknown, inner: string) => {
    const row = child(value, [inner]);
    copy[field] = row[inner] === undefined ? {} : { [inner]: strings(row[inner]) };
  };
  if (source.browserKeyRestrictions !== undefined) list('browserKeyRestrictions', source.browserKeyRestrictions, 'allowedReferrers');
  if (source.serverKeyRestrictions !== undefined) list('serverKeyRestrictions', source.serverKeyRestrictions, 'allowedIps');
  if (source.iosKeyRestrictions !== undefined) list('iosKeyRestrictions', source.iosKeyRestrictions, 'allowedBundleIds');
  if (source.androidKeyRestrictions !== undefined) {
    const android = child(source.androidKeyRestrictions, ['allowedApplications']);
    if (android.allowedApplications === undefined) copy.androidKeyRestrictions = {};
    else {
      if (!Array.isArray(android.allowedApplications) || android.allowedApplications.length > 1_000) {
        throw new GoogleGuidedRotationRequiredError();
      }
      copy.androidKeyRestrictions = { allowedApplications: android.allowedApplications.map((entry) => {
        const app = child(entry, ['sha1Fingerprint', 'packageName']);
        if (typeof app.sha1Fingerprint !== 'string' || !app.sha1Fingerprint || typeof app.packageName !== 'string' || !app.packageName) {
          throw new GoogleGuidedRotationRequiredError();
        }
        return { sha1Fingerprint: app.sha1Fingerprint, packageName: app.packageName };
      }) };
    }
  }
  return copy;
}

/** The create body that reproduces the old key's restrictions, annotations and bound service account. */
function replacementSpec(key: Row, name: string, now: Date): CreateBody {
  if (Object.keys(key).some(field => !KEY_FIELDS.has(field)) || key.name !== name
    || (key.deleteTime !== undefined && key.deleteTime !== '')) {
    throw new GoogleGuidedRotationRequiredError();
  }
  const body: CreateBody = { displayName: `keysentry ${now.toISOString().slice(0, 10)}` };
  if (key.displayName !== undefined && key.displayName !== '') {
    if (typeof key.displayName !== 'string' || key.displayName.length > 63) throw new GoogleGuidedRotationRequiredError();
    body.displayName = key.displayName;
  }
  if (key.restrictions !== undefined) {
    const restrictions = copyRestrictions(key.restrictions);
    if (Object.keys(restrictions).length > 0) body.restrictions = restrictions;
  }
  if (key.annotations !== undefined) {
    const annotations = record(key.annotations);
    if (!annotations || !Object.values(annotations).every(value => typeof value === 'string')) {
      throw new GoogleGuidedRotationRequiredError();
    }
    if (Object.keys(annotations).length > 0) body.annotations = { ...annotations } as Record<string, string>;
  }
  if (key.serviceAccountEmail !== undefined && key.serviceAccountEmail !== '') {
    if (typeof key.serviceAccountEmail !== 'string' || !SERVICE_ACCOUNT_EMAIL.test(key.serviceAccountEmail)) {
      throw new GoogleGuidedRotationRequiredError();
    }
    body.serviceAccountEmail = key.serviceAccountEmail;
  }
  return body;
}

interface Operation { name?: string; done: boolean; failed: boolean; response?: unknown }

function operation(value: unknown): Operation {
  const op = record(value);
  if (!op || (op.done !== undefined && typeof op.done !== 'boolean')) throw new Error(`${PROVIDER} returned an invalid operation`);
  const name = typeof op.name === 'string' && OPERATION.test(op.name) ? op.name : undefined;
  if (op.name !== undefined && !name) throw new Error(`${PROVIDER} returned an invalid operation`);
  const done = op.done === true;
  if (!done && !name) throw new Error(`${PROVIDER} returned an invalid operation`);
  return { ...(name ? { name } : {}), done, failed: done && op.error !== undefined, response: op.response };
}

export function createGoogleProvider(options: GoogleProviderOptions = {}): ProviderAdapter {
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => { setTimeout(resolve, ms); }));
  const now = options.now ?? (() => new Date());

  /** null when no management credential is configured. Throws fixed errors for unusable credentials. */
  async function session(ctx: ProviderContext): Promise<Session | null> {
    const adminKey = nonEmpty(ctx.credentials[GOOGLE_ADMIN_KEY]);
    const direct = nonEmpty(ctx.credentials[GOOGLE_ACCESS_TOKEN]);
    const configuredProject = nonEmpty(ctx.credentials[GOOGLE_PROJECT])?.trim();
    if (!adminKey && !direct) return null;
    const secrets = secretValues(ctx);
    let token: string;
    let keyProject: string | undefined;
    if (adminKey) {
      const account = parseServiceAccount(adminKey, GOOGLE_ADMIN_KEY);
      secrets.push(account.privateKey);
      const response = await tokenRequest(ctx, account, CLOUD_SCOPE, now(), secrets);
      if (response.status < 200 || response.status >= 300) {
        throw new Error(`${PROVIDER} OAuth token request failed (HTTP ${response.status})`);
      }
      token = accessToken(response);
      keyProject = account.projectId;
    } else {
      if (!ACCESS_TOKEN.test(direct!)) throw new Error(`${GOOGLE_ACCESS_TOKEN} is not a usable access token`);
      token = direct!;
    }
    secrets.push(token);
    if (configuredProject !== undefined && !PROJECT.test(configuredProject)) {
      throw new Error(`${GOOGLE_PROJECT} is not a valid Google Cloud project ID or number`);
    }
    const project = configuredProject ?? keyProject;
    return { token, secrets, ...(project ? { project } : {}) };
  }

  async function api(ctx: ProviderContext, s: Session, method: HttpRequest['method'], url: string): Promise<unknown> {
    const response = await call(ctx, { method, url, headers: { Authorization: `Bearer ${s.token}` } }, s.secrets);
    ensureOk(response, PROVIDER);
    return readJson<unknown>(response, PROVIDER);
  }

  /** Full listing, following nextPageToken. Returns at most `limit + 1` rows so callers can detect overflow. */
  async function keyRows(ctx: ProviderContext, s: Session, project: string, limit = Number.POSITIVE_INFINITY): Promise<Row[]> {
    const rows: Row[] = [];
    const names = new Set<string>();
    const tokens = new Set<string>();
    let pageToken: string | undefined;
    for (let page = 0; page < MAX_PAGES; page++) {
      const query = pageToken === undefined ? '' : `?pageToken=${encodeURIComponent(pageToken)}`;
      const data = record(await api(ctx, s, 'GET', `${API_KEYS}/projects/${project}/locations/global/keys${query}`));
      if (!data || (data.keys !== undefined && !Array.isArray(data.keys))) throw new Error(`${PROVIDER} returned an invalid key list`);
      for (const entry of (data.keys as unknown[] | undefined) ?? []) {
        const row = record(entry);
        const name = keyName(row?.name, s.secrets);
        if (!row || !name || names.has(name)) throw new Error(`${PROVIDER} returned an invalid key list`);
        names.add(name);
        rows.push(row);
        if (rows.length > limit) return rows;
      }
      const next = data.nextPageToken;
      if (next === undefined || next === '') return rows;
      if (typeof next !== 'string' || next.length > 4_096 || tokens.has(next)) throw new Error(`${PROVIDER} returned an invalid key list`);
      tokens.add(next);
      pageToken = next;
    }
    throw new Error(`${PROVIDER} returned too many key list pages`);
  }

  /** Map a key value to its resource name without putting the value in a URL (keys:lookupKey would). */
  async function findKeyName(ctx: ProviderContext, s: Session, project: string, value: string): Promise<string | null> {
    const rows = await keyRows(ctx, s, project, MAX_KEYS);
    if (rows.length > MAX_KEYS) return null;
    for (const row of rows) {
      if (typeof row.deleteTime === 'string' && row.deleteTime !== '') continue;
      const name = row.name as string;
      const data = record(await api(ctx, s, 'GET', `${API_KEYS}/${name}/keyString`));
      if (typeof data?.keyString !== 'string') throw new Error(`${PROVIDER} returned an invalid key string response`);
      if (sameSecret(data.keyString, value)) return name;
    }
    return null;
  }

  async function settle(ctx: ProviderContext, s: Session, first: unknown, action: 'creation' | 'deletion'): Promise<unknown> {
    let op = operation(first);
    const name = op.name;
    for (let attempt = 0; !op.done; attempt++) {
      if (attempt >= POLL_DELAYS_MS.length) {
        throw new OperationRunningError(action === 'creation'
          ? MESSAGES.createRunning
          : `${PROVIDER} API key deletion is still running; check the key in the Google Cloud console.`);
      }
      await sleep(POLL_DELAYS_MS[attempt]!);
      op = operation(await api(ctx, s, 'GET', `${API_KEYS}/${name}`));
      if (op.name !== undefined && op.name !== name) throw new Error(`${PROVIDER} returned an invalid operation`);
    }
    if (op.failed) throw new OperationFailedError(`${PROVIDER} API key ${action} failed`);
    return op.response;
  }

  async function replace(ctx: ProviderContext, s: Session, oldName: string, oldValue?: string): Promise<RotationResult> {
    const key = record(await api(ctx, s, 'GET', `${API_KEYS}/${oldName}`));
    if (!key) throw new Error(`${PROVIDER} returned an invalid key`);
    // Keys restricted to websites or apps live in shipped clients: replacing and later deleting them breaks those
    // clients, which keysentry cannot redeploy.
    const restrictions = record(key.restrictions);
    if (restrictions && SHIPPED_CLIENT_RESTRICTIONS.some(field => restrictions[field] !== undefined && restrictions[field] !== null)) {
      throw new GoogleGuidedRotationRequiredError(MESSAGES.clientKey, { retainOldKey: true });
    }
    const body = replacementSpec(key, oldName, now());
    const project = KEY_NAME.exec(oldName)![1]!;
    let response: HttpResponse;
    try {
      response = await call(ctx, {
        method: 'POST',
        url: `${API_KEYS}/projects/${project}/locations/global/keys`,
        headers: { Authorization: `Bearer ${s.token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }, s.secrets);
    } catch {
      throw new ProviderMutationUncertainError(MESSAGES.createUnanswered);
    }
    // A synchronous client error means no long-running operation started, so nothing was created.
    if ([400, 401, 403, 404].includes(response.status)) throw new GoogleGuidedRotationRequiredError(MESSAGES.createRejected);
    if (response.status >= 500) {
      throw new ProviderMutationUncertainError(`${PROVIDER} request failed (HTTP ${response.status}); an unused replacement may appear in the project. Check the Google Cloud console.`);
    }
    ensureOk(response, PROVIDER);
    let created: Row | undefined;
    try {
      created = record(await settle(ctx, s, readJson<unknown>(response, PROVIDER), 'creation'));
    } catch (error) {
      // A failed operation created nothing. Anything else (still running, unreadable, a failed poll) may leave a key.
      if (error instanceof OperationFailedError) throw error;
      throw new ProviderMutationUncertainError(error instanceof OperationRunningError ? MESSAGES.createRunning : MESSAGES.createUnknown);
    }
    const newName = keyName(created?.name, s.secrets);
    const invalid = () => new ProviderMutationUncertainError(
      `${PROVIDER} returned an invalid replacement key response; check the project for an unused key created just now.`,
      false, newName !== undefined && newName !== oldName ? newName : null);
    if (!created || !newName || newName === oldName || KEY_NAME.exec(newName)![1] !== project) throw invalid();
    let keyString = created.keyString;
    if (keyString === undefined) {
      try {
        keyString = record(await api(ctx, s, 'GET', `${API_KEYS}/${newName}/keyString`))?.keyString;
      } catch {
        throw invalid();
      }
    }
    if (typeof keyString !== 'string' || !KEY_STRING.test(keyString) || (oldValue !== undefined && sameSecret(keyString, oldValue))
      || s.secrets.includes(keyString)) {
      throw invalid();
    }
    return {
      newValue: keyString,
      oldKeyRef: oldName,
      newKeyRef: newName,
      oldRevoked: false,
      ...(body.restrictions ? {} : {
        notes: 'The previous Google API key had no API or application restrictions, so the replacement has none either. Consider adding restrictions in the Google Cloud console.',
      }),
    };
  }

  async function verifyApiKey(value: string, ctx: ProviderContext): Promise<VerifyResult> {
    let status: number | undefined;
    try {
      const response = await call(ctx, { method: 'GET', url: GEMINI_MODELS, headers: { 'x-goog-api-key': value } },
        secretValues(ctx, [value]));
      status = response.status;
      if (status >= 200 && status < 300) {
        const data = record(readJson<unknown>(response, PROVIDER));
        if (!data || (data.models !== undefined && !Array.isArray(data.models))) throw new Error();
        return { ok: true, status, identity: 'Gemini API key' };
      }
      if (status === 403 && LIMITED_REASONS.has(errorReason(response) ?? '')) {
        return { ok: true, status, identity: `${PROVIDER} API key (limited)` };
      }
      return { ok: false, status, error: `${PROVIDER} verification failed (HTTP ${status})` };
    } catch {
      return { ok: false, ...(status === undefined ? {} : { status }), error: `${PROVIDER} verification failed` };
    }
  }

  async function verifyServiceAccount(value: string, ctx: ProviderContext): Promise<VerifyResult> {
    let account: ServiceAccount;
    try { account = parseServiceAccount(value, 'The value'); } catch {
      return { ok: false, error: `${PROVIDER} service-account key is malformed` };
    }
    const secrets = secretValues(ctx, [value, account.privateKey]);
    let status: number | undefined;
    try {
      const response = await tokenRequest(ctx, account, READ_ONLY_SCOPE, now(), secrets);
      status = response.status;
      if (status < 200 || status >= 300) return { ok: false, status, error: `${PROVIDER} service-account verification failed (HTTP ${status})` };
      accessToken(response);
      return { ok: true, status, identity: safeIdentity(account.email, `${PROVIDER} service account`, secrets) };
    } catch {
      return { ok: false, ...(status === undefined ? {} : { status }), error: `${PROVIDER} service-account verification failed` };
    }
  }

  function credentialsMissing(): Error {
    return new Error(`Missing provider credential: ${GOOGLE_ADMIN_KEY} or ${GOOGLE_ACCESS_TOKEN}`);
  }

  return {
    id: 'google',
    method: 'auto',

    verify(value, ctx) {
      return looksLikeServiceAccount(value) ? verifyServiceAccount(value, ctx) : verifyApiKey(value, ctx);
    },

    async rotate(oldValue, ctx) {
      if (looksLikeServiceAccount(oldValue)) throw new GoogleGuidedRotationRequiredError(MESSAGES.serviceAccountKey);
      const s = await session(ctx);
      if (!s) throw new GoogleGuidedRotationRequiredError(MESSAGES.credentials);
      if (!s.project) throw new GoogleGuidedRotationRequiredError(MESSAGES.project);
      protect(s, oldValue);
      const name = await findKeyName(ctx, s, s.project, oldValue);
      if (!name) throw new GoogleGuidedRotationRequiredError(MESSAGES.notFound);
      return replace(ctx, s, name, oldValue);
    },

    async rotateByRef(ref, ctx) {
      if (!keyName(ref, secretValues(ctx))) throw new GoogleGuidedRotationRequiredError(MESSAGES.reference);
      const s = await session(ctx);
      if (!s) throw new GoogleGuidedRotationRequiredError(MESSAGES.credentials);
      return replace(ctx, s, ref);
    },

    async revoke(ref, ctx) {
      if (!keyName(ref, secretValues(ctx))) throw new Error(`${PROVIDER} requires a valid API key reference`);
      const s = await session(ctx);
      if (!s) throw credentialsMissing();
      const response = await call(ctx, { method: 'DELETE', url: `${API_KEYS}/${ref}`, headers: { Authorization: `Bearer ${s.token}` } }, s.secrets);
      ensureOk(response, PROVIDER);
      await settle(ctx, s, readJson<unknown>(response, PROVIDER), 'deletion');
    },

    async resolveKeyRef(value, ctx) {
      // The engine also resolves old keys during guided fallback; an unidentified key is reported, never guessed.
      if (looksLikeServiceAccount(value)) return null;
      try {
        const s = await session(ctx);
        if (!s?.project) return null;
        protect(s, value);
        return await findKeyName(ctx, s, s.project, value);
      } catch {
        ctx.log.warn('Google API key reference lookup failed.');
        return null;
      }
    },

    async listKeys(ctx): Promise<ProviderKeyInfo[]> {
      const s = await session(ctx);
      if (!s) throw credentialsMissing();
      if (!s.project) throw new Error(`Missing provider credential: ${GOOGLE_PROJECT}`);
      return (await keyRows(ctx, s, s.project)).map((row) => {
        const name = safeLabel(row.displayName, s.secrets);
        const createdAt = typeof row.createTime === 'string' && !Number.isNaN(Date.parse(row.createTime)) ? row.createTime : undefined;
        return { keyRef: row.name as string, ...(name ? { name } : {}), ...(createdAt ? { createdAt } : {}) };
      });
    },

    guidance() {
      return {
        url: 'https://console.cloud.google.com/apis/credentials',
        steps: [
          'For an API key, open Google Cloud credentials (or Google AI Studio for a Gemini key) and create a replacement with the same API restrictions, application restrictions and bound service account; the console Rotate key action copies restrictions.',
          'For a service-account JSON key, create a new key for the same service account in IAM and replace the whole JSON document, including private_key and private_key_id.',
          'Update every consumer and redeploy, verify the affected Google API calls, then delete the old API key or disable and delete the old service-account key.',
          `For automatic API key rotation, configure ${GOOGLE_ADMIN_KEY} (a service-account key with the API Keys Admin role) or ${GOOGLE_ACCESS_TOKEN}.`,
        ],
      };
    },
  };
}

function errorReason(response: HttpResponse): string | undefined {
  try {
    const details = record(record(response.json<unknown>())?.error)?.details;
    if (!Array.isArray(details)) return undefined;
    const info = details.map(record).find(item => item?.['@type'] === 'type.googleapis.com/google.rpc.ErrorInfo');
    return typeof info?.reason === 'string' ? info.reason : undefined;
  } catch {
    return undefined;
  }
}

export const googleProvider = createGoogleProvider();
