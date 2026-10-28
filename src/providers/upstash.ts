import type { HttpResponse, ProviderAdapter, ProviderContext, RotationResult, VerifyResult } from '../types.js';
import { credential, ensureOk, PLANNED_FORM_PREFIX, ProviderMutationUncertainError, readJson, request, verifyRead } from './shared.js';
import type { CredentialForms, CredentialFormsSource } from './shared.js';

// Docs (accessed 2026-10-28): https://upstash.com/docs/devops/developer-api/authentication.md,
// .../developer-api/redis/list_databases.md, .../developer-api/redis/reset_password.md,
// https://upstash.com/docs/api-reference/qstash/list-qstash-users.md, .../qstash/reset-qstash-token.md,
// https://upstash.com/docs/redis/features/restapi.md, https://upstash.com/docs/qstash/api-reference/queues/list-queues.md.
const MGMT = 'https://api.upstash.com/v2';
const PROVIDER = 'Upstash';
const ID = /^[A-Za-z0-9-]{1,64}$/;
const ENDPOINT = /^[A-Za-z0-9.-]{1,253}$/;
const QSTASH_REGION_HOSTS = ['qstash-eu-central-1.upstash.io', 'qstash-us-east-1.upstash.io'];

export class UpstashGuidedRotationRequiredError extends Error {
  readonly code = 'GUIDED_ROTATION_REQUIRED';
  readonly provider = 'upstash';

  constructor(reason = 'the Upstash credential could not be identified exactly') {
    super(`${reason}; use guided rotation.`);
    this.name = 'UpstashGuidedRotationRequiredError';
  }
}

type Row = Record<string, unknown>;

interface Database {
  id: string;
  host: string;
  port?: number;
  state?: string;
  password?: string;
  restToken?: string;
  readOnlyToken?: string;
}

interface QStashUser { id: string; token?: string; readOnlyToken?: string }

interface RedisUrl { scheme: string; user: string; password: string; host: string; hostRaw: string; port: string; rest: string }

type Target =
  | { kind: 'rest' | 'read-only' | 'password'; db: Database }
  | { kind: 'url'; db: Database; url: RedisUrl }
  | { kind: 'qstash' | 'qstash-read-only'; user: QStashUser };

function record(value: unknown): Row | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Row : undefined;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function mgmtHeaders(ctx: ProviderContext): Record<string, string> {
  const email = credential(ctx, 'UPSTASH_ADMIN_EMAIL').trim();
  const key = credential(ctx, 'UPSTASH_ADMIN_KEY');
  return { Authorization: `Basic ${Buffer.from(`${email}:${key}`, 'utf8').toString('base64')}` };
}

const REDIS_URL = /^(rediss?:\/\/)([^:@/?#]*):([^@/?#]+)@([^/?#:]+)(:\d{1,5})?([/?#].*)?$/i;

function parseRedisUrl(value: string): RedisUrl | null {
  const match = REDIS_URL.exec(value);
  if (!match) return null;
  let password: string;
  try {
    password = decodeURIComponent(match[3]!);
  } catch {
    return null;
  }
  return { scheme: match[1]!, user: match[2]!, password, host: match[4]!.toLowerCase(), hostRaw: match[4]!, port: match[5] ?? '', rest: match[6] ?? '' };
}

function withPassword(url: RedisUrl, password: string): string {
  return `${url.scheme}${url.user}:${encodeURIComponent(password)}@${url.hostRaw}${url.port}${url.rest}`;
}

function databaseHost(endpoint: string): string {
  const host = endpoint.toLowerCase();
  return host.includes('.') ? host : `${host}.upstash.io`;
}

async function listDatabases(ctx: ProviderContext): Promise<Database[]> {
  const response = await request(ctx, { method: 'GET', url: `${MGMT}/redis/databases`, headers: mgmtHeaders(ctx) }, PROVIDER);
  ensureOk(response, PROVIDER);
  const rows = readJson<unknown>(response, PROVIDER);
  if (!Array.isArray(rows)) throw new Error(`${PROVIDER} returned an invalid database list`);
  return rows.map((entry) => {
    const row = record(entry);
    if (!row || typeof row.database_id !== 'string' || !ID.test(row.database_id)
      || typeof row.endpoint !== 'string' || !ENDPOINT.test(row.endpoint)) {
      throw new Error(`${PROVIDER} returned an invalid database list`);
    }
    const db: Database = { id: row.database_id, host: databaseHost(row.endpoint) };
    if (typeof row.state === 'string') db.state = row.state;
    if (typeof row.port === 'number' && Number.isInteger(row.port) && row.port > 0 && row.port < 65536) db.port = row.port;
    const password = optionalString(row.password);
    const restToken = optionalString(row.rest_token);
    const readOnlyToken = optionalString(row.read_only_rest_token);
    if (password) db.password = password;
    if (restToken) db.restToken = restToken;
    if (readOnlyToken) db.readOnlyToken = readOnlyToken;
    return db;
  });
}

async function listQStashUsers(ctx: ProviderContext): Promise<QStashUser[]> {
  const response = await request(ctx, { method: 'GET', url: `${MGMT}/qstash/users`, headers: mgmtHeaders(ctx) }, PROVIDER);
  ensureOk(response, PROVIDER);
  const rows = readJson<unknown>(response, PROVIDER);
  if (!Array.isArray(rows)) throw new Error(`${PROVIDER} returned an invalid QStash user list`);
  return rows.map((entry) => {
    const row = record(entry);
    if (!row || typeof row.id !== 'string' || !ID.test(row.id)) throw new Error(`${PROVIDER} returned an invalid QStash user list`);
    const user: QStashUser = { id: row.id };
    const token = optionalString(row.token);
    const readOnlyToken = optionalString(row.read_only_token);
    if (token) user.token = token;
    if (readOnlyToken) user.readOnlyToken = readOnlyToken;
    return user;
  });
}

/**
 * Identify a value by exact comparison with the credentials the management API returns. There are no hints or
 * prefixes to match on, so nothing is guessed: no match or several matches return null / 'ambiguous'.
 */
async function identify(value: string, ctx: ProviderContext): Promise<Target | null | 'ambiguous'> {
  const url = parseRedisUrl(value);
  const matches: Target[] = [];
  for (const db of await listDatabases(ctx)) {
    if (url) {
      if (url.host === db.host && db.password !== undefined && url.password === db.password) matches.push({ kind: 'url', db, url });
      continue;
    }
    if (db.restToken === value) matches.push({ kind: 'rest', db });
    if (db.readOnlyToken === value) matches.push({ kind: 'read-only', db });
    if (db.password === value) matches.push({ kind: 'password', db });
  }
  if (matches.length > 1) return 'ambiguous';
  if (matches.length === 1 || url) return matches[0] ?? null;
  for (const user of await listQStashUsers(ctx)) {
    if (user.token === value) matches.push({ kind: 'qstash', user });
    if (user.readOnlyToken === value) matches.push({ kind: 'qstash-read-only', user });
  }
  return matches.length > 1 ? 'ambiguous' : matches[0] ?? null;
}

/** The Redis URLs the Upstash console and integrations write for a database (TLS and plain, with or without a user). */
function canonicalUrls(db: Database, password: string): string[] {
  const ports = [...new Set([db.port ?? 6379, 6379])].map(port => `:${port}`);
  const encoded = encodeURIComponent(password);
  return ['rediss://', 'redis://'].flatMap(scheme => ['default', ''].flatMap(user =>
    [...ports, ''].map(port => `${scheme}${user}:${encoded}@${db.host}${port}`)));
}

/**
 * Every form a reset by `ref` changes, as the management API lists it now: for a database the password, the REST
 * token, the read-only REST token and its Redis URLs; for a QStash user its token and read-only token. Matching is
 * exact (a Redis URL by host and password), so no other credential can be mistaken for a form.
 */
async function credentialForms(ref: string, ctx: ProviderContext): Promise<CredentialForms | null> {
  const db = (await listDatabases(ctx)).find(candidate => candidate.id === ref);
  if (db) {
    const values = [db.password, db.restToken, db.readOnlyToken].filter((value): value is string => value !== undefined);
    if (db.password !== undefined) values.push(...canonicalUrls(db, db.password));
    return {
      values,
      holds(value) {
        if (values.includes(value) || values.includes(value.trim())) return true;
        const url = parseRedisUrl(value.trim());
        return url !== null && db.password !== undefined && url.host === db.host && url.password === db.password;
      },
    };
  }
  const user = (await listQStashUsers(ctx)).find(candidate => candidate.id === ref);
  if (!user) return null;
  const values = [user.token, user.readOnlyToken].filter((value): value is string => value !== undefined);
  return { values, holds: value => values.includes(value) || values.includes(value.trim()) };
}

const ROLLED_UNKNOWN = 'Upstash completed the reset but did not return usable new credentials; the old credentials may already be invalid. Copy the new values from the Upstash console and update every consumer now.';
const UNCONFIRMED = 'the reset may already have happened. Check the credential in the Upstash console before retrying.';

/**
 * A reset whose outcome is unknown (transport failure, 5xx) must not read as "nothing changed": it raises the coded
 * ProviderMutationUncertainError, which the engine reports as a possibly rolled credential.
 */
async function mutate(ctx: ProviderContext, url: string): Promise<HttpResponse> {
  let response: HttpResponse;
  try {
    response = await request(ctx, { method: 'POST', url, headers: mgmtHeaders(ctx) }, PROVIDER);
  } catch {
    throw new ProviderMutationUncertainError(`${PROVIDER} did not answer the reset request; ${UNCONFIRMED}`, true);
  }
  if (response.status >= 500) throw new ProviderMutationUncertainError(`${PROVIDER} request failed (HTTP ${response.status}); ${UNCONFIRMED}`, true);
  ensureOk(response, PROVIDER);
  return response;
}

/** Other forms of the same database credential in the context service, rewritten with the new values. */
function redisCompanions(siblings: Record<string, string>, primary: string, before: Database,
  after: { password: string; restToken: string; readOnlyToken?: string }): { companions: Record<string, string>; readOnlyUnknown: boolean } {
  const companions: Record<string, string> = {};
  let readOnlyUnknown = false;
  for (const [name, value] of Object.entries(siblings)) {
    if (typeof value !== 'string' || value === primary) continue;
    if (value === before.restToken) companions[name] = after.restToken;
    else if (value === before.password) companions[name] = after.password;
    else if (before.readOnlyToken !== undefined && value === before.readOnlyToken) {
      if (after.readOnlyToken === undefined) readOnlyUnknown = true;
      // A planned form is answered even when unchanged, so the engine can tell "unchanged" from "unknown".
      else if (after.readOnlyToken !== before.readOnlyToken || name.startsWith(PLANNED_FORM_PREFIX)) companions[name] = after.readOnlyToken;
    } else {
      const url = parseRedisUrl(value);
      if (url && url.host === before.host && url.password === before.password) companions[name] = withPassword(url, after.password);
    }
  }
  return { companions, readOnlyUnknown };
}

async function rollDatabase(target: Extract<Target, { db: Database }>, oldValue: string, ctx: ProviderContext): Promise<RotationResult> {
  const { db } = target;
  const response = await mutate(ctx, `${MGMT}/redis/reset-password/${db.id}`);
  let fresh: Row | undefined;
  try {
    fresh = record(response.json<unknown>());
  } catch {
    fresh = undefined;
  }
  const password = optionalString(fresh?.password);
  const restToken = optionalString(fresh?.rest_token);
  if (!password || !restToken || password === db.password || restToken === db.restToken) throw new ProviderMutationUncertainError(ROLLED_UNKNOWN, true);
  const readOnlyToken = optionalString(fresh?.read_only_rest_token);
  const newValue = target.kind === 'rest' ? restToken : target.kind === 'password' ? password : withPassword((target as { url: RedisUrl }).url, password);
  const { companions, readOnlyUnknown } = redisCompanions(ctx.siblingVars ?? {}, oldValue, db,
    { password, restToken, ...(readOnlyToken ? { readOnlyToken } : {}) });
  const notes = ['Upstash reset the database password atomically: the previous password, REST token and Redis URLs stopped working. keysentry updates every form of this credential it planned; redeploy every consumer immediately.'];
  if (readOnlyUnknown) notes.push('A read-only REST token in this service may also have changed; check it in the Upstash console.');
  return {
    newValue, oldKeyRef: db.id, newKeyRef: db.id, oldRevoked: true,
    ...(Object.keys(companions).length > 0 ? { companions } : {}),
    notes: notes.join(' '),
  };
}

async function rollQStash(user: QStashUser, ctx: ProviderContext): Promise<RotationResult> {
  const response = await mutate(ctx, `${MGMT}/qstash/rotate-token/${user.id}`);
  let fresh: Row | undefined;
  try {
    fresh = record(response.json<unknown>());
  } catch {
    fresh = undefined;
  }
  const token = optionalString(fresh?.token);
  if (!token || token === user.token) throw new ProviderMutationUncertainError(ROLLED_UNKNOWN, true);
  const readOnlyToken = optionalString(fresh?.read_only_token);
  const companions: Record<string, string> = {};
  if (user.readOnlyToken !== undefined && readOnlyToken !== undefined) {
    for (const [name, value] of Object.entries(ctx.siblingVars ?? {})) {
      // A planned form is answered even when unchanged, so the engine can tell "unchanged" from "unknown".
      if (value === user.readOnlyToken && (readOnlyToken !== user.readOnlyToken || name.startsWith(PLANNED_FORM_PREFIX))) companions[name] = readOnlyToken;
    }
  }
  return {
    newValue: token, oldKeyRef: user.id, newKeyRef: user.id, oldRevoked: true,
    ...(Object.keys(companions).length > 0 ? { companions } : {}),
    notes: 'Upstash rotated the QStash token atomically: the previous token stopped working. Update and redeploy every consumer immediately. Signing keys are unchanged.',
  };
}

function restOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash
      || (url.pathname !== '/' && url.pathname !== '') || !/^[a-z0-9-]+\.upstash\.io$/.test(url.hostname)
      || url.hostname.startsWith('qstash')) return null;
    return url.origin;
  } catch {
    return null;
  }
}

function qstashHost(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash
      || (url.pathname !== '/' && url.pathname !== '') || !/^qstash(?:-[a-z0-9-]+)?\.upstash\.io$/.test(url.hostname)) return null;
    return url.hostname;
  } catch {
    return null;
  }
}

/** The REST URL paired with a token: `<PREFIX>_URL` for `<PREFIX>_TOKEN` / `<PREFIX>_READ_ONLY_TOKEN`, else the only one. */
function pairedRestUrl(holders: string[], siblings: Record<string, string>): string | null {
  for (const holder of holders) {
    const prefix = /^(.*?)(?:_READ_ONLY_TOKEN|_TOKEN)$/.exec(holder)?.[1];
    const candidate = prefix === undefined ? undefined : siblings[`${prefix}_URL`];
    const origin = typeof candidate === 'string' ? restOrigin(candidate) : null;
    if (origin) return origin;
  }
  const origins = new Set(Object.values(siblings).map((value) => typeof value === 'string' ? restOrigin(value) : null)
    .filter((origin): origin is string => origin !== null));
  return origins.size === 1 ? [...origins][0]! : null;
}

async function verifyQStash(value: string, siblings: Record<string, string>, ctx: ProviderContext): Promise<VerifyResult> {
  const configured = Object.entries(siblings).filter(([name]) => /QSTASH.*URL$/.test(name)).map(([, url]) => qstashHost(url));
  const hosts = configured.length === 1 && configured[0] ? [configured[0]] : QSTASH_REGION_HOSTS;
  let result: VerifyResult = { ok: true, identity: 'unverified' };
  for (const host of hosts) {
    result = await verifyRead(ctx, { method: 'GET', url: `https://${host}/v2/queues`, headers: { Authorization: `Bearer ${value}` } }, PROVIDER,
      (data) => {
        if (!Array.isArray(data)) throw new Error('invalid');
        return 'Upstash QStash token';
      });
    if (result.ok || result.status !== 401) return result;
  }
  return result;
}

/**
 * Redis database credentials (REST token, password, Redis URL) and QStash tokens roll atomically: Upstash documents
 * no way to create a second credential alongside the old one. Read-only tokens, QStash signing keys and management
 * API keys stay guided.
 */
export const upstashProvider: ProviderAdapter & CredentialFormsSource = {
  id: 'upstash',
  method: 'atomic-roll',

  async verify(value, ctx) {
    if (/^rediss?:\/\//i.test(value)) return { ok: true, identity: 'unverified' };
    const siblings = ctx.siblingVars ?? {};
    const holders = Object.keys(siblings).filter((name) => siblings[name] === value);
    if (holders.some((name) => /QSTASH/.test(name))) {
      // Only QStash tokens authenticate to QStash; signing keys verify webhooks and have no read to test them with.
      return holders.some((name) => /QSTASH.*TOKEN$/.test(name)) ? verifyQStash(value, siblings, ctx) : { ok: true, identity: 'unverified' };
    }
    const origin = pairedRestUrl(holders, siblings);
    if (!origin) return { ok: true, identity: 'unverified' };
    return verifyRead(ctx, { method: 'GET', url: `${origin}/ping`, headers: { Authorization: `Bearer ${value}` } }, PROVIDER, (data) => {
      if (record(data)?.result !== 'PONG') throw new Error('invalid');
      return 'Upstash Redis REST token';
    });
  },

  async resolveKeyRef(value, ctx) {
    const target = await identify(value, ctx);
    if (target === null || target === 'ambiguous') return null;
    return 'db' in target ? target.db.id : target.user.id;
  },

  credentialForms,

  async rotate(oldValue, ctx): Promise<RotationResult> {
    mgmtHeaders(ctx);
    let target: Target | null | 'ambiguous';
    try {
      target = await identify(oldValue, ctx);
    } catch {
      throw new UpstashGuidedRotationRequiredError('Upstash credentials could not be listed with UPSTASH_ADMIN_KEY');
    }
    if (target === null) throw new UpstashGuidedRotationRequiredError('the value does not match a credential visible to UPSTASH_ADMIN_KEY');
    if (target === 'ambiguous') throw new UpstashGuidedRotationRequiredError('the value matches more than one Upstash credential');
    if (target.kind === 'read-only' || target.kind === 'qstash-read-only') {
      throw new UpstashGuidedRotationRequiredError('Upstash does not document whether a reset replaces read-only tokens');
    }
    if ('user' in target) return rollQStash(target.user, ctx);
    if (target.db.password === undefined || target.db.restToken === undefined) {
      throw new UpstashGuidedRotationRequiredError('Upstash hides this database credential (credential protection or a read-only key)');
    }
    if (target.db.state !== undefined && target.db.state !== 'active') {
      throw new UpstashGuidedRotationRequiredError('the Upstash database is not active');
    }
    return rollDatabase(target, oldValue, ctx);
  },

  async rotateByRef() {
    throw new UpstashGuidedRotationRequiredError('Upstash credentials cannot be rolled by reference');
  },

  guidance() {
    return {
      url: 'https://console.upstash.com/',
      steps: [
        'For a Redis database: open the database and reset its password. The old password, REST token and Redis URL stop working at once, so update every form of the credential (REST token, read-only token, Redis URL) and redeploy right away.',
        'For QStash: open QStash, choose Reset token and confirm; the old token stops working at once. Signing keys are rolled separately and need both the current and next key updated.',
        'For a management API key: create a new key under Account > Developer API, update keysentry, then delete the old key.',
      ],
    };
  },
};
