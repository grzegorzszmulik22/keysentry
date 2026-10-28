import type { HttpRequest, ProviderAdapter, ProviderContext, ProviderKeyInfo, RotationResult } from '../types.js';
import { credential, ensureOk, mutationRequest, ProviderMutationUncertainError, readJson, request, safeIdentity, verifyRead } from './shared.js';

// Docs (accessed 2026-10-28): https://www.twilio.com/docs/iam/api-keys/key-resource-v1,
// https://www.twilio.com/docs/usage/requests-to-twilio, https://www.twilio.com/docs/api/errors/20003,
// https://www.twilio.com/docs/iam/api/secondary_authtoken, https://www.twilio.com/docs/iam/api/authtoken.
const API = 'https://api.twilio.com/2010-04-01';
const IAM = 'https://iam.twilio.com/v1';
const PROVIDER = 'Twilio';
const KEY_SID = /^SK[0-9a-fA-F]{32}$/;
const ACCOUNT_SID = /^AC[0-9a-fA-F]{32}$/;
/** Account Auth Tokens are 32 lowercase hex characters; API key secrets are mixed-case alphanumerics. */
const AUTH_TOKEN_SHAPE = /^[0-9a-f]{32}$/;
const MAX_PAGES = 1000;

export class TwilioGuidedRotationRequiredError extends Error {
  readonly code = 'GUIDED_ROTATION_REQUIRED';
  readonly provider = 'twilio';

  constructor(reason = 'Twilio key permissions could not be preserved safely') {
    super(`${reason}; use guided rotation.`);
    this.name = 'TwilioGuidedRotationRequiredError';
  }
}

type Row = Record<string, unknown>;
type Kind = 'api-key' | 'auth-token';
interface Policy { allow: string[] }
interface Admin { username: string; password: string; accountSid: string }
interface Pair {
  kind: Kind;
  /** API key SID paired with the secret (null for Auth Tokens or when not found / ambiguous). */
  keySid: string | null;
  /** Every sibling variable holding that SID; each receives the new SID as a companion. */
  keySidVars: string[];
  /** Account SID named by the service itself (never the management credential). */
  accountSid: string | null;
}

function record(value: unknown): Row | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Row : undefined;
}

function isIdentifier(value: string): boolean {
  return KEY_SID.test(value) || ACCOUNT_SID.test(value);
}

function basic(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`;
}

/**
 * Account and API key SIDs are public identifiers that Twilio puts in URL paths and queries. The shared request
 * guard refuses any URL containing a configured credential value, so SID-shaped credentials are left out of it.
 */
function requestCtx(ctx: ProviderContext): ProviderContext {
  const credentials = Object.fromEntries(Object.entries(ctx.credentials)
    .filter(([, value]) => typeof value !== 'string' || !isIdentifier(value.trim())));
  return { ...ctx, credentials };
}

function secrets(ctx: ProviderContext, extra: string[] = []): string[] {
  return [...Object.values(requestCtx(ctx).credentials).filter((value): value is string => typeof value === 'string'), ...extra];
}

function adminAuth(ctx: ProviderContext): Admin {
  const username = credential(ctx, 'TWILIO_ADMIN_KEY_SID').trim();
  const password = credential(ctx, 'TWILIO_ADMIN_KEY');
  if (!KEY_SID.test(username) && !ACCOUNT_SID.test(username)) {
    throw new Error('TWILIO_ADMIN_KEY_SID must be a Twilio Main API key SID or an Account SID');
  }
  const accountSid = ACCOUNT_SID.test(username) ? username : credential(ctx, 'TWILIO_ADMIN_ACCOUNT_SID').trim();
  if (!ACCOUNT_SID.test(accountSid)) throw new Error('TWILIO_ADMIN_ACCOUNT_SID must be a Twilio Account SID');
  return { username, password, accountSid };
}

function adminAccountSid(ctx: ProviderContext): string | null {
  for (const name of ['TWILIO_ADMIN_ACCOUNT_SID', 'TWILIO_ADMIN_KEY_SID']) {
    const value = ctx.credentials[name]?.trim();
    if (value && ACCOUNT_SID.test(value)) return value;
  }
  return null;
}

/** Choose one sibling value: a conventionally named variable first, else the only distinct value of that shape. */
function pick(siblings: Record<string, string>, candidates: string[], shape: RegExp, claimed: ReadonlySet<string> = new Set()): string | null {
  for (const name of candidates) {
    const value = siblings[name];
    if (typeof value === 'string' && shape.test(value)) return value;
  }
  const values = new Set(Object.values(siblings).filter((value) => typeof value === 'string' && shape.test(value)));
  if (values.size !== 1) return null;
  const only = [...values][0]!;
  // The fallback never takes a SID that sits under the conventional name of another secret's SID: that SID belongs to
  // the other secret (TWILIO_API_KEY to TWILIO_API_SECRET), not to the value being rotated.
  return Object.keys(siblings).some((name) => siblings[name] === only && claimed.has(name)) ? null : only;
}

/** Conventional names of the API key SID paired with a secret held under `holder` (TWILIO_API_SECRET -> TWILIO_API_KEY). */
export function twilioSidNames(holder: string): string[] {
  let match: RegExpExecArray | null;
  if ((match = /^(.*)API_KEY_SECRET$/.exec(holder))) return [`${match[1]}API_KEY_SID`, `${match[1]}API_KEY`];
  if ((match = /^(.*)API_SECRET$/.exec(holder))) return [`${match[1]}API_KEY`, `${match[1]}API_KEY_SID`, `${match[1]}API_SID`];
  if ((match = /^(.*)SECRET$/.exec(holder))) return [`${match[1]}SID`, `${match[1]}KEY_SID`];
  return [];
}

/**
 * The API key SID paired with a secret held under `holders` in one service: a conventionally named SID first, else the
 * only SK… value in the service, unless that SID is the conventional partner of another secret in the service.
 * Shared with the rotation engine's consistency check so both always agree.
 */
export function twilioKeySidFor(holders: string[], siblings: Record<string, string>): string | null {
  const own = holders.flatMap(twilioSidNames);
  const claimed = new Set(Object.keys(siblings)
    .filter((name) => !holders.includes(name) && /SECRET$/.test(name) && typeof siblings[name] === 'string' && siblings[name]!.length > 0)
    .flatMap(twilioSidNames));
  return pick(siblings, own, KEY_SID, claimed);
}

/**
 * Pair a secret with its identifier using the service's other variables. Naming conventions follow Twilio's docs
 * (TWILIO_ACCOUNT_SID, TWILIO_API_KEY with TWILIO_API_SECRET) plus the common *_API_KEY_SID / *_API_KEY_SECRET form.
 */
function findPair(value: string, ctx: ProviderContext): Pair {
  const siblings = ctx.siblingVars ?? {};
  const holders = Object.keys(siblings).filter((name) => siblings[name] === value);
  const kind: Kind = holders.some((name) => /AUTH_TOKEN$/.test(name)) ? 'auth-token'
    : holders.some((name) => /SECRET$/.test(name)) ? 'api-key'
      : AUTH_TOKEN_SHAPE.test(value) ? 'auth-token' : 'api-key';
  const accountNames: string[] = [];
  for (const holder of holders) {
    let match: RegExpExecArray | null;
    if ((match = /^(.*)AUTH_TOKEN$/.exec(holder))) {
      accountNames.push(`${match[1]}ACCOUNT_SID`);
    } else if ((match = /^(.*?)(?:API_KEY_SECRET|API_SECRET|SECRET)$/.exec(holder))) {
      accountNames.push(`${match[1]}ACCOUNT_SID`);
    }
  }
  accountNames.push('TWILIO_ACCOUNT_SID');
  const accountSid = pick(siblings, accountNames, ACCOUNT_SID);
  const keySid = kind === 'api-key' ? twilioKeySidFor(holders, siblings) : null;
  const keySidVars = keySid === null ? [] : Object.keys(siblings).filter((name) => siblings[name] === keySid).sort();
  return { kind, keySid, keySidVars, accountSid };
}

function applicationsRequest(accountSid: string, username: string, password: string): HttpRequest {
  return {
    method: 'GET',
    url: `${API}/Accounts/${accountSid}/Applications.json?PageSize=1`,
    headers: { Authorization: basic(username, password) },
  };
}

function parsePolicy(value: unknown): Policy | null {
  if (value === null) return null;
  const policy = record(value);
  // Only the documented allow-list shape can be reproduced exactly; anything else may carry restrictions keysentry
  // would silently drop.
  if (!policy || Object.keys(policy).length !== 1 || !Array.isArray(policy.allow) || policy.allow.length === 0
    || !policy.allow.every((entry) => typeof entry === 'string' && /^\/[\x21-\x7e]{1,256}$/.test(entry))) {
    throw new TwilioGuidedRotationRequiredError('Twilio key permissions use an unsupported policy shape');
  }
  return { allow: [...policy.allow as string[]] };
}

function samePolicy(requested: Policy | null, returned: unknown): boolean {
  if (requested === null) return returned === null || returned === undefined;
  const policy = record(returned);
  if (!policy || Object.keys(policy).length !== 1 || !Array.isArray(policy.allow)) return false;
  const left = [...requested.allow].sort();
  const right = [...policy.allow].map(String).sort();
  return left.length === right.length && left.every((entry, index) => entry === right[index]);
}

async function keyPolicy(pair: Pair & { keySid: string; accountSid: string }, oldValue: string, admin: Admin,
  ctx: ProviderContext): Promise<Policy | null> {
  try {
    // Prove the pair first: the secret must authenticate as the SID it was paired with. 2xx, or 403 for a Restricted
    // key without access to this list, proves it; 401 (or anything else) means the SID belongs to another secret.
    const proof = await request(ctx, applicationsRequest(pair.accountSid, pair.keySid, oldValue), PROVIDER);
    if (!(proof.status >= 200 && proof.status < 300) && proof.status !== 403) {
      throw new TwilioGuidedRotationRequiredError('the secret does not authenticate as the API key SID paired with it');
    }
    const response = await request(ctx, {
      method: 'GET', url: `${IAM}/Keys/${pair.keySid}`, headers: { Authorization: basic(admin.username, admin.password) },
    }, PROVIDER);
    if (response.status < 200 || response.status >= 300) {
      throw new TwilioGuidedRotationRequiredError('Twilio did not return the old API key for the management account');
    }
    const data = record(readJson<unknown>(response, PROVIDER));
    if (!data || data.sid !== pair.keySid || !Object.hasOwn(data, 'policy')) {
      throw new TwilioGuidedRotationRequiredError('Twilio did not describe the old API key permissions');
    }
    const policy = parsePolicy(data.policy);
    if (policy !== null) return policy;
    // A null policy is a Standard key or a Main key. Main keys can only be created in the Console, and the docs say
    // Standard keys are refused (error 20003) by the Keys endpoints that Main keys may call. A Standard key reads the
    // account's resources, so the proof above must have been a 2xx: a refusal cannot simply mean a wrong secret.
    if (proof.status < 200 || proof.status >= 300) {
      throw new TwilioGuidedRotationRequiredError('the old Twilio API key did not authenticate');
    }
    const probe = await request(ctx, {
      method: 'GET', url: `${IAM}/Keys?AccountSid=${pair.accountSid}&PageSize=1`, headers: { Authorization: basic(pair.keySid, oldValue) },
    }, PROVIDER);
    if (probe.status !== 401 && probe.status !== 403) {
      throw new TwilioGuidedRotationRequiredError('the old Twilio key may be a Main key, which only the Twilio Console can create');
    }
    return null;
  } catch (error) {
    if (error instanceof TwilioGuidedRotationRequiredError) throw error;
    throw new TwilioGuidedRotationRequiredError('Twilio key permissions could not be read');
  }
}

async function removeUnusable(sid: string, admin: Admin, ctx: ProviderContext): Promise<never> {
  let removed = false;
  try {
    const response = await request(ctx, {
      method: 'DELETE', url: `${IAM}/Keys/${sid}`, headers: { Authorization: basic(admin.username, admin.password) },
    }, PROVIDER);
    removed = response.status >= 200 && response.status < 300;
  } catch {
    removed = false;
  }
  if (removed) throw new Error('Twilio returned an unusable or differently scoped replacement key; it was deleted and no consumer was changed.');
  throw new ProviderMutationUncertainError(
    'Twilio returned an unusable or differently scoped replacement key and it could not be deleted; delete the unused keysentry API key in the Twilio Console.',
    false, sid);
}

export const twilioProvider: ProviderAdapter = {
  id: 'twilio',
  method: 'auto',

  async verify(value, ctx) {
    if (isIdentifier(value)) return { ok: true, identity: 'unverified' };
    const pair = findPair(value, ctx);
    const username = pair.kind === 'auth-token' ? pair.accountSid : pair.keySid;
    const account = pair.kind === 'auth-token' ? pair.accountSid : pair.accountSid ?? adminAccountSid(ctx);
    if (!username || !account) return { ok: true, identity: 'unverified' };
    return verifyRead(requestCtx(ctx), applicationsRequest(account, username, value), PROVIDER, (data) => {
      if (!Array.isArray(record(data)?.applications)) throw new Error('invalid');
      return pair.kind === 'auth-token' ? 'Twilio account' : 'Twilio API key';
    }, pair.kind === 'api-key');
  },

  async resolveKeyRef(value, ctx) {
    if (isIdentifier(value)) return null;
    const pair = findPair(value, ctx);
    const account = pair.accountSid ?? adminAccountSid(ctx);
    if (pair.kind !== 'api-key' || !pair.keySid || !account) return null;
    // Only return a SID once the pair is proven, so a mispaired sibling can never be revoked.
    const response = await request(requestCtx(ctx), applicationsRequest(account, pair.keySid, value), PROVIDER);
    return (response.status >= 200 && response.status < 300) || response.status === 403 ? pair.keySid : null;
  },

  async rotate(oldValue, ctx): Promise<RotationResult> {
    if (isIdentifier(oldValue)) throw new TwilioGuidedRotationRequiredError('this value is a Twilio identifier, not a secret');
    const pair = findPair(oldValue, ctx);
    if (pair.kind === 'auth-token') {
      throw new TwilioGuidedRotationRequiredError(
        'the account Auth Token is rotated by promoting a secondary token, which ends the old token for every consumer at once');
    }
    const admin = adminAuth(ctx);
    if (!pair.keySid) throw new TwilioGuidedRotationRequiredError('the API key SID paired with this secret was not found');
    if (pair.keySid === admin.username || oldValue === admin.password) {
      throw new TwilioGuidedRotationRequiredError('this is the management key keysentry uses');
    }
    if (!pair.accountSid || pair.accountSid !== admin.accountSid) {
      throw new TwilioGuidedRotationRequiredError('the service does not name the Twilio account of the management credential');
    }
    const rctx = requestCtx(ctx);
    const policy = await keyPolicy({ ...pair, keySid: pair.keySid, accountSid: pair.accountSid }, oldValue, admin, rctx);

    const body = new URLSearchParams({ AccountSid: admin.accountSid, FriendlyName: `keysentry-${new Date().toISOString()}` });
    if (policy) {
      body.set('KeyType', 'restricted');
      body.set('Policy', JSON.stringify(policy));
    }
    const response = await mutationRequest(rctx, {
      method: 'POST', url: `${IAM}/Keys`,
      headers: { Authorization: basic(admin.username, admin.password), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    }, PROVIDER);
    ensureOk(response, PROVIDER);
    let data: Row | undefined;
    try {
      data = record(response.json<unknown>());
    } catch {
      data = undefined;
    }
    const newSid = data?.sid;
    if (typeof newSid !== 'string' || !KEY_SID.test(newSid) || newSid === pair.keySid) {
      throw new ProviderMutationUncertainError('Twilio returned an invalid API key creation response; check the Twilio Console for an unused keysentry API key.');
    }
    const secret = data?.secret;
    if (typeof secret !== 'string' || secret.trim().length === 0 || secret === oldValue || isIdentifier(secret)
      || !samePolicy(policy, data?.policy)) {
      return removeUnusable(newSid, admin, rctx);
    }
    return {
      newValue: secret,
      oldKeyRef: pair.keySid,
      newKeyRef: newSid,
      oldRevoked: false,
      companions: Object.fromEntries(pair.keySidVars.map((name) => [name, newSid])),
    };
  },

  async rotateByRef() {
    // Without the consumer's variables the new SID cannot be delivered with its secret, and a null policy cannot
    // distinguish a Standard key from a Main key without authenticating as the old key.
    throw new TwilioGuidedRotationRequiredError('Twilio API keys cannot be replaced by reference');
  },

  async revoke(keyRef, ctx) {
    const admin = adminAuth(ctx);
    if (typeof keyRef !== 'string' || !KEY_SID.test(keyRef)) throw new Error('Twilio requires a valid API key SID');
    if (keyRef === admin.username) throw new Error('Twilio will not delete the management key keysentry uses');
    const response = await request(requestCtx(ctx), {
      method: 'DELETE', url: `${IAM}/Keys/${keyRef}`, headers: { Authorization: basic(admin.username, admin.password) },
    }, PROVIDER);
    ensureOk(response, PROVIDER);
  },

  async listKeys(ctx): Promise<ProviderKeyInfo[]> {
    const admin = adminAuth(ctx);
    const rctx = requestCtx(ctx);
    const keys: ProviderKeyInfo[] = [];
    const seenKeys = new Set<string>();
    const seenPages = new Set<string>();
    let url: string | null = `${IAM}/Keys?AccountSid=${admin.accountSid}&PageSize=100`;
    while (url !== null && !seenPages.has(url) && seenPages.size < MAX_PAGES) {
      seenPages.add(url);
      const response = await request(rctx, { method: 'GET', url, headers: { Authorization: basic(admin.username, admin.password) } }, PROVIDER);
      ensureOk(response, PROVIDER);
      const data = record(readJson<unknown>(response, PROVIDER));
      if (!data || !Array.isArray(data.keys)) throw new Error(`${PROVIDER} returned an invalid key list`);
      for (const entry of data.keys) {
        const row = record(entry);
        if (!row || typeof row.sid !== 'string' || !KEY_SID.test(row.sid)) throw new Error(`${PROVIDER} returned an invalid key list`);
        if (seenKeys.has(row.sid)) continue;
        seenKeys.add(row.sid);
        const name = safeIdentity(row.friendly_name, '', secrets(ctx));
        const created = typeof row.date_created === 'string' ? Date.parse(row.date_created) : Number.NaN;
        keys.push({
          keyRef: row.sid,
          ...(name ? { name } : {}),
          ...(Number.isNaN(created) ? {} : { createdAt: new Date(created).toISOString() }),
        });
      }
      const next = record(data.meta)?.next_page_url;
      if (next === null || next === undefined) break;
      // Never follow a page link off the IAM Keys list: it would receive the management credential.
      if (typeof next !== 'string' || !next.startsWith(`${IAM}/Keys?`)) throw new Error(`${PROVIDER} returned an invalid page link`);
      url = next;
    }
    return keys;
  },

  guidance() {
    return {
      url: 'https://console.twilio.com/us1/account/keys-credentials/api-keys',
      steps: [
        'For an API key: create a replacement of the same type (Standard, or Restricted with the same permissions). Main keys can only be created in the Twilio Console.',
        'Update the API key SID and its secret together in every consumer, redeploy, verify the affected API calls, then delete the old API key.',
        'For the account Auth Token: create a secondary Auth Token, update every consumer and redeploy, then promote it. Promotion deletes the old primary token at once, and webhook signatures use the primary token.',
      ],
    };
  },
};
