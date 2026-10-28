import { randomBytes } from 'node:crypto';
import type { PasskeyCredential } from '../../types.js';
import { verifyAssertion } from '../../approvals/webauthn/index.js';

export interface PasskeyStore {
  list(): Promise<PasskeyCredential[]>;
  add(credential: PasskeyCredential): Promise<void>;
  update(credential: PasskeyCredential): Promise<void>;
}

export interface PasskeyRequestOptions {
  challenge: string;
  rpId: string;
  userVerification: 'required';
  timeout: number;
  allowCredentials: { id: string; type: 'public-key' }[];
}
export class PasskeyGateError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = 'PasskeyGateError';
  }
}

const LIFETIME_MS = 120_000;
const MAX_PENDING = 100;
const FRESH_PROOF = 'Use a fresh passkey to continue.';
export const REGISTER_IN_TERMINAL = 'Register a passkey with keysentry passkey register in your terminal, then reload this page.';
interface PendingBase { session: string; expires: number }
type Pending = PendingBase & { route: string; digest: string };

function reject(): never { throw new PasskeyGateError(403, FRESH_PROOF); }
function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return reject();
  return value as Record<string, unknown>;
}
function decode(value: unknown, maxBytes: number): Buffer {
  if (typeof value !== 'string' || !value || value.length > Math.ceil(maxBytes * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) return reject();
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length > maxBytes || decoded.toString('base64url') !== value) return reject();
  return decoded;
}
function parseJson(bytes: Buffer): unknown {
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { return reject(); }
}
function wire(value: unknown): { id: string; response: Record<string, unknown>; clientData: Buffer; challenge: string } {
  const credential = object(value);
  if (credential.type !== 'public-key') return reject();
  const id = decode(credential.id, 1023).toString('base64url');
  if (decode(credential.rawId, 1023).toString('base64url') !== id) return reject();
  const response = object(credential.response);
  const clientData = decode(response.clientDataJSON, 8192);
  const challenge = decode(object(parseJson(clientData)).challenge, 32);
  if (challenge.length !== 32) return reject();
  return { id, response, clientData, challenge: challenge.toString('base64url') };
}

function teamOrigin(origin: string, rpId: string): boolean {
  try {
    const url = new URL(origin);
    return url.protocol === 'https:' && url.origin === origin && url.hostname === rpId && /^[a-z0-9.-]+$/.test(rpId) && !/^[0-9.]+$/.test(rpId);
  } catch { return false; }
}

/**
 * Authorize actions with passkeys registered through the human terminal command. Team mode passes the public
 * HTTPS origin and its RP ID, and a store scoped to the signed-in member on every call.
 */
export function createPasskeyGate(opts: { passkeys: PasskeyStore; origin: string; rpId?: string; noPasskeyMessage?: string; now?: () => number }) {
  if (opts.rpId === undefined) {
    if (!/^http:\/\/localhost:[1-9][0-9]{0,4}$/.test(opts.origin) || Number(opts.origin.split(':').at(-1)) > 65535) {
      throw new Error('Dashboard origin must be http://localhost with a port.');
    }
  } else if (!teamOrigin(opts.origin, opts.rpId)) throw new Error('Team dashboard origin must be https on its RP ID host.');
  const rpId = opts.rpId ?? 'localhost';
  const noPasskey = opts.noPasskeyMessage ?? REGISTER_IN_TERMINAL;
  const now = opts.now ?? Date.now;
  const pending = new Map<string, Pending>();
  let queue: Promise<unknown> = Promise.resolve();
  function serial<T>(fn: () => Promise<T>): Promise<T> {
    const result = queue.then(fn, fn);
    queue = result.catch(() => undefined);
    return result;
  }
  function prune(): void {
    const time = now();
    for (const [key, entry] of pending) if (time >= entry.expires) pending.delete(key);
  }
  function create(entry: Omit<Pending, 'expires'>): string {
    prune();
    if (pending.size >= MAX_PENDING) throw new PasskeyGateError(429, 'Complete a pending passkey prompt or try again in two minutes.');
    const challenge = randomBytes(32).toString('base64url');
    pending.set(challenge, { ...entry, expires: now() + LIFETIME_MS });
    return challenge;
  }
  function take(challenge: string, session: string): Pending {
    prune();
    const entry = pending.get(challenge);
    pending.delete(challenge);
    if (!entry || entry.session !== session) return reject();
    return entry;
  }
  function usable(credential: PasskeyCredential): boolean {
    if (opts.rpId !== undefined) return credential.rpId === rpId && Array.isArray(credential.origins) && credential.origins.includes(opts.origin);
    return credential.rpId === 'localhost' && Array.isArray(credential.origins)
      && (credential.origins.includes(opts.origin) || credential.origins.includes('http://localhost'));
  }
  function checkSession(session: string): void {
    if (typeof session !== 'string' || !session || session.length > 256) throw new PasskeyGateError(400, 'Open keysentry again from your terminal.');
  }

  return {
    challenge(session: string, route: string, bodyDigest: string, scoped?: PasskeyStore): Promise<PasskeyRequestOptions> {
      const store = scoped ?? opts.passkeys;
      return serial(async () => {
        checkSession(session);
        if (typeof route !== 'string' || route.length > 200 || !/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(route)
          || typeof bodyDigest !== 'string' || !/^[a-f0-9]{64}$/.test(bodyDigest)) {
          throw new PasskeyGateError(400, 'Choose an action and try again.');
        }
        const credentials = (await store.list()).filter(usable);
        if (credentials.length === 0) throw new PasskeyGateError(403, noPasskey);
        return {
          challenge: create({ session, route, digest: bodyDigest }),
          rpId, userVerification: 'required', timeout: LIFETIME_MS,
          allowCredentials: credentials.map(c => ({ id: c.id, type: 'public-key' })),
        };
      });
    },

    /** Resolves with the id of the credential that signed the assertion. */
    verify(session: string, route: string, bodyDigest: string, header: string | undefined, scoped?: PasskeyStore): Promise<string> {
      const store = scoped ?? opts.passkeys;
      return serial(async () => {
        // Consume any submitted challenge before an awaited storage operation can fail.
        // Empty storage still takes precedence over a missing or invalid proof.
        let assertion: ReturnType<typeof wire> | undefined;
        let entry: Pending | undefined;
        let invalid: unknown;
        try {
          assertion = wire(parseJson(decode(header, 24_576)));
          entry = take(assertion.challenge, session);
        } catch (error) { invalid = error; }
        const credentials = await store.list();
        if (credentials.length === 0) throw new PasskeyGateError(403, noPasskey);
        if (invalid) throw invalid;
        if (!assertion || !entry) return reject();
        if (entry.route !== route || entry.digest !== bodyDigest) return reject();
        const credential = credentials.find(c => c.id === assertion.id && usable(c));
        if (!credential || now() >= entry.expires) return reject();
        let result: ReturnType<typeof verifyAssertion>;
        try {
          result = verifyAssertion({
            // A portless localhost origin marks a credential enrolled for this local RP.
            // Only the current exact origin is accepted from clientDataJSON.
            credential: { ...credential, origins: [opts.origin] },
            expectedChallenge: Buffer.from(assertion.challenge, 'base64url'), expectedOrigins: [opts.origin],
            requireUserVerification: true, clientDataJSON: assertion.clientData,
            authenticatorData: decode(assertion.response.authenticatorData, 65_536), signature: decode(assertion.response.signature, 1024),
          });
        } catch { return reject(); }
        if (result.cloneWarning || now() >= entry.expires) return reject();
        await store.update({ ...credential, origins: [...credential.origins], signCount: result.signCount });
        if (now() >= entry.expires) return reject();
        return credential.id;
      });
    },
  };
}
