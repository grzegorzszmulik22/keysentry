import { randomBytes } from 'node:crypto';
import type { PasskeyCredential } from '../../types.js';
import { verifyAssertion, verifyRegistration } from '../../approvals/webauthn/index.js';

export interface PasskeyStore {
  list(): Promise<PasskeyCredential[]>;
  add(credential: PasskeyCredential): Promise<void>;
  update(credential: PasskeyCredential): Promise<void>;
}

export interface PasskeyRequestOptions {
  challenge: string;
  rpId: 'localhost';
  userVerification: 'required';
  timeout: number;
  allowCredentials: { id: string; type: 'public-key' }[];
}
export interface PasskeyRegistrationOptions {
  challenge: string;
  rp: { id: 'localhost'; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: 'public-key'; alg: -7 | -8 | -257 }[];
  authenticatorSelection: { userVerification: 'required'; residentKey: 'preferred' };
  timeout: number;
  attestation: 'none';
  excludeCredentials: { id: string; type: 'public-key' }[];
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
interface PendingBase { session: string; expires: number }
type Pending = PendingBase & ({ kind: 'assertion'; route: string; digest: string } | { kind: 'registration'; credentialIds: string[] });

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

/** Enrollment options consume the proof previously verified for passkey/register/options. */
export function createPasskeyGate(opts: { passkeys: PasskeyStore; origin: string; now?: () => number }) {
  if (!/^http:\/\/localhost:[1-9][0-9]{0,4}$/.test(opts.origin) || Number(opts.origin.split(':').at(-1)) > 65535) {
    throw new Error('Dashboard origin must be http://localhost with a port.');
  }
  const now = opts.now ?? Date.now;
  const pending = new Map<string, Pending>();
  const enrollmentGrants = new Map<string, number>();
  const userId = randomBytes(32).toString('base64url');
  let queue: Promise<unknown> = Promise.resolve();
  function serial<T>(fn: () => Promise<T>): Promise<T> {
    const result = queue.then(fn, fn);
    queue = result.catch(() => undefined);
    return result;
  }
  function prune(): void {
    const time = now();
    for (const [key, entry] of pending) if (time >= entry.expires) pending.delete(key);
    for (const [session, expires] of enrollmentGrants) if (time >= expires) enrollmentGrants.delete(session);
  }
  function create(entry: Omit<PendingBase, 'expires'> & ({ kind: 'assertion'; route: string; digest: string } | { kind: 'registration'; credentialIds: string[] })): string {
    prune();
    if (pending.size + enrollmentGrants.size >= MAX_PENDING) throw new PasskeyGateError(429, 'Complete a pending passkey prompt or try again in two minutes.');
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
    return credential.rpId === 'localhost' && Array.isArray(credential.origins)
      && (credential.origins.includes(opts.origin) || credential.origins.includes('http://localhost'));
  }
  function credentialIds(credentials: PasskeyCredential[]): string[] { return credentials.map(c => c.id).sort(); }
  function checkSession(session: string): void {
    if (typeof session !== 'string' || !session || session.length > 256) throw new PasskeyGateError(400, 'Open keysentry again from your terminal.');
  }

  return {
    challenge(session: string, route: string, bodyDigest: string): Promise<PasskeyRequestOptions> {
      return serial(async () => {
        checkSession(session);
        if (typeof route !== 'string' || route.length > 200 || !/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(route)
          || typeof bodyDigest !== 'string' || !/^[a-f0-9]{64}$/.test(bodyDigest)) {
          throw new PasskeyGateError(400, 'Choose an action and try again.');
        }
        const credentials = (await opts.passkeys.list()).filter(usable);
        if (credentials.length === 0) throw new PasskeyGateError(403, 'Register a passkey before making a change.');
        return {
          challenge: create({ kind: 'assertion', session, route, digest: bodyDigest }),
          rpId: 'localhost', userVerification: 'required', timeout: LIFETIME_MS,
          allowCredentials: credentials.map(c => ({ id: c.id, type: 'public-key' })),
        };
      });
    },

    verify(session: string, route: string, bodyDigest: string, header: string | undefined): Promise<void> {
      return serial(async () => {
        const assertion = wire(parseJson(decode(header, 24_576)));
        const entry = take(assertion.challenge, session);
        if (entry.kind !== 'assertion' || entry.route !== route || entry.digest !== bodyDigest) return reject();
        const credential = (await opts.passkeys.list()).find(c => c.id === assertion.id && usable(c));
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
        await opts.passkeys.update({ ...credential, origins: [...credential.origins], signCount: result.signCount });
        if (now() >= entry.expires) return reject();
        if (route === 'passkey/register/options') enrollmentGrants.set(session, entry.expires);
      });
    },

    registrationOptions(session: string): Promise<PasskeyRegistrationOptions> {
      return serial(async () => {
        checkSession(session);
        const credentials = await opts.passkeys.list();
        prune();
        const authorized = enrollmentGrants.has(session);
        enrollmentGrants.delete(session);
        if (credentials.length > 0 && !authorized) return reject();
        for (const [key, entry] of pending) if (entry.kind === 'registration' && entry.session === session) pending.delete(key);
        return {
          challenge: create({ kind: 'registration', session, credentialIds: credentialIds(credentials) }),
          rp: { id: 'localhost', name: 'keysentry' },
          user: { id: userId, name: 'keysentry-local', displayName: 'keysentry local dashboard' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }, { type: 'public-key', alg: -257 }],
          authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
          timeout: LIFETIME_MS, attestation: 'none',
          excludeCredentials: credentials.filter(c => c.rpId === 'localhost').map(c => ({ id: c.id, type: 'public-key' })),
        };
      });
    },

    registrationFinish(session: string, body: unknown): Promise<void> {
      return serial(async () => {
        const registration = wire(body);
        const entry = take(registration.challenge, session);
        if (entry.kind !== 'registration') return reject();
        const credentials = await opts.passkeys.list();
        if (now() >= entry.expires || JSON.stringify(entry.credentialIds) !== JSON.stringify(credentialIds(credentials))) return reject();
        let credential: PasskeyCredential;
        try {
          credential = verifyRegistration({
            attestationObject: decode(registration.response.attestationObject, 65_536), clientDataJSON: registration.clientData,
            expectedChallenge: Buffer.from(registration.challenge, 'base64url'), expectedOrigins: [opts.origin],
            rpId: 'localhost', requireUserVerification: true,
          });
        } catch { return reject(); }
        if (credential.id !== registration.id || now() >= entry.expires) return reject();
        if (credentials.some(c => c.id === credential.id)) throw new PasskeyGateError(409, 'This passkey is already registered.');
        await opts.passkeys.add({ ...credential, origins: [opts.origin, 'http://localhost'] });
      });
    },
  };
}
