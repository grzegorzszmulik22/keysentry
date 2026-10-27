// Transport-free, immutable transitions. Attestation verification and token minting
// happen outside this module; only locally verified results enter next().
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { z } from 'zod';
import { canonicalJson, deviceKeyFromPrivate, signDetached, verifyDetached } from '../../security/index.js';
import type { DeviceKey } from '../../security/index.js';
import type { AttestationResult } from '../../types.js';
import { openAsBox, sealToBox } from './hpke.js';
import type { BoxKeyPair } from './hpke.js';

export const HANDSHAKE_SIGNATURE_PREFIX = 'keysentry-box-handshake:v1\n';
export const HANDSHAKE_TTL_MS = 600_000;
const MAX_BUNDLE_BYTES = 1024 * 1024;
const MAX_WIRE_BYTES = 2 * 1024 * 1024;

function base64url(bytes: number) {
  return z.string().regex(/^[A-Za-z0-9_-]+$/).length(Math.ceil(bytes * 8 / 6))
    .refine((s) => Buffer.from(s, 'base64url').length === bytes && Buffer.from(s, 'base64url').toString('base64url') === s);
}
const idSchema = base64url(16);
const hashSchema = base64url(32);
const timeSchema = z.string().datetime().refine((s) => Number.isFinite(Date.parse(s)) && new Date(s).toISOString() === s);
const common = {
  v: z.literal(1), id: idSchema, sessionId: idSchema,
  sentAt: timeSchema, expiresAt: timeSchema, sig: base64url(64),
};
const publicKeys = { boxPublicKey: hashSchema, boxSigningPublicKey: hashSchema };
const tokenSchema = z.string().min(1).max(64 * 1024);
const bundleSchema = z.string().min(71).max(Math.ceil((MAX_BUNDLE_BYTES + 53) * 8 / 6))
  .regex(/^[A-Za-z0-9_-]+$/).refine((s) => Buffer.from(s, 'base64url').toString('base64url') === s);

export const boxHelloSchema = z.object({ ...common, type: z.literal('box-hello'), seq: z.literal(0),
  previous: z.null(), ...publicKeys, attestationToken: tokenSchema }).strict();
export const cliChallengeSchema = z.object({ ...common, type: z.literal('cli-challenge'), seq: z.literal(1),
  previous: hashSchema, boxKeyHash: hashSchema, challenge: hashSchema }).strict();
export const boxAttestSchema = z.object({ ...common, type: z.literal('box-attest'), seq: z.literal(2),
  previous: hashSchema, ...publicKeys, boxKeyHash: hashSchema, challenge: hashSchema, attestationToken: tokenSchema }).strict();
export const tokenBundleSchema = z.object({ ...common, type: z.literal('token-bundle'), seq: z.literal(3),
  previous: hashSchema, boxKeyHash: hashSchema, bundle: bundleSchema }).strict();
export const boxAckSchema = z.object({ ...common, type: z.literal('box-ack'), seq: z.literal(4),
  previous: hashSchema, boxKeyHash: hashSchema, bundleHash: hashSchema }).strict();

export const handshakeMessageSchema = z.discriminatedUnion('type', [
  boxHelloSchema, cliChallengeSchema, boxAttestSchema, tokenBundleSchema, boxAckSchema,
]).refine((m) => Date.parse(m.expiresAt) - Date.parse(m.sentAt) === HANDSHAKE_TTL_MS);

export type BoxHello = z.infer<typeof boxHelloSchema>;
export type CliChallenge = z.infer<typeof cliChallengeSchema>;
export type BoxAttest = z.infer<typeof boxAttestSchema>;
export type TokenBundle = z.infer<typeof tokenBundleSchema>;
export type BoxAck = z.infer<typeof boxAckSchema>;
export type HandshakeMessage = z.infer<typeof handshakeMessageSchema>;
type WithoutSignature<T> = T extends unknown ? Omit<T, 'sig'> : never;
export type UnsignedHandshakeMessage = WithoutSignature<HandshakeMessage>;

function hash(data: Buffer | string): string { return createHash('sha256').update(data).digest('base64url'); }
function fail(detail: string): never { throw new Error(`Box handshake: ${detail}.`); }

/** Strict JSON input only; schema failures never include the untrusted payload. */
export function parseHandshakeMessage(input: unknown): HandshakeMessage {
  let value = input;
  if (typeof input === 'string') {
    if (Buffer.byteLength(input) > MAX_WIRE_BYTES) fail('invalid message size');
    try { value = JSON.parse(input); } catch { fail('invalid message'); }
  }
  const parsed = handshakeMessageSchema.safeParse(value);
  if (!parsed.success) fail('invalid message');
  if (typeof input === 'string' && canonicalJson(parsed.data) !== input) fail('message must use canonical JSON');
  return parsed.data;
}

export function serializeHandshakeMessage(message: HandshakeMessage): string {
  return canonicalJson(parseHandshakeMessage(message));
}

export function signHandshakeMessage(message: UnsignedHandshakeMessage, key: DeviceKey): HandshakeMessage {
  const body = parseHandshakeMessage({ ...message, sig: Buffer.alloc(64).toString('base64url') });
  const { sig: _sig, ...unsigned } = body;
  const data = Buffer.from(HANDSHAKE_SIGNATURE_PREFIX + canonicalJson(unsigned));
  try {
    const sig = signDetached(key.privateKeyDer, data);
    if (!verifyDetached(key.publicKeyDer, data, sig)) fail('signing key does not match');
    return { ...unsigned, sig: sig.toString('base64url') } as HandshakeMessage;
  } catch { fail('could not sign message'); }
}

export function verifyHandshakeMessage(input: unknown, publicKeyDer: Buffer): boolean {
  try {
    const { sig, ...body } = parseHandshakeMessage(input);
    return verifyDetached(publicKeyDer, Buffer.from(HANDSHAKE_SIGNATURE_PREFIX + canonicalJson(body)), Buffer.from(sig, 'base64url'));
  } catch { return false; }
}

/** Attestation binds X25519 || Ed25519, both raw 32-byte public keys, in that order. */
export function boxKeyBindingNonce(x25519Public: Buffer, ed25519Public: Buffer): string {
  if (!Buffer.isBuffer(x25519Public) || x25519Public.length !== 32 || !Buffer.isBuffer(ed25519Public) || ed25519Public.length !== 32) {
    throw new TypeError('Box public keys must each be 32 bytes.');
  }
  return hash(Buffer.concat([x25519Public, ed25519Public]));
}

export function handshakeAttestationNonces(message: BoxHello | BoxAttest): string[] {
  const m = parseHandshakeMessage(message);
  if (m.type !== 'box-hello' && m.type !== 'box-attest') fail('message has no attestation');
  const binding = boxKeyBindingNonce(Buffer.from(m.boxPublicKey, 'base64url'), Buffer.from(m.boxSigningPublicKey, 'base64url'));
  return m.type === 'box-hello' ? [binding] : [binding, m.challenge];
}

/** The hybrid envelope's HKDF and AAD context includes protocol, both keys and session. */
export function handshakeSealInfo(sessionId: string, boxKeyHash: string): string {
  if (!idSchema.safeParse(sessionId).success || !hashSchema.safeParse(boxKeyHash).success) fail('invalid encryption context');
  return `keysentry-box-handshake:v1|${boxKeyHash}|${sessionId}`;
}

export interface CliHandshakeOptions {
  deviceKey: DeviceKey;
  seenIds?: readonly string[];
  seenSessionIds?: readonly string[];
}
export interface BoxHandshakeOptions {
  devicePublicKeyDer: Buffer;
  signingKey: DeviceKey;
  boxKey: BoxKeyPair;
  sessionId?: string;
  seenIds?: readonly string[];
  seenSessionIds?: readonly string[];
}
export interface HandshakeInput {
  now: Date;
  message?: unknown;
  /** Token minted by the local box for the next outgoing box message. */
  attestationToken?: string;
  /** Local verifier result for exactly message.attestationToken, never a relay-provided value. */
  verifiedAttestation?: AttestationResult;
  /** In-memory CLI plaintext, used only after the second attestation is checked. */
  plaintext?: Buffer;
  /** Optional explicit fresh entropy for callers that manage their own randomness. */
  id?: string;
  challenge?: string;
}
export type HandshakeState = 'ready' | 'awaiting-hello' | 'awaiting-challenge' | 'awaiting-attestation'
  | 'awaiting-bundle' | 'awaiting-ack' | 'complete';
export interface Handshake {
  readonly role: 'cli' | 'box';
  readonly state: HandshakeState;
  readonly sessionId: string | null;
  readonly seenIds: readonly string[];
  readonly seenSessionIds: readonly string[];
  /** Retain the returned handshake. This object is unchanged on success and failure. */
  next(input: HandshakeInput): HandshakeTransition;
}
export interface HandshakeTransition {
  handshake: Handshake;
  message: HandshakeMessage | null;
  /** Box only: caller owns disposal after sealing at rest; never kept in handshake state. */
  plaintext?: Buffer;
}

interface Config {
  role: 'cli' | 'box';
  signer: DeviceKey;
  devicePublicKeyDer: Buffer;
  boxKey?: BoxKeyPair;
  signingPublicRaw?: string;
}
interface Context {
  stage: HandshakeState;
  sessionId: string | null;
  previous: string | null;
  seenIds: readonly string[];
  seenSessionIds: readonly string[];
  deadline?: number;
  boxPublicKey?: string;
  boxSigningPublicKey?: string;
  boxKeyHash?: string;
  challenge?: string;
  bundleHash?: string;
}

function signingPublicRaw(publicKeyDer: Buffer): string {
  try {
    const key = createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') fail('signing key must be Ed25519');
    const x = key.export({ format: 'jwk' }).x;
    if (!hashSchema.safeParse(x).success) fail('invalid signing key');
    return x!;
  } catch { fail('invalid signing key'); }
}
function signingPublicDer(raw: string): Buffer {
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw }, format: 'jwk' }).export({ format: 'der', type: 'spki' });
}

export function createHandshake(role: 'cli', options: CliHandshakeOptions): Handshake;
export function createHandshake(role: 'box', options: BoxHandshakeOptions): Handshake;
export function createHandshake(role: 'cli' | 'box', options: CliHandshakeOptions | BoxHandshakeOptions): Handshake {
  const signer = deviceKeyFromPrivate(('deviceKey' in options ? options.deviceKey : options.signingKey).privateKeyDer);
  const devicePublicKeyDer = Buffer.from('deviceKey' in options ? signer.publicKeyDer : options.devicePublicKeyDer);
  signingPublicRaw(devicePublicKeyDer);
  const context: Context = { stage: role === 'cli' ? 'awaiting-hello' : 'ready', sessionId: null, previous: null,
    seenIds: Object.freeze([...(options.seenIds ?? [])]), seenSessionIds: Object.freeze([...(options.seenSessionIds ?? [])]) };
  const config: Config = { role, signer, devicePublicKeyDer };
  if (role === 'box') {
    if (!('boxKey' in options)) fail('box keys are required');
    const raw = options.boxKey.publicKeyRaw;
    try {
      if (options.boxKey.privateKey.asymmetricKeyType !== 'x25519' || options.boxKey.privateKey.type !== 'private') throw new Error();
      const derived = createPublicKey(options.boxKey.privateKey).export({ format: 'jwk' }).x;
      if (!Buffer.isBuffer(raw) || raw.length !== 32 || raw.toString('base64url') !== derived) throw new Error();
    } catch { fail('box key pair does not match'); }
    config.boxKey = { publicKeyRaw: Buffer.from(raw), privateKey: options.boxKey.privateKey };
    config.signingPublicRaw = signingPublicRaw(signer.publicKeyDer);
    context.sessionId = options.sessionId ?? randomBytes(16).toString('base64url');
    if (!idSchema.safeParse(context.sessionId).success) fail('invalid session id');
    if (context.seenSessionIds.includes(context.sessionId)) fail('replayed session');
    context.boxPublicKey = raw.toString('base64url');
    context.boxSigningPublicKey = config.signingPublicRaw;
    context.boxKeyHash = boxKeyBindingNonce(raw, Buffer.from(config.signingPublicRaw, 'base64url'));
  } else if (role !== 'cli' || !('deviceKey' in options)) fail('invalid handshake role');
  return machine(config, context);
}

function checkEvidence(result: AttestationResult | undefined, nonces: string[]): void {
  if (!result?.ok || !result.claims) fail('verified attestation is required');
  const actual = result.claims.eat_nonce;
  const list = typeof actual === 'string' ? [actual] : actual;
  if (!Array.isArray(list) || list.length !== nonces.length || list.some((n, i) => n !== nonces[i])) fail('attestation nonces do not match');
  if (result.boxKeyHash !== nonces[0]) fail('attestation key binding does not match');
}

function machine(config: Config, context: Context): Handshake {
  return Object.freeze({ role: config.role, state: context.stage, sessionId: context.sessionId,
    seenIds: context.seenIds, seenSessionIds: context.seenSessionIds,
    next: (input: HandshakeInput) => advance(config, context, input) });
}

function advance(config: Config, current: Context, input: HandshakeInput): HandshakeTransition {
  const millis = input.now instanceof Date ? input.now.getTime() : NaN;
  if (!Number.isFinite(millis)) fail('invalid clock');
  if (current.stage === 'complete') fail('handshake is complete');
  const c: Context = { ...current };
  let incoming: HandshakeMessage | undefined;
  if (current.stage !== 'ready') {
    incoming = parseHandshakeMessage(input.message);
    if (c.seenIds.includes(incoming.id)) fail('replayed message');
    if (millis >= Date.parse(incoming.expiresAt)) fail('message expired');
    if (millis < Date.parse(incoming.sentAt)) fail('message is from the future');
    if (c.deadline !== undefined && millis >= c.deadline) fail('session expired');
    const expected = { 'awaiting-hello': 0, 'awaiting-challenge': 1, 'awaiting-attestation': 2, 'awaiting-bundle': 3, 'awaiting-ack': 4 };
    if (incoming.seq !== expected[current.stage]) fail('message is out of order');
    if (c.sessionId !== null && incoming.sessionId !== c.sessionId) fail('session does not match');
    if (incoming.previous !== c.previous) fail('transcript does not match');
    const verifier = config.role === 'box' ? config.devicePublicKeyDer
      : signingPublicDer(incoming.type === 'box-hello' ? incoming.boxSigningPublicKey : c.boxSigningPublicKey!);
    if (!verifyHandshakeMessage(incoming, verifier)) fail('message signature does not match');
    if (incoming.type !== 'box-hello' && incoming.boxKeyHash !== c.boxKeyHash) fail('box key binding does not match');
    c.seenIds = Object.freeze([...c.seenIds, incoming.id]);
    c.previous = hash(serializeHandshakeMessage(incoming));
  } else if (input.message !== undefined) fail('message is out of order');

  function emit(body: Record<string, unknown>, stage: HandshakeState): HandshakeTransition {
    const id = input.id ?? randomBytes(16).toString('base64url');
    if (c.seenIds.includes(id)) fail('replayed message id');
    const message = signHandshakeMessage({ ...body, v: 1, id, sessionId: c.sessionId!,
      previous: c.previous, sentAt: input.now.toISOString(), expiresAt: new Date(millis + HANDSHAKE_TTL_MS).toISOString() } as UnsignedHandshakeMessage, config.signer);
    c.stage = stage;
    c.previous = hash(serializeHandshakeMessage(message));
    c.seenIds = Object.freeze([...c.seenIds, id]);
    return { handshake: machine(config, c), message };
  }

  if (current.stage === 'ready') {
    c.deadline = millis + HANDSHAKE_TTL_MS;
    c.seenSessionIds = Object.freeze([...c.seenSessionIds, c.sessionId!]);
    return emit({ type: 'box-hello', seq: 0, boxPublicKey: c.boxPublicKey!, boxSigningPublicKey: c.boxSigningPublicKey!,
      attestationToken: input.attestationToken }, 'awaiting-challenge');
  }
  if (incoming?.type === 'box-hello') {
    if (c.seenSessionIds.includes(incoming.sessionId)) fail('replayed session');
    // This hello is provisional: a fresh challenge is safe to send before verifying
    // the box. Only the later two-nonce box-attest can authorize a token bundle.
    c.sessionId = incoming.sessionId;
    c.deadline = Date.parse(incoming.expiresAt);
    c.seenSessionIds = Object.freeze([...c.seenSessionIds, c.sessionId]);
    c.boxPublicKey = incoming.boxPublicKey;
    c.boxSigningPublicKey = incoming.boxSigningPublicKey;
    c.boxKeyHash = handshakeAttestationNonces(incoming)[0]!;
    c.challenge = input.challenge ?? randomBytes(32).toString('base64url');
    return emit({ type: 'cli-challenge', seq: 1, boxKeyHash: c.boxKeyHash, challenge: c.challenge }, 'awaiting-attestation');
  }
  if (incoming?.type === 'cli-challenge') {
    c.challenge = incoming.challenge;
    return emit({ type: 'box-attest', seq: 2, boxPublicKey: c.boxPublicKey!, boxSigningPublicKey: c.boxSigningPublicKey!,
      boxKeyHash: c.boxKeyHash!, challenge: c.challenge, attestationToken: input.attestationToken }, 'awaiting-bundle');
  }
  if (incoming?.type === 'box-attest') {
    if (incoming.boxPublicKey !== c.boxPublicKey || incoming.boxSigningPublicKey !== c.boxSigningPublicKey) fail('box public key changed');
    if (incoming.challenge !== c.challenge) fail('challenge does not match');
    checkEvidence(input.verifiedAttestation, [c.boxKeyHash!, c.challenge!]);
    if (!Buffer.isBuffer(input.plaintext) || input.plaintext.length > MAX_BUNDLE_BYTES) fail('invalid token bundle');
    const sealed = sealToBox(Buffer.from(c.boxPublicKey!, 'base64url'), input.plaintext, handshakeSealInfo(c.sessionId!, c.boxKeyHash!));
    c.bundleHash = hash(sealed);
    return emit({ type: 'token-bundle', seq: 3, boxKeyHash: c.boxKeyHash!, bundle: sealed.toString('base64url') }, 'awaiting-ack');
  }
  if (incoming?.type === 'token-bundle') {
    const sealed = Buffer.from(incoming.bundle, 'base64url');
    const opened = openAsBox(config.boxKey!.privateKey, sealed, handshakeSealInfo(c.sessionId!, c.boxKeyHash!));
    try {
      const transition = emit({ type: 'box-ack', seq: 4, boxKeyHash: c.boxKeyHash!, bundleHash: hash(sealed) }, 'complete');
      return { ...transition, plaintext: opened };
    } catch (error) { opened.fill(0); throw error; }
  }
  if (incoming?.type === 'box-ack') {
    if (incoming.bundleHash !== c.bundleHash) fail('acknowledgement bundle does not match');
    c.stage = 'complete';
    return { handshake: machine(config, c), message: null };
  }
  return fail('message is out of order');
}
