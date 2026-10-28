import { createPublicKey } from 'node:crypto';
import { z } from 'zod';
import { MAX_BOX_BUNDLE_BYTES } from '../seal/index.js';
import type { BoxSealMode } from '../../types.js';

/**
 * The variables `keysentry watcher setup` produces for a self-hosted watcher. The box receives the same set inside
 * the device-signed bundle, so it runs the same deployed-watcher code with them held in memory, never in its environment.
 */
export const BOX_DEPLOYMENT_VARIABLES = ['KEYSENTRY_WATCHER_KEY', 'KEYSENTRY_WATCHER_CONFIG', 'KEYSENTRY_STATE_KEY',
  'KEYSENTRY_VAULT_PASSPHRASE', 'KEYSENTRY_WATCHER_VAULT'] as const;
export type BoxDeploymentVariable = typeof BOX_DEPLOYMENT_VARIABLES[number];

export class BoxPayloadError extends Error {
  constructor(message = 'The box received a token bundle it cannot use.') { super(message); this.name = 'BoxPayloadError'; }
}

const BOX_ID = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** An Ed25519 public key in SPKI DER. An X25519 key has the same length and must not pass. */
export function isEd25519Spki(der: Buffer): boolean {
  try { return createPublicKey({ key: der, format: 'der', type: 'spki' }).asymmetricKeyType === 'ed25519'; } catch { return false; }
}
const base64 = (min: number, max: number) => z.string().max(Math.ceil(max / 3) * 4).refine(value => {
  const bytes = Buffer.from(value, 'base64');
  return bytes.length >= min && bytes.length <= max && bytes.toString('base64') === value;
}, 'invalid base64');
const settingsSchema = z.object({
  mode: z.enum(['standard', 'byo-kms', 'unlock-on-restart']),
  audience: z.string().regex(/^\/\/iam\.googleapis\.com\/projects\/\d+\/locations\/global\/workloadIdentityPools\/[A-Za-z0-9_-]+\/providers\/[A-Za-z0-9_-]+$/),
  keyName: z.string().regex(/^projects\/[A-Za-z0-9_-]+\/locations\/[A-Za-z0-9_-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+$/),
  // Ed25519 SPKI DER is 44 bytes. These devices may open later sessions (unlock, replacing the tokens).
  deviceKeys: z.array(base64(44, 44).refine(key => isEd25519Spki(Buffer.from(key, 'base64')), 'not an Ed25519 key')).min(1).max(8)
    .refine(keys => new Set(keys).size === keys.length, 'duplicate device key'),
}).strict();
const channelSchema = z.object({
  id: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/),
  kind: z.enum(['telegram', 'discord', 'slack', 'ntfy', 'webhook', 'resend', 'smtp']),
  server: z.string().max(2048).optional(), from: z.string().max(320).optional(), to: z.array(z.string().max(320)).max(16).optional(),
  host: z.string().max(253).optional(), port: z.union([z.literal(465), z.literal(587)]).optional(),
}).strict();
const noticeSchema = z.object({
  channels: z.array(channelSchema).max(16),
  secrets: z.array(z.object({ name: z.string().regex(/^notify\/[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\/[a-zA-Z]{1,32}$/), value: z.string().min(1).max(4096) }).strict()).max(64),
}).strict();
const deploymentSchema = z.object(Object.fromEntries(BOX_DEPLOYMENT_VARIABLES.map(name => [name, z.string().min(1).max(MAX_BOX_BUNDLE_BYTES)])) as
  Record<BoxDeploymentVariable, z.ZodString>).strict();
const enrollSchema = z.object({ v: z.literal(1), kind: z.literal('enroll'), boxId: z.string().regex(BOX_ID), settings: settingsSchema,
  deployment: deploymentSchema, notice: noticeSchema, shareB: base64(32, 32).optional() }).strict();
const unlockSchema = z.object({ v: z.literal(1), kind: z.literal('unlock'), boxId: z.string().regex(BOX_ID), shareB: base64(32, 32) }).strict();
const noticeRecordSchema = z.object({ v: z.literal(1), kind: z.literal('notice'), boxId: z.string().regex(BOX_ID), settings: settingsSchema,
  notice: noticeSchema }).strict();
const payloadSchema = z.discriminatedUnion('kind', [enrollSchema, unlockSchema, noticeRecordSchema]);

export interface BoxSettings { mode: BoxSealMode; audience: string; keyName: string; deviceKeys: string[] }
export type BoxNoticeKit = z.infer<typeof noticeSchema>;
export type BoxEnrollPayload = z.infer<typeof enrollSchema>;
export type BoxUnlockPayload = z.infer<typeof unlockSchema>;
/** Sealed beside the tokens in unlock-on-restart mode, under KMS alone, so a locked box can send its one notice. */
export type BoxNoticeRecord = z.infer<typeof noticeRecordSchema>;
export type BoxPayload = z.infer<typeof payloadSchema>;

export function isBoxId(value: unknown): value is string { return typeof value === 'string' && BOX_ID.test(value); }

/** Caller owns the returned buffer and clears it after use. */
export function encodeBoxPayload(payload: BoxPayload): Buffer {
  const parsed = payloadSchema.safeParse(payload);
  if (!parsed.success) throw new BoxPayloadError('The token bundle is incomplete or invalid.');
  // The sealed copy of an unlock-on-restart record leaves the share out on purpose; only the other modes forbid one.
  if (parsed.data.kind === 'enroll' && parsed.data.shareB !== undefined && parsed.data.settings.mode !== 'unlock-on-restart') {
    throw new BoxPayloadError('A device share is used only with unlock-on-restart.');
  }
  const bytes = Buffer.from(JSON.stringify(parsed.data), 'utf8');
  if (bytes.length > MAX_BOX_BUNDLE_BYTES) { bytes.fill(0); throw new BoxPayloadError('The token bundle is larger than the box accepts (1 MiB).'); }
  return bytes;
}

/** Errors are fixed text: nothing from the bundle is echoed. The input buffer stays the caller's to clear. */
export function decodeBoxPayload(bytes: Buffer): BoxPayload {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_BOX_BUNDLE_BYTES) throw new BoxPayloadError();
  let value: unknown;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new BoxPayloadError(); }
  const parsed = payloadSchema.safeParse(value);
  if (!parsed.success) throw new BoxPayloadError();
  if (parsed.data.kind === 'enroll' && parsed.data.shareB !== undefined && parsed.data.settings.mode !== 'unlock-on-restart') throw new BoxPayloadError();
  return parsed.data;
}

export function sameSettings(a: BoxSettings, b: BoxSettings): boolean {
  return a.mode === b.mode && a.audience === b.audience && a.keyName === b.keyName
    && a.deviceKeys.length === b.deviceKeys.length && a.deviceKeys.every((key, index) => key === b.deviceKeys[index]);
}
