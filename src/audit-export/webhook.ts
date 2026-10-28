import { createHmac, createPublicKey, timingSafeEqual } from 'node:crypto';
import { canonicalJson, signDetached, verifyDetached } from '../security/index.js';
import type { DeviceKey } from '../security/index.js';
import type { AuditExportRecord, HttpClient, Vault } from '../types.js';
import { httpFailure, readSecret, sendRequest } from './delivery.js';
import { AuditExportError, type ExportSink, type WebhookTarget } from './types.js';

/**
 * Standard Webhooks (https://www.standardwebhooks.com/): headers webhook-id, webhook-timestamp and webhook-signature;
 * the signed content is `${webhook-id}.${webhook-timestamp}.${body}` (UTF-8). Symmetric signatures are `v1,<base64
 * HMAC-SHA256>`, asymmetric ones `v1a,<base64 Ed25519>`.
 */
export const WEBHOOK_EVENT_TYPE = 'keysentry.audit.batch';
const RECEIVER = 'webhook receiver';
const RETRYABLE = (status: number) => status === 408 || status === 425 || status === 429 || status >= 500;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function webhookSignedContent(id: string, timestamp: number, body: string): Buffer {
  return Buffer.from(`${id}.${timestamp}.${body}`, 'utf8');
}

/** The raw 32-byte Ed25519 public key, base64, prefixed `whpk_` as Standard Webhooks shows asymmetric public keys. */
export function webhookPublicKey(publicKeyDer: Buffer): string {
  const jwk = createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' }).export({ format: 'jwk' });
  return `whpk_${Buffer.from(String(jwk.x), 'base64url').toString('base64')}`;
}

/** Decodes a `whsec_<base64>` secret of 24 to 64 bytes (the Standard Webhooks range). The caller clears the result. */
export function decodeWebhookSecret(value: Buffer): Buffer | null {
  const text = value.toString('utf8').trim();
  if (!text.startsWith('whsec_')) return null;
  const encoded = text.slice('whsec_'.length);
  if (!BASE64.test(encoded)) return null;
  const key = Buffer.from(encoded, 'base64');
  if (key.length < 24 || key.length > 64 || key.toString('base64') !== encoded) { key.fill(0); return null; }
  return key;
}

export function buildWebhookBody(batch: readonly AuditExportRecord[], opts: { sentAt: Date; sourceId: string; logId?: string }): string {
  return canonicalJson({ type: WEBHOOK_EVENT_TYPE, timestamp: opts.sentAt.toISOString(),
    data: { source: opts.sourceId, ...(opts.logId ? { log: opts.logId } : {}), records: batch } });
}

/** Stable across retries of the same batch, so receivers can use it as an idempotency key. Never contains '.'. */
export function webhookId(sourceId: string, batch: readonly AuditExportRecord[], logId?: string): string {
  return `${sourceId}${logId ? `_${logId}` : ''}_${batch[0]?.seq ?? 0}-${batch.at(-1)?.seq ?? 0}`;
}

export function signWebhook(content: Buffer, key: { ed25519: Buffer } | { hmac: Buffer }): string {
  return 'ed25519' in key
    ? `v1a,${signDetached(key.ed25519, content).toString('base64')}`
    : `v1,${createHmac('sha256', key.hmac).update(content).digest('base64')}`;
}

/**
 * Receiver-side check, also used by the tests: true when any signature in the space-separated header verifies.
 * `publicKeyDer` is SPKI DER (or use the whpk_ value with any Ed25519 library); `secret` is the decoded HMAC key.
 */
export function verifyWebhookSignature(opts: { id: string; timestamp: string; body: string; signature: string;
  publicKeyDer?: Buffer; secret?: Buffer }): boolean {
  if (!/^\d{1,12}$/.test(opts.timestamp) || opts.id.includes('.')) return false;
  const content = webhookSignedContent(opts.id, Number(opts.timestamp), opts.body);
  return opts.signature.split(' ').some(entry => {
    const [version, value] = entry.split(',', 2);
    if (!value || !BASE64.test(value)) return false;
    const signature = Buffer.from(value, 'base64');
    if (version === 'v1a' && opts.publicKeyDer) return verifyDetached(opts.publicKeyDer, content, signature);
    if (version === 'v1' && opts.secret) {
      const expected = createHmac('sha256', opts.secret).update(content).digest();
      return expected.length === signature.length && timingSafeEqual(expected, signature);
    }
    return false;
  });
}

export function createWebhookSink(target: WebhookTarget, deps: {
  http: HttpClient; vault: Vault; now: () => Date; sourceId: string; logId?: string; signingKey: () => Promise<DeviceKey>;
}): ExportSink {
  async function sign(content: Buffer): Promise<{ signature: string; keyId?: string }> {
    if (target.signing === 'ed25519') {
      let key: DeviceKey;
      try { key = await deps.signingKey(); }
      catch { throw new AuditExportError('The device signing key is unavailable, so the webhook batch could not be signed.', false); }
      try { return { signature: signWebhook(content, { ed25519: key.privateKeyDer }), keyId: key.keyId }; }
      catch { throw new AuditExportError('The webhook batch could not be signed.', false); }
      finally { key.privateKeyDer.fill(0); }
    }
    const stored = await readSecret(deps.vault, target.id, 'hmac-secret');
    if (!stored) throw new AuditExportError(`Store the webhook signing secret first: keysentry audit export secret ${target.id} hmac-secret.`, false);
    const secret = decodeWebhookSecret(stored);
    stored.fill(0);
    if (!secret) throw new AuditExportError('The stored webhook secret must be whsec_ followed by base64 of 24 to 64 random bytes.', false);
    try { return { signature: signWebhook(content, { hmac: secret }) }; }
    finally { secret.fill(0); }
  }

  return {
    target,
    // Host only: webhook paths often carry a token, and they never appear in output.
    destination: `signed webhook (${target.signing}) to ${new URL(target.url).host}`,
    async deliver(batch) {
      const sentAt = deps.now();
      const timestamp = Math.floor(sentAt.getTime() / 1000);
      const id = webhookId(deps.sourceId, batch, deps.logId);
      const body = buildWebhookBody(batch, { sentAt, sourceId: deps.sourceId, ...(deps.logId ? { logId: deps.logId } : {}) });
      const { signature, keyId } = await sign(webhookSignedContent(id, timestamp, body));
      const response = await sendRequest(deps.http, { method: 'POST', url: target.url, body, headers: {
        'content-type': 'application/json', 'webhook-id': id, 'webhook-timestamp': String(timestamp), 'webhook-signature': signature,
        ...(keyId ? { 'keysentry-key-id': keyId } : {}),
      } }, RECEIVER);
      if (response.status >= 200 && response.status < 300) return {};
      throw httpFailure(response, RECEIVER, deps.now(), RETRYABLE);
    },
    preview: batch => ({ location: new URL(target.url).host,
      bytes: Buffer.byteLength(buildWebhookBody(batch, { sentAt: deps.now(), sourceId: deps.sourceId, ...(deps.logId ? { logId: deps.logId } : {}) })) }),
    dispose() {},
  };
}
