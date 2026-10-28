import { createHmac, createPublicKey, randomBytes, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  AuditExportError, WEBHOOK_EVENT_TYPE, createWebhookSink, decodeWebhookSecret, verifyWebhookSignature, webhookId, webhookPublicKey,
} from '../../src/audit-export/index.js';
import { generateDeviceKey } from '../../src/security/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { FakeHttp, text } from '../helpers/fake-http.js';
import { sampleRecord, unexpected } from './helpers.js';

const now = () => new Date('2026-10-28T12:00:00.000Z');
const device = generateDeviceKey();
const signingKey = async () => ({ ...device, privateKeyDer: Buffer.from(device.privateKeyDer) });
const ed = { kind: 'webhook' as const, id: 'hook', url: 'https://hooks.example.com/keysentry', signing: 'ed25519' as const };
const hm = { ...ed, signing: 'hmac-sha256' as const };
const secretBytes = randomBytes(32);
const WHSEC = `whsec_${secretBytes.toString('base64')}`;

/** What a receiver does with nothing but node:crypto and the published whpk_ key. */
function receiverVerifiesEd25519(headers: Record<string, string>, body: string, whpk: string): boolean {
  const raw = Buffer.from(whpk.slice('whpk_'.length), 'base64');
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') }, format: 'jwk' });
  const signed = Buffer.from(`${headers['webhook-id']}.${headers['webhook-timestamp']}.${body}`, 'utf8');
  return headers['webhook-signature']!.split(' ').some(entry => entry.startsWith('v1a,')
    && verify(null, signed, key, Buffer.from(entry.slice(4), 'base64')));
}

describe('signed webhook export (Standard Webhooks)', () => {
  it('signs with the device Ed25519 key; a receiver verifies with the published public key', async () => {
    const http = new FakeHttp().on('POST', /hooks\.example\.com/, () => text(204, ''));
    const batch = [sampleRecord(1), sampleRecord(2)];
    expect(await createWebhookSink(ed, { http, vault: createFakeVault(), now, sourceId: 'src1', signingKey }).deliver(batch)).toEqual({});
    const request = http.calls[0]!;
    const headers = request.headers!;
    expect(headers['content-type']).toBe('application/json');
    expect(headers['webhook-id']).toBe('src1_1-2');
    expect(headers['webhook-timestamp']).toBe(String(Math.floor(now().getTime() / 1000)));
    expect(headers['webhook-signature']).toMatch(/^v1a,[A-Za-z0-9+/]+=*$/);
    expect(headers['keysentry-key-id']).toBe(device.keyId);
    expect(JSON.parse(request.body!)).toEqual({ type: WEBHOOK_EVENT_TYPE, timestamp: '2026-10-28T12:00:00.000Z', data: { source: 'src1', records: batch } });

    const whpk = webhookPublicKey(device.publicKeyDer);
    expect(Buffer.from(whpk.slice(5), 'base64')).toHaveLength(32);
    expect(receiverVerifiesEd25519(headers, request.body!, whpk)).toBe(true);
    expect(verifyWebhookSignature({ id: headers['webhook-id']!, timestamp: headers['webhook-timestamp']!, body: request.body!,
      signature: headers['webhook-signature']!, publicKeyDer: device.publicKeyDer })).toBe(true);
    // A changed body, id or timestamp, or another key, does not verify.
    expect(receiverVerifiesEd25519(headers, request.body!.replace('Event 1', 'Event X'), whpk)).toBe(false);
    expect(receiverVerifiesEd25519({ ...headers, 'webhook-timestamp': '1' }, request.body!, whpk)).toBe(false);
    expect(receiverVerifiesEd25519(headers, request.body!, webhookPublicKey(generateDeviceKey().publicKeyDer))).toBe(false);
  });

  it('signs with HMAC-SHA256 over id.timestamp.body using the decoded whsec_ secret', async () => {
    const http = new FakeHttp().on('POST', /hooks/, () => text(200, 'ok'));
    const vault = createFakeVault({ 'audit-export/hook/hmac-secret': Buffer.from(WHSEC) });
    await createWebhookSink(hm, { http, vault, now, sourceId: 'src1', signingKey }).deliver([sampleRecord(3)]);
    const { headers, body } = http.calls[0]!;
    const expected = createHmac('sha256', secretBytes).update(`${headers!['webhook-id']}.${headers!['webhook-timestamp']}.${body}`).digest('base64');
    expect(headers!['webhook-signature']).toBe(`v1,${expected}`);
    expect(headers!['keysentry-key-id']).toBeUndefined();
    expect(verifyWebhookSignature({ id: headers!['webhook-id']!, timestamp: headers!['webhook-timestamp']!, body: body!,
      signature: `v1,${'A'.repeat(43)}= ${headers!['webhook-signature']}`, secret: secretBytes })).toBe(true);
    expect(verifyWebhookSignature({ id: headers!['webhook-id']!, timestamp: headers!['webhook-timestamp']!, body: `${body} `,
      signature: headers!['webhook-signature']!, secret: secretBytes })).toBe(false);
    expect(JSON.stringify(http.calls)).not.toContain(WHSEC);
  });

  it('keeps the message id stable across retries of the same batch and free of "."', () => {
    expect(webhookId('src1', [sampleRecord(10), sampleRecord(11), sampleRecord(12)])).toBe('src1_10-12');
    expect(webhookId('src1', [sampleRecord(10)])).not.toContain('.');
  });

  it('accepts only whsec_ secrets of 24 to 64 bytes', () => {
    expect(decodeWebhookSecret(Buffer.from(WHSEC))?.equals(secretBytes)).toBe(true);
    for (const value of ['plain-secret-value', `whsec_${randomBytes(16).toString('base64')}`, `whsec_${randomBytes(65).toString('base64')}`, 'whsec_not base64!']) {
      expect(decodeWebhookSecret(Buffer.from(value))).toBeNull();
    }
  });

  it('refuses to send without a usable secret or key, with guidance and no secret in the message', async () => {
    const http = new FakeHttp();
    const missing = await createWebhookSink(hm, { http, vault: createFakeVault(), now, sourceId: 's', signingKey }).deliver([sampleRecord(1)])
      .then(unexpected, (caught: unknown) => caught as AuditExportError);
    expect(missing.message).toBe('Store the webhook signing secret first: keysentry audit export secret hook hmac-secret.');
    const weak = await createWebhookSink(hm, { http, vault: createFakeVault({ 'audit-export/hook/hmac-secret': Buffer.from('whsec_short-secret-value') }), now, sourceId: 's', signingKey })
      .deliver([sampleRecord(1)]).then(unexpected, (caught: unknown) => caught as AuditExportError);
    expect(weak.message).not.toContain('short-secret-value');
    const noKey = await createWebhookSink(ed, { http, vault: createFakeVault(), now, sourceId: 's', signingKey: async () => { throw new Error('vault locked: detail'); } })
      .deliver([sampleRecord(1)]).then(unexpected, (caught: unknown) => caught as AuditExportError);
    expect(noKey.message).toBe('The device signing key is unavailable, so the webhook batch could not be signed.');
    expect(http.calls).toHaveLength(0);
  });

  it('clears the private key buffer it was given after signing', async () => {
    let given: Buffer | undefined;
    const http = new FakeHttp().on('POST', /hooks/, () => text(200, ''));
    await createWebhookSink(ed, { http, vault: createFakeVault(), now, sourceId: 's',
      signingKey: async () => { given = Buffer.from(device.privateKeyDer); return { ...device, privateKeyDer: given }; } }).deliver([sampleRecord(1)]);
    expect(given!.every(byte => byte === 0)).toBe(true);
  });

  it('retries timeouts, throttling and server errors, not other client errors', async () => {
    for (const [status, retryable] of [[500, true], [503, true], [429, true], [408, true], [400, false], [401, false], [410, false]] as const) {
      const http = new FakeHttp().on('POST', /hooks/, () => text(status, 'receiver detail', { 'retry-after': '3' }));
      const error = await createWebhookSink(ed, { http, vault: createFakeVault(), now, sourceId: 's', signingKey }).deliver([sampleRecord(1)])
        .then(unexpected, (caught: unknown) => caught as AuditExportError);
      expect(error.message).toBe(`The webhook receiver answered HTTP ${status}.`);
      expect(error.retryable).toBe(retryable);
      expect(error.retryAfterMs).toBe(retryable ? 3000 : undefined);
    }
  });
});
