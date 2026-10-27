import { createHash, createPublicKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalJson, generateDeviceKey } from '../../../src/security/index.js';
import type { DeviceKey } from '../../../src/security/index.js';
import type { AttestationResult } from '../../../src/types.js';
import { generateBoxKeyPair } from '../../../src/box/handshake/hpke.js';
import type { BoxKeyPair } from '../../../src/box/handshake/hpke.js';
import {
  boxKeyBindingNonce, createHandshake, handshakeAttestationNonces, handshakeMessageSchema,
  parseHandshakeMessage, serializeHandshakeMessage, signHandshakeMessage, verifyHandshakeMessage,
} from '../../../src/box/handshake/messages.js';
import type { BoxAttest, BoxHello, HandshakeMessage, UnsignedHandshakeMessage } from '../../../src/box/handshake/messages.js';

const now = new Date('2026-10-27T12:00:00.000Z');
const later = new Date('2026-10-27T12:10:00.000Z');
const challenge = Buffer.alloc(32, 7).toString('base64url');
const sessionId = Buffer.alloc(16, 1).toString('base64url');
const plaintext = Buffer.from('synthetic-private-token-bundle');

function evidence(nonces: string[], ok = true): AttestationResult {
  return {
    ok, checks: [{ name: 'fixture', ok, detail: 'local test evidence' }], boxKeyHash: nonces[0]!,
    claims: { iss: 'local-fixture', aud: 'keysentry', iat: now.getTime() / 1000, exp: later.getTime() / 1000,
      eat_nonce: nonces.length === 1 ? nonces[0] : nonces },
  };
}

function setup(keys: { deviceKey?: DeviceKey; signingKey?: DeviceKey; boxKey?: BoxKeyPair; sessionId?: string } = {}) {
  const deviceKey = keys.deviceKey ?? generateDeviceKey();
  const signingKey = keys.signingKey ?? generateDeviceKey();
  const boxKey = keys.boxKey ?? generateBoxKeyPair();
  const cli = createHandshake('cli', { deviceKey });
  const box = createHandshake('box', { devicePublicKeyDer: deviceKey.publicKeyDer, signingKey, boxKey, sessionId: keys.sessionId ?? sessionId });
  const h = box.next({ now, attestationToken: 'local-hello-token' });
  const hello = h.message as BoxHello;
  const c = cli.next({ now, message: hello, challenge });
  const a = h.handshake.next({ now, message: c.message!, attestationToken: 'local-challenged-token' });
  const attest = a.message as BoxAttest;
  return { deviceKey, signingKey, boxKey, cli, box, h, hello, c, a, attest };
}

function resign(message: HandshakeMessage, key: ReturnType<typeof generateDeviceKey>, changes: Record<string, unknown>) {
  const { sig: _sig, ...body } = message;
  return signHandshakeMessage({ ...body, ...changes } as UnsignedHandshakeMessage, key);
}

describe('canonical signed handshake messages', () => {
  it('signs every message, transfers only ciphertext, and acknowledges the exact sealed bundle', () => {
    const s = setup();
    const b = s.c.handshake.next({ now, message: s.attest,
      verifiedAttestation: evidence(handshakeAttestationNonces(s.attest)), plaintext });
    expect(b.message?.type).toBe('token-bundle');
    expect(serializeHandshakeMessage(b.message!)).not.toContain(plaintext.toString());
    const ack = s.a.handshake.next({ now, message: b.message! });
    expect(ack.plaintext).toEqual(plaintext);
    expect(ack.message?.type).toBe('box-ack');
    if (b.message?.type !== 'token-bundle' || ack.message?.type !== 'box-ack') throw new Error('wrong fixture step');
    expect(ack.message.bundleHash).toBe(createHash('sha256').update(Buffer.from(b.message.bundle, 'base64url')).digest('base64url'));
    const done = b.handshake.next({ now, message: ack.message });
    expect(done.handshake.state).toBe('complete');
    expect(ack.handshake.state).toBe('complete');
    expect(done.message).toBeNull();
    expect(s.cli.state).toBe('awaiting-hello');
    expect(s.box.state).toBe('ready');
    const boxDer = s.signingKey.publicKeyDer;
    for (const message of [s.hello, s.c.message!, s.attest, b.message, ack.message]) {
      const cliSigned = message.type === 'cli-challenge' || message.type === 'token-bundle';
      expect(verifyHandshakeMessage(message, cliSigned ? s.deviceKey.publicKeyDer : boxDer)).toBe(true);
      expect(handshakeMessageSchema.safeParse(message).success).toBe(true);
      expect(Date.parse(message.expiresAt) - Date.parse(message.sentAt)).toBe(600_000);
    }
  });

  it('binds both raw public keys in one 43-byte nonce', () => {
    const x = Buffer.alloc(32, 1), ed = Buffer.alloc(32, 2);
    const nonce = boxKeyBindingNonce(x, ed);
    expect(nonce).toBe(createHash('sha256').update(Buffer.concat([x, ed])).digest('base64url'));
    expect(Buffer.byteLength(nonce)).toBe(43);
    expect(boxKeyBindingNonce(x, Buffer.alloc(32, 3))).not.toBe(nonce);
    expect(() => boxKeyBindingNonce(Buffer.alloc(31), ed)).toThrow();
  });

  it('uses canonical JSON for the wire and rejects alternate encodings and added fields', () => {
    const { hello } = setup();
    const wire = serializeHandshakeMessage(hello);
    expect(wire).toBe(canonicalJson(hello));
    expect(parseHandshakeMessage(wire)).toEqual(hello);
    expect(() => parseHandshakeMessage(JSON.stringify(hello, null, 2))).toThrow(/canonical/i);
    expect(() => parseHandshakeMessage({ ...hello, unexpected: 'field' })).toThrow(/message/i);
    expect(() => parseHandshakeMessage('{invalid')).toThrow(/message/i);
  });

  it('rejects an edited body, a foreign signer and a missing signature', () => {
    const { hello, signingKey } = setup();
    expect(verifyHandshakeMessage({ ...hello, attestationToken: 'edited' }, signingKey.publicKeyDer)).toBe(false);
    expect(verifyHandshakeMessage(hello, generateDeviceKey().publicKeyDer)).toBe(false);
    const { sig: _sig, ...unsigned } = hello;
    expect(verifyHandshakeMessage(unsigned, signingKey.publicKeyDer)).toBe(false);
  });

  it('rejects malformed version, session id, timestamp, signature and payload encodings', () => {
    const { hello } = setup();
    for (const change of [{ v: 2 }, { sessionId: 'short' }, { id: 'short' }, { seq: 1 },
      { sentAt: 'yesterday' }, { expiresAt: '2026-10-27T12:20:00.000Z' }, { sig: 'bad' },
      { boxPublicKey: 'bad' }, { attestationToken: '' }]) {
      expect(handshakeMessageSchema.safeParse({ ...hello, ...change }).success).toBe(false);
    }
  });
});

describe('ordered immutable handshake', () => {
  it('responds to a provisional hello with only a fresh challenge before attestation', () => {
    const s = setup();
    const result = s.cli.next({ now, message: s.hello, plaintext });
    expect(result.message?.type).toBe('cli-challenge');
    expect(serializeHandshakeMessage(result.message!)).not.toContain(plaintext.toString());
    expect(result.plaintext).toBeUndefined();
  });

  it('requires fresh two-nonce attestation before sealing plaintext', () => {
    const s = setup();
    expect(() => s.c.handshake.next({ now, message: s.attest, plaintext })).toThrow(/attestation/i);
    expect(() => s.c.handshake.next({ now, message: s.attest, plaintext,
      verifiedAttestation: evidence(handshakeAttestationNonces(s.hello)) })).toThrow(/nonce/i);
    expect(() => s.c.handshake.next({ now, message: s.attest, plaintext,
      verifiedAttestation: evidence(handshakeAttestationNonces(s.attest).reverse()) })).toThrow(/nonce|binding/i);
  });

  it('rejects a changed encryption key after attestation even when the box signed it', () => {
    const s = setup();
    const swapped = resign(s.attest, s.signingKey, { boxPublicKey: generateBoxKeyPair().publicKeyRaw.toString('base64url') });
    expect(() => s.c.handshake.next({ now, message: swapped, plaintext,
      verifiedAttestation: evidence(handshakeAttestationNonces(swapped as BoxAttest)) })).toThrow(/key|binding/i);
  });

  it('rejects a changed signing key after the hello', () => {
    const s = setup();
    const replacement = generateDeviceKey();
    const raw = createPublicKey({ key: replacement.publicKeyDer, format: 'der', type: 'spki' }).export({ format: 'jwk' }).x!;
    const swapped = resign(s.attest, replacement, { boxSigningPublicKey: raw });
    expect(() => s.c.handshake.next({ now, message: swapped, plaintext,
      verifiedAttestation: evidence(handshakeAttestationNonces(swapped as BoxAttest)) })).toThrow(/signature|key/i);
  });

  it('rejects a replayed hello and a hello in the caller-provided replay cache', () => {
    const s = setup();
    expect(() => s.c.handshake.next({ now, message: s.hello })).toThrow(/replay/i);
    const cli = createHandshake('cli', { deviceKey: s.deviceKey, seenIds: [s.hello.id] });
    expect(() => cli.next({ now, message: s.hello })).toThrow(/replay/i);
    const knownSession = createHandshake('cli', { deviceKey: s.deviceKey, seenSessionIds: [s.hello.sessionId] });
    expect(() => knownSession.next({ now, message: s.hello })).toThrow(/replay/i);
  });

  it('rejects an out-of-order bundle before a challenge', () => {
    const s = setup();
    const b = s.c.handshake.next({ now, message: s.attest, plaintext,
      verifiedAttestation: evidence(handshakeAttestationNonces(s.attest)) });
    expect(() => s.h.handshake.next({ now, message: b.message! })).toThrow(/order/i);
  });

  it('rejects an expired challenge at the exact expiry boundary', () => {
    const s = setup();
    expect(() => s.h.handshake.next({ now: later, message: s.c.message!, attestationToken: 'unused' })).toThrow(/expir/i);
  });

  it('rejects future messages and keeps the original state usable after rejection', () => {
    const s = setup();
    expect(() => s.h.handshake.next({ now: new Date(now.getTime() - 1), message: s.c.message!, attestationToken: 'unused' })).toThrow(/future/i);
    expect(s.h.handshake.next({ now, message: s.c.message!, attestationToken: 'local-token' }).message?.type).toBe('box-attest');
  });

  it('rejects changed sessions and a broken transcript link', () => {
    const s = setup();
    const otherSession = resign(s.c.message!, s.deviceKey, { sessionId: Buffer.alloc(16, 2).toString('base64url') });
    expect(() => s.h.handshake.next({ now, message: otherSession, attestationToken: 'unused' })).toThrow(/session/i);
    const brokenLink = resign(s.c.message!, s.deviceKey, { previous: Buffer.alloc(32).toString('base64url') });
    expect(() => s.h.handshake.next({ now, message: brokenLink, attestationToken: 'unused' })).toThrow(/transcript/i);
  });

  it('rejects a foreign device challenge', () => {
    const s = setup();
    expect(() => s.h.handshake.next({ now, message: resign(s.c.message!, generateDeviceKey(), {}), attestationToken: 'unused' })).toThrow(/signature/i);
  });

  it('rejects a changed challenge in the second attestation', () => {
    const s = setup();
    const changed = resign(s.attest, s.signingKey, { challenge: Buffer.alloc(32, 8).toString('base64url') });
    expect(() => s.c.handshake.next({ now, message: changed, plaintext,
      verifiedAttestation: evidence(handshakeAttestationNonces(changed as BoxAttest)) })).toThrow(/challenge/i);
  });

  it('rejects ciphertext signed for another session and does not acknowledge it', () => {
    const s = setup();
    const other = setup({ deviceKey: s.deviceKey, signingKey: s.signingKey, boxKey: s.boxKey,
      sessionId: Buffer.alloc(16, 3).toString('base64url') });
    const bundle = other.c.handshake.next({ now, message: other.attest, plaintext,
      verifiedAttestation: evidence(handshakeAttestationNonces(other.attest)) }).message!;
    const spliced = resign(bundle, s.deviceKey, { previous: createHash('sha256').update(serializeHandshakeMessage(s.attest)).digest('base64url'),
      sessionId: s.hello.sessionId,
      boxKeyHash: boxKeyBindingNonce(s.boxKey.publicKeyRaw, Buffer.from(s.hello.boxSigningPublicKey, 'base64url')) });
    expect(() => s.a.handshake.next({ now, message: spliced })).toThrow();
  });

  it('rejects an acknowledgement for a different sealed bundle', () => {
    const s = setup();
    const b = s.c.handshake.next({ now, message: s.attest, plaintext,
      verifiedAttestation: evidence(handshakeAttestationNonces(s.attest)) });
    const ack = s.a.handshake.next({ now, message: b.message! });
    const wrongHash = resign(ack.message!, s.signingKey, { bundleHash: Buffer.alloc(32).toString('base64url') });
    expect(() => b.handshake.next({ now, message: wrongHash })).toThrow(/bundle/i);
  });

  it('uses fresh 128-bit sessions, message ids and challenges by default', () => {
    const a = setup(), b = setup();
    const c1 = a.cli.next({ now, message: a.hello });
    const c2 = a.cli.next({ now, message: a.hello });
    expect(c1.message!.id).not.toBe(c2.message!.id);
    if (c1.message?.type !== 'cli-challenge' || c2.message?.type !== 'cli-challenge') throw new Error('wrong fixture step');
    expect(c1.message.challenge).not.toBe(c2.message.challenge);
    const boxA = createHandshake('box', { devicePublicKeyDer: a.deviceKey.publicKeyDer, signingKey: a.signingKey, boxKey: a.boxKey });
    const boxB = createHandshake('box', { devicePublicKeyDer: b.deviceKey.publicKeyDer, signingKey: b.signingKey, boxKey: b.boxKey });
    expect(Buffer.from(boxA.sessionId!, 'base64url').length).toBe(16);
    expect(boxA.sessionId).not.toBe(boxB.sessionId);
  });
});
