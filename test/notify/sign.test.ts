import { createHash } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { canonicalJson, generateDeviceKey, verifyDetached } from '../../src/security/index.js';
import type { NotifyMessage, SignedNotifyMessage } from '../../src/types.js';
import { signMessage, verifyMessage } from '../../src/notify/sign.js';

const message: NotifyMessage = {
  id: 'message-1', at: '2026-10-27T10:00:00.000Z', kind: 'rotation', severity: 'warning',
  title: 'Rotation needs approval', lines: ['One service is ready.'], actionId: 'action-1',
  approveUrl: 'https://localhost/approve/action-1',
};

describe('notification signing', () => {
  test('signs the exact versioned canonical message and derives the RFC 4648 verification code', () => {
    const key = generateDeviceKey();
    const signed = signMessage(message, key);
    const signature = Buffer.from(signed.sig, 'base64');
    expect(verifyDetached(key.publicKeyDer, Buffer.from('keysentry-notify:v1\n' + canonicalJson(message)), signature)).toBe(true);
    const bits = [...createHash('sha256').update(signature).digest().subarray(0, 5)]
      .map((byte) => byte.toString(2).padStart(8, '0')).join('');
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const code = bits.match(/.{5}/g)!.map((part) => alphabet[Number.parseInt(part, 2)]).join('');
    expect(signed.code).toBe(code.slice(0, 4) + '-' + code.slice(4));
    expect(signed.keyId).toBe(key.keyId);
    expect(verifyMessage(signed, key.publicKeyDer)).toBe(true);
    expect(message).not.toHaveProperty('sig');
    signed.lines.push('Signed copy changed');
    expect(message.lines).toEqual(['One service is ready.']);
  });

  test('any changed message field or signature, code, or key id fails verification', () => {
    const key = generateDeviceKey();
    const signed = signMessage(message, key);
    const edits: Partial<SignedNotifyMessage>[] = [
      { id: 'another' }, { at: '2026-10-28T10:00:00.000Z' }, { kind: 'test' }, { severity: 'urgent' },
      { title: 'Changed' }, { lines: ['Changed'] }, { actionId: 'another' }, { approveUrl: 'https://elsewhere.example/' },
      { keyId: '0123456789abcdef' }, { code: 'AAAA-AAAA' }, { sig: Buffer.alloc(64).toString('base64') },
    ];
    for (const edit of edits) expect(verifyMessage({ ...signed, ...edit }, key.publicKeyDer)).toBe(false);
    expect(verifyMessage(signed, generateDeviceKey().publicKeyDer)).toBe(false);
    expect(verifyMessage(signed, Buffer.from('invalid public key'))).toBe(false);
  });

  test('rejects unknown unsigned fields and malformed signatures without throwing or reflecting input', () => {
    const key = generateDeviceKey();
    const signed = signMessage(message, key);
    for (const value of [null, {}, { ...signed, extra: 'ignored?' }, { ...signed, lines: [42] },
      { ...signed, severity: 'invalid' }, { ...signed, sig: signed.sig + '!' },
      { ...signed, sig: signed.sig.replace(/=+$/, '') }, { ...signed, code: 'aaaa-aaaa' },
      { ...signed, title: undefined }, { ...signed, approveUrl: null }]) {
      expect(verifyMessage(value as SignedNotifyMessage, key.publicKeyDer)).toBe(false);
    }
    expect(() => signMessage({ ...message, secretField: 'never echo this' } as NotifyMessage, key))
      .toThrow('Invalid notification message');
  });

  test('does not evaluate accessors or custom serialization in untrusted messages', () => {
    const key = generateDeviceKey();
    let reads = 0;
    const signed = signMessage(message, key);
    const accessor = { ...signed, get title() { reads += 1; return 'Changed'; } };
    expect(verifyMessage(accessor, key.publicKeyDer)).toBe(false);
    expect(reads).toBe(0);
    expect(verifyMessage({ ...signed, toJSON: () => signed } as SignedNotifyMessage, key.publicKeyDer)).toBe(false);
  });

  test('rejects custom array iteration and sparse lines without executing untrusted code', () => {
    const key = generateDeviceKey();
    const signed = signMessage(message, key);
    let reads = 0;
    const lines = [...signed.lines];
    Object.defineProperty(lines, Symbol.iterator, { value() { reads += 1; return [][Symbol.iterator](); } });
    expect(verifyMessage({ ...signed, lines }, key.publicKeyDer)).toBe(false);
    expect(reads).toBe(0);
    expect(() => signMessage({ ...message, lines: new Array<string>(1) }, key)).toThrow('Invalid notification message');
  });
});
