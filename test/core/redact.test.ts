import { describe, expect, it, vi } from 'vitest';
import { createLogger, createRedactor } from '../../src/core/redact.js';

const hex = '0123456789abcdef'.repeat(4);
const random = 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY';

describe('createRedactor', () => {
  it('masks all registered occurrences, including overlaps and regex metacharacters', () => {
    const redactor = createRedactor();
    redactor.register('abc123');
    redactor.register('abc12345');
    redactor.register('fake.$[secret]');
    redactor.register('tiny');
    expect(redactor.redact('abc12345 abc123 abc12345 fake.$[secret] tiny')).toBe('«redacted» «redacted» «redacted» «redacted» tiny');
  });

  const keys = [
    `sk-proj-${random}`, `sk-svcacct-${random}`, `sk-${hex}`, `sk-ant-api03-${random}`, `sk-ant-admin01-${random}`, `sk-or-v1-${hex}`,
    `sk_live_${random}`, `sk_test_${random}`, `rk_live_${random}`, `rk_test_${random}`, `whsec_${random}`, `re_${random}`,
    `ghp_${random}`, `gho_${random}`, `ghs_${random}`, `ghu_${random}`, `github_pat_${random}`, `sb_secret_${random}`,
    'xoxb-1234567890-1234567890-fakeABC1234567890', 'xoxp-1234567890-1234567890-fakeABC1234567890',
    'https://hooks.slack.com/services/T00000000/B00000000/fakeABC123fakeABC123fakeAB',
    `SG.${random.slice(0, 22)}.${random}${random}`, `SK${hex.slice(0, 32)}`, `AIza${random}abc`,
    'postgres://user:fake-password@localhost/db', 'mongodb://user:fake-password@db1,db2/db',
    'postgresql://localhost/db?user=app&password=fake-database-password',
    'postgresql://app:fake-database-password@${{Postgres.HOST}}/db',
    '-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----',
    `${Buffer.from('{"alg":"HS256"}').toString('base64url')}.${Buffer.from('{"role":"service_role"}').toString('base64url')}.fake_sig`,
    JSON.stringify({ type: 'service_account', private_key: 'fake-private-material' }),
  ];
  it.each(keys)('masks an unregistered provider pattern (case %#)', (key) => {
    const result = createRedactor().redact(`before (${key}) after ${key}`);
    expect(result).not.toContain(key);
    expect(result).toContain('«redacted»');
    expect(result).toContain('before');
  });

  it('preserves public and ordinary values', () => {
    const text = `pk_live_${random} AKIA0123456789ABCDEF https://example.test 123 true`;
    expect(createRedactor().redact(text)).toBe(text);
  });

  it('masks the whole provider key when a registered prefix overlaps its pattern', () => {
    const redactor = createRedactor();
    redactor.register('sk-proj-');
    expect(redactor.redact(`before sk-proj-${random} after`)).toBe('before «redacted» after');
  });

  it('covers overlapping registered values even when they start at different offsets', () => {
    const redactor = createRedactor();
    redactor.register('abc123');
    redactor.register('c12345');
    expect(redactor.redact('abc12345')).toBe('«redacted»');
  });
});

describe('createLogger', () => {
  it('filters below the configured level and redacts nested data, errors, and messages', () => {
    const lines: string[] = [];
    const redactor = createRedactor();
    redactor.register('fake-log-secret');
    const log = createLogger({ redactor, level: 'warn', sink: (line) => lines.push(line) });
    log.debug('hidden');
    log.info('hidden');
    log.warn('fake-log-secret', { nested: { value: 'fake-log-secret' }, error: new Error(`sk-${hex}`) });
    log.error('failed', { value: `sk-${hex}` });
    expect(lines).toHaveLength(2);
    expect(lines.join('\n')).not.toContain('fake-log-secret');
    expect(lines.join('\n')).not.toContain(`sk-${hex}`);
    expect(lines.join('\n')).toContain('«redacted»');
  });

  it('emits valid JSON after redaction even for quoted registered values', () => {
    const redactor = createRedactor();
    redactor.register('fake-"quote-secret');
    const lines: string[] = [];
    createLogger({ redactor, json: true, sink: (line) => lines.push(line) }).info('event', { value: 'fake-"quote-secret', nested: { secret: `sk-${hex}` } });
    const parsed = JSON.parse(lines[0]!);
    expect(parsed.level).toBe('info');
    expect(parsed.message).toBe('event');
    expect(JSON.stringify(parsed)).not.toContain('quote-secret');
    expect(JSON.stringify(parsed)).not.toContain(`sk-${hex}`);
  });

  it('handles cycles and bigint without throwing and defaults to stderr', () => {
    const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      const circular: Record<string, unknown> = { amount: 1n };
      circular.self = circular;
      createLogger({ redactor: createRedactor() }).info('event', circular);
      expect(write).toHaveBeenCalledOnce();
      expect(String(write.mock.calls[0]?.[0])).toContain('event');
    } finally {
      write.mockRestore();
    }
  });

  it('redacts registered values emitted as numeric data', () => {
    const redactor = createRedactor();
    redactor.register('123456789');
    const lines: string[] = [];
    createLogger({ redactor, json: true, sink: (line) => lines.push(line) }).info('event', { integer: 123456789, big: 123456789n });
    expect(lines[0]).not.toContain('123456789');
    expect(JSON.parse(lines[0]!).data).toEqual({ integer: '«redacted»', big: '«redacted»' });
  });

  it.each([true, false])('does not invoke a custom serializer after redaction (json=%s)', (json) => {
    const redactor = createRedactor();
    redactor.register('fake-registered-sensitive-token');
    const lines: string[] = [];
    const toJSON = vi.fn(() => 'fake-registered-sensitive-token');
    createLogger({ redactor, json, sink: (line) => lines.push(line) }).info('event', { nested: { toJSON } });
    expect(lines[0]).not.toContain('fake-registered-sensitive-token');
    expect(toJSON).not.toHaveBeenCalled();
  });

  it('copies array subclasses into plain arrays without invoking their serializers', () => {
    const redactor = createRedactor();
    redactor.register('fake-registered-sensitive-token');
    class SecretArray extends Array {
      toJSON() { return 'fake-registered-sensitive-token'; }
    }
    const lines: string[] = [];
    createLogger({ redactor, json: true, sink: (line) => lines.push(line) }).info('event', { list: new SecretArray('safe') });
    expect(lines[0]).not.toContain('fake-registered-sensitive-token');
    expect(JSON.parse(lines[0]!).data.list).toEqual(['safe']);
  });

  it('redacts registered ISO dates and tolerates throwing data getters', () => {
    const redactor = createRedactor();
    const date = new Date('2026-10-26T12:34:56.000Z');
    redactor.register(date.toISOString());
    const lines: string[] = [];
    const data = { date, nested: { get value(): never { throw new Error('fake-sensitive-getter'); } } };
    expect(() => createLogger({ redactor, json: true, sink: (line) => lines.push(line) }).info('event', data)).not.toThrow();
    expect(lines[0]).not.toContain(date.toISOString());
    expect(lines[0]).not.toContain('fake-sensitive-getter');
    expect(JSON.parse(lines[0]!).data.date).toBe('«redacted»');
  });
});
