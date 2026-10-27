import { randomBytes } from 'node:crypto';
import { expect, test } from 'vitest';
import { sealBytes } from '../../src/security/index.js';
import { openWatcherConfig, sealWatcherConfig } from '../../src/watcher/seal.js';
import type { WatcherConfig } from '../../src/watcher/config.js';

function config(): WatcherConfig {
  return {
    v: 1, projectId: 'project-test', armed: null, trustedKeyIds: [], devicePublicKeys: [], passkeys: [],
    notify: { channels: [{ kind: 'webhook', settings: { webhookUrl: 'https://example.com/private-token' } }] },
    sources: { disabled: [], extra: [] }, approvals: { publicOrigin: null, relay: null }, intervalSeconds: 600,
  };
}

test('sealed config round-trips and any edited envelope byte fails to open', () => {
  const key = randomBytes(32);
  const sealed = sealWatcherConfig(config(), key);
  expect(sealed).toMatch(/^ksw1\.[A-Za-z0-9_-]+$/);
  expect(sealed).not.toContain('private-token');
  expect(openWatcherConfig(sealed, key)).toEqual(config());
  const bytes = Buffer.from(sealed.slice(5), 'base64url');
  for (let i = 0; i < bytes.length; i++) {
    const changed = Buffer.from(bytes);
    changed[i] ^= 1;
    expect(() => openWatcherConfig(`ksw1.${changed.toString('base64url')}`, key)).toThrow();
  }
});

test('wrong key, wrong AAD and noncanonical encodings fail with no secret in the error', () => {
  const key = randomBytes(32);
  const sealed = sealWatcherConfig(config(), key);
  const wrongLabel = sealBytes(key, Buffer.from(JSON.stringify(config())), 'another-label');
  for (const invalid of ['private-token', `${sealed}=`, sealed.replace('ksw1.', 'ksw2.'), `ksw1.${wrongLabel.toString('base64url')}`]) {
    expect(() => openWatcherConfig(invalid, key)).toThrow(/watcher config/i);
    try { openWatcherConfig(invalid, key); } catch (error) { expect(String(error)).not.toContain('private-token'); }
  }
  expect(() => openWatcherConfig(sealed, randomBytes(32))).toThrow(/watcher config/i);
});

test('authenticated malformed JSON, schema changes and oversized configs are rejected', () => {
  const key = randomBytes(32);
  for (const plain of ['{private-token', JSON.stringify({ ...config(), unexpected: 'private-token' }), ' '.repeat(2 * 1024 * 1024 + 1)]) {
    const sealed = `ksw1.${sealBytes(key, Buffer.from(plain), 'keysentry-watcher-config:v1').toString('base64url')}`;
    expect(() => openWatcherConfig(sealed, key)).toThrow(/watcher config/i);
  }
  expect(() => sealWatcherConfig({ ...config(), intervalSeconds: 0 }, key)).toThrow(/watcher config/i);
  expect(() => sealWatcherConfig(config(), Buffer.alloc(31))).toThrow(/32 bytes/);
});

test('independent seals use independent nonces and leave the deploy key untouched', () => {
  const key = Buffer.alloc(32, 42);
  expect(sealWatcherConfig(config(), key)).not.toBe(sealWatcherConfig(config(), key));
  expect(key).toEqual(Buffer.alloc(32, 42));
});
