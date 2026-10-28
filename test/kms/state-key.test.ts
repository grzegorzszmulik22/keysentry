import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  createVaultTransitWrapper, decodeWrappedStateKey, encodeWrappedStateKey, KmsError, loadProjectStateKey, migrateStateKey, rotateStateKey,
  stateKeyContext, stateKeyStatus, unwrapWatcherStateKey, wrapWatcherStateKey, type MigrationPoint,
} from '../../src/kms/index.js';
import type { HttpClient, KeyWrapper } from '../../src/types.js';
import { createEnvVault } from '../../src/vault/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { credentialSource, failure, fakeVaultTransit, now, secretFree, VAULT_ADDR } from './fakes.js';

const PROJECT = '0123456789abcdef';
const PLAIN = `project/${PROJECT}/key/state`;
const WRAPPED = `project/${PROJECT}/key/state.wrapped`;
const TOKEN = 'hvs.vault-token-planted';
const settings = { provider: 'vault-transit', address: VAULT_ADDR, mount: 'transit', keyName: 'state' } as const;

function setup(seed: Record<string, Buffer> = {}) {
  const fake = fakeVaultTransit();
  const vault = createFakeVault(seed);
  const wrapper = createVaultTransitWrapper(settings, { http: fake.http, credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now });
  return { fake, vault, wrapper };
}
const snapshot = (vault: ReturnType<typeof createFakeVault>) => new Map([...vault.dump()].map(([name, value]) => [name, value.toString('base64')]));
const down: HttpClient = { async request() { throw new Error('connect ECONNREFUSED upstream-secret-detail'); } };

async function migrated() {
  const original = randomBytes(32);
  const f = setup({ [PLAIN]: original });
  expect((await migrateStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper, now })).result).toBe('migrated');
  return { ...f, original };
}

describe('state key loading', () => {
  it('without kms keeps the existing behaviour: the plain key, created on first use', async () => {
    const vault = createFakeVault();
    const key = await loadProjectStateKey({ vault, projectId: PROJECT });
    expect(key).toHaveLength(32);
    expect((await vault.get(PLAIN))!.equals(key)).toBe(true);
    expect(await vault.get(WRAPPED)).toBeNull();
  });

  it('without kms refuses a wrapped-only key and creates nothing', async () => {
    const { vault } = await migrated();
    const before = snapshot(vault);
    const error = await failure(loadProjectStateKey({ vault, projectId: PROJECT }));
    expect(error).toBeInstanceOf(KmsError);
    expect(error.message).toContain('keysentry.yaml has no kms section');
    expect(snapshot(vault)).toEqual(before);
  });

  it('with kms unwraps the wrapped key into memory and keeps no plain copy', async () => {
    const { vault, wrapper, original } = await migrated();
    expect(await vault.get(PLAIN)).toBeNull();
    const record = decodeWrappedStateKey((await vault.get(WRAPPED))!);
    expect(record).toMatchObject({ v: 1, provider: 'vault-transit', keyRef: wrapper.keyRef, wrappedAt: now().toISOString() });
    const key = await loadProjectStateKey({ vault, projectId: PROJECT, wrapper });
    expect(key.equals(original)).toBe(true);
  });

  it.each([
    ['an unreachable KMS', 'unreachable', (f: Awaited<ReturnType<typeof migrated>>) => createVaultTransitWrapper(settings, { http: down, credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now })],
    ['a revoked token', 'denied', (f: Awaited<ReturnType<typeof migrated>>) => { f.fake.state.token = 'hvs.rotated'; return f.wrapper; }],
    ['a deleted key', 'key-unavailable', (f: Awaited<ReturnType<typeof migrated>>) => { f.fake.state.exists = false; return f.wrapper; }],
    ['a different configured key', 'wrong-key', (f: Awaited<ReturnType<typeof migrated>>) => createVaultTransitWrapper({ ...settings, keyName: 'other' }, { http: f.fake.http, credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now })],
  ] as const)('refuses to start with %s and never creates a new state key', async (_name, code, breakIt) => {
    const f = await migrated();
    const wrapper: KeyWrapper = breakIt(f);
    const before = snapshot(f.vault);
    const error = await failure(loadProjectStateKey({ vault: f.vault, projectId: PROJECT, wrapper }));
    expect(error).toBeInstanceOf(KmsError);
    expect(error.code).toBe(code);
    expect(error.message).toContain('keysentry did not create a new state key');
    expect(snapshot(f.vault)).toEqual(before);
    expect(secretFree(error, [TOKEN, f.original.toString('base64'), f.original.toString('hex')])).toBe(true);
  });

  it('refuses a tampered wrapped blob and a blob copied from another project', async () => {
    const f = await migrated();
    const record = decodeWrappedStateKey((await f.vault.get(WRAPPED))!);
    const opaque = JSON.parse(Buffer.from(record.ciphertext, 'base64').toString());
    const raw = Buffer.from(opaque.ciphertext.slice('vault:v1:'.length), 'base64'); raw[14]! ^= 1;
    const tamperedOpaque = Buffer.from(JSON.stringify({ v: 1, ciphertext: `vault:v1:${raw.toString('base64')}` })).toString('base64');
    await f.vault.set(WRAPPED, encodeWrappedStateKey({ ...record, ciphertext: tamperedOpaque }));
    expect((await failure(loadProjectStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper }))).code).toBe('rejected');
    await f.vault.set(WRAPPED, Buffer.from('{"v":1,"provider":"vault-transit"'));
    expect((await failure(loadProjectStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper }))).code).toBe('damaged');
    expect(await f.vault.get(PLAIN)).toBeNull();

    const other = '1111111111111111';
    const copy = createFakeVault({ [`project/${other}/key/state.wrapped`]: encodeWrappedStateKey(record) });
    const copied = await failure(loadProjectStateKey({ vault: copy, projectId: other, wrapper: f.wrapper }));
    expect(copied.code).toBe('rejected');
    expect(await copy.get(`project/${other}/key/state`)).toBeNull();
  });

  it('with kms and only a plain key, keeps working on the plain key and asks for a migration', async () => {
    const original = randomBytes(32);
    const f = setup({ [PLAIN]: original });
    const warnings: string[] = [];
    const key = await loadProjectStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper, log: { warn: text => warnings.push(text) } });
    expect(key.equals(original)).toBe(true);
    expect(warnings.join('\n')).toContain('keysentry kms migrate');
    expect(f.fake.http.calls).toHaveLength(0);
    expect(await f.vault.get(WRAPPED)).toBeNull();
  });

  it('with kms and no key at all, creates the first key wrapped only', async () => {
    const f = setup();
    const key = await loadProjectStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper, now });
    expect(await f.vault.get(PLAIN)).toBeNull();
    expect(await f.vault.get(WRAPPED)).not.toBeNull();
    expect((await loadProjectStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper })).equals(key)).toBe(true);

    const offline = createFakeVault();
    const error = await failure(loadProjectStateKey({ vault: offline, projectId: PROJECT,
      wrapper: createVaultTransitWrapper(settings, { http: down, credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now }) }));
    expect(error.code).toBe('unreachable');
    expect(offline.dump().size).toBe(0);
  });

  it('refuses when the wrapped and plain copies are different keys', async () => {
    const f = await migrated();
    await f.vault.set(PLAIN, randomBytes(32));
    expect((await failure(loadProjectStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper }))).code).toBe('mismatch');
  });

  it('reads KEYSENTRY_STATE_KEY_WRAPPED from an environment vault', async () => {
    const f = await migrated();
    const encoded = (await f.vault.get(WRAPPED))!.toString('base64');
    const env = createEnvVault({});
    const key = await loadProjectStateKey({ vault: env, projectId: PROJECT, wrapper: f.wrapper, envWrapped: encoded });
    expect(key.equals(f.original)).toBe(true);
    expect((await failure(loadProjectStateKey({ vault: env, projectId: PROJECT, envWrapped: encoded }))).message).toContain('no kms section');
    expect((await failure(migrateStateKey({ vault: env, projectId: PROJECT, wrapper: f.wrapper }))).code).toBe('read-only');
    expect((await failure(loadProjectStateKey({ vault: env, projectId: PROJECT, wrapper: f.wrapper }))).code).toBe('read-only');
  });
});

describe('state key migration', () => {
  it('wraps, verifies, then removes the plain copy; a second run changes nothing', async () => {
    const original = randomBytes(32);
    const f = setup({ [PLAIN]: original });
    const result = await migrateStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper, now });
    expect(result.result).toBe('migrated');
    expect([...f.vault.dump().keys()]).toEqual([WRAPPED]);
    // encrypt, decrypt with another context (the one-time binding self-test, review L5), decrypt (verify the wrap),
    // decrypt (verify the saved copy)
    expect(f.fake.http.calls.map(call => call.url.split('/').slice(-2).join('/'))).toEqual(['keys/state', 'encrypt/state', 'keys/state', 'decrypt/state', 'decrypt/state', 'decrypt/state']);
    expect((await migrateStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper, now })).result).toBe('already-wrapped');
    expect((await loadProjectStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper })).equals(original)).toBe(true);
  });

  it.each(['wrapped-saved', 'plain-deleted'] as const)('is crash safe at %s', async point => {
    const original = randomBytes(32);
    const f = setup({ [PLAIN]: original });
    const crash = async (at: MigrationPoint) => { if (at === point) throw new Error('simulated crash'); };
    await expect(migrateStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper, now, checkpoint: crash })).rejects.toThrow('simulated crash');
    if (point === 'wrapped-saved') {
      expect([...f.vault.dump().keys()].sort()).toEqual([PLAIN, WRAPPED]);
      const warnings: string[] = [];
      const key = await loadProjectStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper, log: { warn: text => warnings.push(text) } });
      expect(key.equals(original)).toBe(true);
      expect(warnings.join('\n')).toContain('plain copy is still in the vault');
      expect((await migrateStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper, now })).result).toBe('finished');
    }
    expect([...f.vault.dump().keys()]).toEqual([WRAPPED]);
    expect((await loadProjectStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper })).equals(original)).toBe(true);
  });

  it('keeps the plain copy when the KMS fails or does not give the same key back', async () => {
    const original = randomBytes(32);
    const unreachable = setup({ [PLAIN]: original });
    const offline = createVaultTransitWrapper(settings, { http: down, credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now });
    expect((await failure(migrateStateKey({ vault: unreachable.vault, projectId: PROJECT, wrapper: offline, now }))).code).toBe('unreachable');
    expect([...unreachable.vault.dump().keys()]).toEqual([PLAIN]);

    const f = setup({ [PLAIN]: original });
    const liar: KeyWrapper = { provider: f.wrapper.provider, keyRef: f.wrapper.keyRef,
      wrap: (key, context) => f.wrapper.wrap(key, context), unwrap: async () => randomBytes(32) };
    const error = await failure(migrateStateKey({ vault: f.vault, projectId: PROJECT, wrapper: liar, now }));
    expect(error.code).toBe('invalid-response');
    expect([...f.vault.dump().keys()]).toEqual([PLAIN]);
    expect((await f.vault.get(PLAIN))!.equals(original)).toBe(true);
  });

  it('refuses to finish a migration whose two copies differ', async () => {
    const f = await migrated();
    await f.vault.set(PLAIN, randomBytes(32));
    expect((await failure(migrateStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper, now }))).code).toBe('mismatch');
    expect([...f.vault.dump().keys()].sort()).toEqual([PLAIN, WRAPPED]);
  });
});

describe('state key rotation and status', () => {
  it('rewraps under the latest key version', async () => {
    const f = await migrated();
    f.fake.state.versions.push(randomBytes(32));
    const result = await rotateStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper, now });
    expect(result).toMatchObject({ before: 'v1', after: 'v2' });
    expect((await loadProjectStateKey({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper })).equals(f.original)).toBe(true);
    expect((await failure(rotateStateKey({ vault: createFakeVault({ [PLAIN]: randomBytes(32) }), projectId: PROJECT, wrapper: f.wrapper }))).code).toBe('not-wrapped');
  });

  it('reports configuration, storage and a live unwrap check', async () => {
    const f = await migrated();
    const ok = await stateKeyStatus({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper });
    expect(ok).toMatchObject({ configured: { provider: 'vault-transit', keyRef: f.wrapper.keyRef },
      wrapped: { provider: 'vault-transit', keyRef: f.wrapper.keyRef, keyVersion: 'v1', matchesConfig: true }, plainCopy: false, check: { ok: true } });
    f.fake.state.sealed = true;
    const failed = await stateKeyStatus({ vault: f.vault, projectId: PROJECT, wrapper: f.wrapper });
    expect(failed.check.ok).toBe(false);
    expect(failed.check.message).toContain('unavailable');
    const unconfigured = await stateKeyStatus({ vault: f.vault, projectId: PROJECT });
    expect(unconfigured.check).toMatchObject({ ok: false });
    const notWrapped = await stateKeyStatus({ vault: createFakeVault({ [PLAIN]: randomBytes(32) }), projectId: PROJECT, wrapper: f.wrapper });
    expect(notWrapped).toMatchObject({ wrapped: null, plainCopy: true, check: { ok: false } });
  });
});

describe('watcher wrapped state key', () => {
  it('round-trips KEYSENTRY_STATE_KEY_WRAPPED and refuses tampering or another project', async () => {
    const f = setup();
    const stateKey = randomBytes(32);
    const encoded = await wrapWatcherStateKey({ wrapper: f.wrapper, projectId: PROJECT, stateKey, now });
    expect(encoded).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(Buffer.from(encoded, 'base64').toString()).not.toContain(stateKey.toString('base64'));
    expect((await unwrapWatcherStateKey({ wrapper: f.wrapper, projectId: PROJECT, encoded })).equals(stateKey)).toBe(true);
    expect((await failure(unwrapWatcherStateKey({ wrapper: f.wrapper, projectId: '1111111111111111', encoded }))).code).toBe('rejected');
    expect((await failure(unwrapWatcherStateKey({ wrapper: f.wrapper, projectId: PROJECT, encoded: `${encoded.slice(0, -4)}!!!!` }))).code).toBe('damaged');
    expect(stateKeyContext(PROJECT)).toBe('keysentry-state:v1:0123456789abcdef');
  });
});

describe('first start of a new project is serialized (review M1)', () => {
  /** Two views of one store, so the in-process vault identity cannot serialize anything by itself. */
  function sharedViews() {
    const store = createFakeVault();
    const view = (): typeof store => ({ ...store, get: name => store.get(name), set: (name, value) => store.set(name, value),
      delete: name => store.delete(name), list: prefix => store.list(prefix) });
    return { store, a: view(), b: view() };
  }
  /** The fake Vault Transit answers at once; add a round-trip delay so the two starts really overlap. */
  function slow(wrapper: KeyWrapper, ms = 25): KeyWrapper {
    const wait = () => new Promise(resolve => setTimeout(resolve, ms));
    return { provider: wrapper.provider, keyRef: wrapper.keyRef,
      async wrap(key, context) { await wait(); return wrapper.wrap(key, context); },
      async unwrap(blob, context) { await wait(); return wrapper.unwrap(blob, context); } };
  }

  it('two overlapping starts in one process end with one wrapped key that both use', async () => {
    const f = setup();
    const views = sharedViews();
    const wrapper = slow(f.wrapper);
    const first = loadProjectStateKey({ vault: views.a, projectId: PROJECT, wrapper, now });
    await new Promise(resolve => setTimeout(resolve, 10));
    const second = loadProjectStateKey({ vault: views.b, projectId: PROJECT, wrapper, now });
    const [a, b] = await Promise.all([first, second]);
    expect(a.equals(b)).toBe(true);
    const kept = await loadProjectStateKey({ vault: views.store, projectId: PROJECT, wrapper: f.wrapper, now });
    expect(kept.equals(a)).toBe(true);
    // Only one key was ever created and wrapped.
    expect(f.fake.http.callsTo('POST', /encrypt/)).toHaveLength(1);
  });

  it('a lock file held by another process makes a start wait, then use the key that process saved', async () => {
    const { mkdtemp, rm, writeFile, stat } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { withStateKeyLock } = await import('../../src/kms/lock.js');
    const dir = await mkdtemp(join(tmpdir(), 'ks-kms-lock-'));
    try {
      const lockPath = join(dir, 'state-key.lock');
      const f = setup();
      const views = sharedViews();
      // "Another process": a different in-process key, so only the lock file can serialize the two.
      let releaseOther!: () => void;
      const otherHolds = new Promise<void>(resolve => { releaseOther = resolve; });
      let otherKey: Buffer | undefined;
      const other = withStateKeyLock({ key: 'another-process', lockPath }, async () => {
        await otherHolds;
        otherKey = randomBytes(32);
        const record = await (await import('../../src/kms/index.js')).wrapStateKey(f.wrapper, otherKey, PROJECT, now);
        await views.a.set(WRAPPED, encodeWrappedStateKey(record));
      });
      await new Promise(resolve => setTimeout(resolve, 20));
      expect((await stat(lockPath)).isFile()).toBe(true);
      const start = loadProjectStateKey({ vault: views.b, projectId: PROJECT, wrapper: f.wrapper, now, lockPath });
      await new Promise(resolve => setTimeout(resolve, 50));
      expect(await views.store.get(WRAPPED)).toBeNull(); // the start is waiting, not creating its own key
      releaseOther();
      await other;
      expect((await start).equals(otherKey!)).toBe(true);
      await expect(stat(lockPath)).rejects.toMatchObject({ code: 'ENOENT' });

      // A lock left by a crashed process (its time no longer renewed) is taken over instead of blocking forever.
      await writeFile(lockPath, '{"pid":1}');
      const { utimes } = await import('node:fs/promises');
      const old = new Date(Date.now() - 120_000);
      await utimes(lockPath, old, old);
      const fresh = setup();
      const key = await loadProjectStateKey({ vault: createFakeVault(), projectId: PROJECT, wrapper: fresh.wrapper, now, lockPath });
      expect(key).toHaveLength(32);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it('gives up with a calm message while another live process keeps the lock', async () => {
    const { mkdtemp, rm, writeFile } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { withStateKeyLock } = await import('../../src/kms/lock.js');
    const dir = await mkdtemp(join(tmpdir(), 'ks-kms-lock-'));
    try {
      const lockPath = join(dir, 'state-key.lock');
      await writeFile(lockPath, '{"pid":1}');
      const error = await failure(withStateKeyLock({ key: 'waiting', lockPath, waitMs: 100 }, async () => 'never'));
      expect(error).toBeInstanceOf(KmsError);
      expect(error.code).toBe('busy');
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
});
