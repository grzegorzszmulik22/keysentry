import { randomBytes } from 'node:crypto';
import type { HttpRequest } from '../../src/types.js';
import { FakeHttp, json } from '../helpers/fake-http.js';
import { describe, expect, it } from 'vitest';
import { createVaultTransitWrapper } from '../../src/kms/index.js';
import { credentialSource, failure, fakeVaultTransit, now, secretFree, VAULT_ADDR } from './fakes.js';

const settings = { provider: 'vault-transit', address: VAULT_ADDR, mount: 'transit', keyName: 'state' } as const;
const CONTEXT = 'keysentry-state:v1:0123456789abcdef';
const TOKEN = 'hvs.vault-token-planted';

describe('Vault Transit key wrapper', () => {
  it('reads the key, then encrypts with associated_data for a non-derived AEAD key', async () => {
    const fake = fakeVaultTransit();
    const wrapper = createVaultTransitWrapper(settings, { http: fake.http, credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now });
    expect(wrapper.keyRef).toBe(`${VAULT_ADDR}/v1/transit/keys/state`);
    const dataKey = randomBytes(32);
    const wrapped = await wrapper.wrap(dataKey, CONTEXT);
    const [read, encrypt] = fake.http.calls;
    expect(read!.method).toBe('GET');
    expect(read!.url).toBe(`${VAULT_ADDR}/v1/transit/keys/state`);
    expect(read!.headers).toEqual({ 'X-Vault-Token': TOKEN });
    expect(encrypt!.method).toBe('POST');
    expect(encrypt!.url).toBe(`${VAULT_ADDR}/v1/transit/encrypt/state`);
    expect(encrypt!.headers).toEqual({ 'X-Vault-Token': TOKEN, 'Content-Type': 'application/json' });
    expect(JSON.parse(encrypt!.body!)).toEqual({ plaintext: dataKey.toString('base64'), associated_data: Buffer.from(CONTEXT).toString('base64') });
    expect(JSON.parse(wrapped.toString()).ciphertext).toMatch(/^vault:v1:/);

    expect((await wrapper.unwrap(wrapped, CONTEXT)).equals(dataKey)).toBe(true);
    const decrypt = fake.http.calls.at(-1)!;
    expect(decrypt.url).toBe(`${VAULT_ADDR}/v1/transit/decrypt/state`);
    expect(JSON.parse(decrypt.body!)).toEqual({ ciphertext: JSON.parse(wrapped.toString()).ciphertext, associated_data: Buffer.from(CONTEXT).toString('base64') });
  });

  it('sends the context as `context` for a derived key, with the namespace header and a custom mount', async () => {
    const fake = fakeVaultTransit({ derived: true, mount: 'kms-prod' });
    const wrapper = createVaultTransitWrapper({ ...settings, mount: 'kms-prod', namespace: 'admin/team-a' },
      { http: fake.http, credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now });
    expect(wrapper.keyRef).toBe(`${VAULT_ADDR}/v1/admin/team-a/kms-prod/keys/state`);
    const dataKey = randomBytes(32);
    const wrapped = await wrapper.wrap(dataKey, CONTEXT);
    const encrypt = fake.http.calls[1]!;
    expect(encrypt.url).toBe(`${VAULT_ADDR}/v1/kms-prod/encrypt/state`);
    expect(encrypt.headers).toEqual({ 'X-Vault-Token': TOKEN, 'X-Vault-Namespace': 'admin/team-a', 'Content-Type': 'application/json' });
    expect(JSON.parse(encrypt.body!)).toEqual({ plaintext: dataKey.toString('base64'), context: Buffer.from(CONTEXT).toString('base64') });
    expect((await wrapper.unwrap(wrapped, CONTEXT)).equals(dataKey)).toBe(true);
    expect((await failure(wrapper.unwrap(wrapped, 'keysentry-state:v1:fedcba9876543210'))).code).toBe('rejected');
  });

  it('refuses a key type that cannot bind the context, and never creates a missing key', async () => {
    const rsa = fakeVaultTransit({ type: 'rsa-4096' });
    const error = await failure(createVaultTransitWrapper(settings, { http: rsa.http, credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now }).wrap(randomBytes(32), CONTEXT));
    expect(error.code).toBe('unsupported');
    expect(rsa.http.callsTo('POST', /encrypt/)).toHaveLength(0);

    const missing = fakeVaultTransit();
    missing.state.exists = false;
    const gone = await failure(createVaultTransitWrapper(settings, { http: missing.http, credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now }).wrap(randomBytes(32), CONTEXT));
    expect(gone.code).toBe('key-unavailable');
    expect(missing.http.callsTo('POST', /encrypt/)).toHaveLength(0);
  });

  it('refuses a wrong context, tampering, a sealed Vault, a bad token and a missing token without echoing them', async () => {
    const fake = fakeVaultTransit();
    const wrapper = createVaultTransitWrapper(settings, { http: fake.http, credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now });
    const wrapped = await wrapper.wrap(randomBytes(32), CONTEXT);
    const wrong = await failure(wrapper.unwrap(wrapped, 'keysentry-state:v1:fedcba9876543210'));
    expect(wrong.code).toBe('rejected');
    const { ciphertext } = JSON.parse(wrapped.toString()) as { ciphertext: string };
    const body = Buffer.from(ciphertext.slice('vault:v1:'.length), 'base64'); body[20]! ^= 1;
    const tampered = await failure(wrapper.unwrap(Buffer.from(JSON.stringify({ v: 1, ciphertext: `vault:v1:${body.toString('base64')}` })), CONTEXT));
    expect(tampered.code).toBe('rejected');
    expect((await failure(wrapper.unwrap(Buffer.from(JSON.stringify({ v: 1, ciphertext: 'not-vault' })), CONTEXT))).code).toBe('rejected');
    fake.state.sealed = true;
    const sealed = await failure(wrapper.unwrap(wrapped, CONTEXT));
    expect(sealed.code).toBe('unavailable');
    fake.state.sealed = false;
    const badToken = await failure(createVaultTransitWrapper(settings, { http: fake.http, credentials: credentialSource({ VAULT_TOKEN: 'hvs.wrong-planted' }), now }).unwrap(wrapped, CONTEXT));
    expect(badToken.code).toBe('denied');
    const none = await failure(createVaultTransitWrapper(settings, { http: fake.http, credentials: credentialSource({}), now }).unwrap(wrapped, CONTEXT));
    expect(none.code).toBe('credentials');
    for (const error of [wrong, tampered, sealed, badToken, none]) expect(secretFree(error, [TOKEN, 'hvs.wrong-planted'])).toBe(true);
  });
});

describe('Vault Transit binding cannot disappear silently (review L5)', () => {
  /** A Vault that drops associated_data (an older release, or something in front of it), with or without a warning. */
  function ignoringVault(warn: boolean): FakeHttp {
    const inner = fakeVaultTransit();
    const http = new FakeHttp();
    const strip = (req: HttpRequest): HttpRequest => {
      const body = JSON.parse(req.body!) as Record<string, unknown>;
      delete body.associated_data;
      return { ...req, body: JSON.stringify(body) };
    };
    http.on('POST', /\/v1\/transit\/(?:encrypt|decrypt)\/state$/, async req => {
      const response = await inner.http.request(strip(req));
      if (!warn || response.status !== 200) return response;
      return json(200, { ...response.json<Record<string, unknown>>(), warnings: ['Endpoint ignored these unrecognized parameters: [associated_data]'] });
    });
    http.on('GET', /.*/, req => inner.http.request(req));
    return http;
  }

  it('refuses a wrap when Vault warns that it ignored the binding parameter', async () => {
    const wrapper = createVaultTransitWrapper(settings, { http: ignoringVault(true), credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now });
    const error = await failure(wrapper.wrap(randomBytes(32), CONTEXT));
    expect(error.code).toBe('unsupported');
    expect(error.message).toContain('context binding');
    expect(error.message).not.toContain('unrecognized');
  });

  it('refuses a wrap when Vault drops the binding without a warning (one self-test per wrapper)', async () => {
    const wrapper = createVaultTransitWrapper(settings, { http: ignoringVault(false), credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now });
    expect((await failure(wrapper.wrap(randomBytes(32), CONTEXT))).code).toBe('unsupported');
  });

  it('a binding Vault passes the self-test once and is not asked again', async () => {
    const fake = fakeVaultTransit();
    const wrapper = createVaultTransitWrapper(settings, { http: fake.http, credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now });
    await wrapper.wrap(randomBytes(32), CONTEXT);
    await wrapper.wrap(randomBytes(32), CONTEXT);
    expect(fake.http.callsTo('POST', /decrypt/)).toHaveLength(1);
    const check = JSON.parse(fake.http.callsTo('POST', /decrypt/)[0]!.body!) as { associated_data: string };
    expect(Buffer.from(check.associated_data, 'base64').toString()).not.toBe(CONTEXT);
  });
});

it('names a refusing network setting instead of reporting the KMS as unreachable (review H1)', async () => {
  const { CaBundleError, TransportConfigError, createUnavailableTransport } = await import('../../src/net/transport.js');
  for (const problem of [new CaBundleError('network.caFile could not be read. Check the path (relative to the project) and its permissions.'),
    new TransportConfigError('network.proxy is not a valid proxy URL. Use http://host:port or https://host:port.')]) {
    const wrapper = createVaultTransitWrapper(settings, { http: createUnavailableTransport(problem), credentials: credentialSource({ VAULT_TOKEN: TOKEN }), now });
    const error = await failure(wrapper.unwrap(Buffer.from(JSON.stringify({ v: 1, ciphertext: 'vault:v1:AAAA' })), CONTEXT));
    expect(error.code).toBe('network');
    expect(error.message).toBe(`Vault Transit was not contacted because the network settings cannot be used: ${problem.message}`);
    expect(error.message).not.toContain('Could not reach');
  }
});
