import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createAzureKeyVaultWrapper } from '../../src/kms/index.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { AZURE_TENANT, AZURE_VAULT, credentialSource, failure, fakeAzureKeyVault, now, rotateAzure, secretFree, sha256 } from './fakes.js';

const settings = { provider: 'azure-key-vault', vaultUrl: `${AZURE_VAULT}/`, keyName: 'state-key' } as const;
const CONTEXT = 'keysentry-state:v1:0123456789abcdef';
const SECRET = 'azure-client-secret-planted';
const credentials = () => credentialSource({ AZURE_TENANT_ID: AZURE_TENANT, AZURE_CLIENT_ID: 'app-client-id', AZURE_CLIENT_SECRET: SECRET });

describe('Azure Key Vault key wrapper', () => {
  it('gets a client-credentials token, resolves the latest version and wraps sha256(context) || key with RSA-OAEP-256', async () => {
    const fake = fakeAzureKeyVault();
    const wrapper = createAzureKeyVaultWrapper(settings, { http: fake.http, credentials: credentials(), now });
    expect(wrapper.keyRef).toBe(`${AZURE_VAULT}/keys/state-key`);
    const dataKey = randomBytes(32);
    const wrapped = await wrapper.wrap(dataKey, CONTEXT);
    const [token, describeKey, wrap] = fake.http.calls;
    expect(token!.url).toBe(`https://login.microsoftonline.com/${AZURE_TENANT}/oauth2/v2.0/token`);
    expect(token!.headers).toEqual({ 'Content-Type': 'application/x-www-form-urlencoded' });
    expect(Object.fromEntries(new URLSearchParams(token!.body))).toEqual({
      client_id: 'app-client-id', scope: 'https://vault.azure.net/.default', client_secret: SECRET, grant_type: 'client_credentials' });
    expect(describeKey!.method).toBe('GET');
    expect(describeKey!.url).toBe(`${AZURE_VAULT}/keys/state-key?api-version=2025-07-01`);
    expect(describeKey!.headers).toEqual({ Authorization: 'Bearer eyJ0eXAi.azure-issued-1' });
    expect(wrap!.url).toBe(`${AZURE_VAULT}/keys/state-key/${fake.state.latest}/wrapkey?api-version=2025-07-01`);
    expect(wrap!.headers).toEqual({ Authorization: 'Bearer eyJ0eXAi.azure-issued-1', 'Content-Type': 'application/json' });
    const body = JSON.parse(wrap!.body!);
    expect(Object.keys(body)).toEqual(['alg', 'value']);
    expect(body.alg).toBe('RSA-OAEP-256');
    expect(Buffer.from(body.value, 'base64url').equals(Buffer.concat([sha256(CONTEXT), dataKey]))).toBe(true);
    expect(JSON.parse(wrapped.toString()).version).toBe(fake.state.latest);

    const unwrapped = await wrapper.unwrap(wrapped, CONTEXT);
    expect(unwrapped.equals(dataKey)).toBe(true);
    expect(fake.http.calls.at(-1)!.url).toBe(`${AZURE_VAULT}/keys/state-key/${fake.state.latest}/unwrapkey?api-version=2025-07-01`);
  });

  it('unwraps with the version it wrapped under after the key rotates, and uses a pinned version without a lookup', async () => {
    const fake = fakeAzureKeyVault();
    const wrapper = createAzureKeyVaultWrapper(settings, { http: fake.http, credentials: credentials(), now });
    const first = fake.state.latest;
    const wrapped = await wrapper.wrap(randomBytes(32), CONTEXT);
    rotateAzure(fake);
    await wrapper.unwrap(wrapped, CONTEXT);
    expect(fake.http.calls.at(-1)!.url).toContain(`/keys/state-key/${first}/unwrapkey`);

    const pinned = fakeAzureKeyVault();
    const pinnedWrapper = createAzureKeyVaultWrapper({ ...settings, keyVersion: pinned.state.latest }, { http: pinned.http, credentials: credentials(), now });
    await pinnedWrapper.wrap(randomBytes(32), CONTEXT);
    expect(pinned.http.callsTo('GET', /keys/)).toHaveLength(0);
  });

  it('refuses a wrong context by its bound prefix, a tampered blob, and a disabled key', async () => {
    const fake = fakeAzureKeyVault();
    const wrapper = createAzureKeyVaultWrapper(settings, { http: fake.http, credentials: credentials(), now });
    const dataKey = randomBytes(32);
    const wrapped = await wrapper.wrap(dataKey, CONTEXT);
    const wrong = await failure(wrapper.unwrap(wrapped, 'keysentry-state:v1:fedcba9876543210'));
    expect(wrong.code).toBe('rejected');
    const envelope = JSON.parse(wrapped.toString());
    const blob = Buffer.from(envelope.ciphertext, 'base64url'); blob[10]! ^= 1;
    const tampered = await failure(wrapper.unwrap(Buffer.from(JSON.stringify({ ...envelope, ciphertext: blob.toString('base64url') })), CONTEXT));
    expect(tampered.code).toBe('rejected');
    expect((await failure(wrapper.unwrap(Buffer.from(JSON.stringify({ ...envelope, version: 'not-a-version' })), CONTEXT))).code).toBe('rejected');
    fake.state.disabled = true;
    const disabledUnwrap = await failure(wrapper.unwrap(wrapped, CONTEXT));
    expect(disabledUnwrap.code).toBe('denied');
    const disabledWrap = await failure(wrapper.wrap(randomBytes(32), CONTEXT));
    expect(disabledWrap.code).toBe('key-unavailable');
    for (const error of [wrong, tampered, disabledUnwrap, disabledWrap]) {
      expect(secretFree(error, [SECRET, dataKey.toString('base64'), dataKey.toString('base64url'), 'eyJ0eXAi'])).toBe(true);
    }
  });

  it('refuses a vault address outside Key Vault, missing credentials and a refused sign-in', async () => {
    const http = new FakeHttp();
    expect(() => createAzureKeyVaultWrapper({ ...settings, vaultUrl: 'https://keys.example.com/' }, { http, credentials: credentials(), now })).toThrow(/Azure Key Vault address/);
    expect((await failure(createAzureKeyVaultWrapper(settings, { http, credentials: credentialSource({}), now }).wrap(randomBytes(32), CONTEXT))).code).toBe('credentials');
    expect(http.calls).toHaveLength(0);
    const fake = fakeAzureKeyVault();
    const refused = await failure(createAzureKeyVaultWrapper(settings, { http: fake.http,
      credentials: credentialSource({ AZURE_TENANT_ID: AZURE_TENANT, AZURE_CLIENT_ID: 'app-client-id', AZURE_CLIENT_SECRET: 'wrong-secret-planted' }), now }).wrap(randomBytes(32), CONTEXT));
    expect(refused.code).toBe('denied');
    expect(secretFree(refused, ['wrong-secret-planted'])).toBe(true);
  });
});
