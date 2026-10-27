import { expect, test } from 'vitest';
import { createFakeVault } from '../helpers/fake-vault.js';
import { PROVIDER_CREDENTIALS } from '../../src/providers/index.js';
import { CREDENTIAL_NAMES, createCredentialSource, credentialVaultName, importFromEnv } from '../../src/vault/index.js';

test('credential names include hosting tokens then deduplicated provider names', () => {
  expect(CREDENTIAL_NAMES).toEqual([...new Set([
    'RAILWAY_TOKEN', 'RAILWAY_PROJECT_TOKEN', 'VERCEL_TOKEN', 'RENDER_API_KEY', 'FLY_API_TOKEN', 'GITHUB_TOKEN',
    ...Object.values(PROVIDER_CREDENTIALS).flat(),
  ])]);
});
test('read role prefers @read; write role never returns the @read token', async () => {
  const vault = createFakeVault({ 'cred/NAME': Buffer.from('vault-write'), 'cred/NAME@read': Buffer.from('vault-read') });
  const source = createCredentialSource(vault, { NAME: 'env-write' });
  expect(await source.get('NAME', 'read')).toEqual({ value: 'vault-read', source: 'vault' });
  expect(await source.get('NAME', 'write')).toEqual({ value: 'vault-write', source: 'vault' });
  await vault.delete('cred/NAME');
  expect(await source.get('NAME', 'write')).toEqual({ value: 'env-write', source: 'env' });
  expect(await createCredentialSource(vault, {}).get('NAME', 'write')).toBeNull();
  await vault.delete('cred/NAME@read');
  expect(await source.get('NAME', 'read')).toEqual({ value: 'env-write', source: 'env' });
  expect(credentialVaultName('NAME', 'read')).toBe('cred/NAME@read');
  expect(credentialVaultName('NAME', 'write')).toBe('cred/NAME');
});
test('read role falls back to base vault token before environment', async () => {
  const source = createCredentialSource(createFakeVault({ 'cred/NAME': Buffer.from('base') }), { NAME: 'environment' });
  expect(await source.get('NAME', 'read')).toEqual({ value: 'base', source: 'vault' });
});
test('importFromEnv stores present credentials and returns their names', async () => {
  const vault = createFakeVault();
  expect(await importFromEnv(vault, { RAILWAY_TOKEN: 'token', OPENAI_ADMIN_KEY: 'admin', VERCEL_TOKEN: '', UNRELATED: 'skip' })).toEqual(['RAILWAY_TOKEN', 'OPENAI_ADMIN_KEY']);
  expect((await vault.get('cred/RAILWAY_TOKEN'))!.toString()).toBe('token');
  expect(await vault.get('cred/UNRELATED')).toBeNull();
  expect(await importFromEnv(vault, { CUSTOM: 'custom' }, ['CUSTOM'])).toEqual(['CUSTOM']);
});
