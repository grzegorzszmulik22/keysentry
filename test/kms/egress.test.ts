import { describe, expect, it } from 'vitest';
import { createKeyWrapper, createKmsHttp, kmsEgressRules, KmsError } from '../../src/kms/index.js';
import { EgressBlockedError } from '../../src/net/index.js';
import { FakeHttp, json, text } from '../helpers/fake-http.js';
import { credentialSource, failure, now } from './fakes.js';

const aws = { provider: 'aws-kms', keyId: 'arn:aws:kms:eu-central-1:111122223333:key/abcd', region: 'eu-central-1' } as const;
const gcp = { provider: 'gcp-kms', keyName: 'projects/acme-prod-123/locations/global/keyRings/r/cryptoKeys/k' } as const;
const azure = { provider: 'azure-key-vault', vaultUrl: 'https://Acme-Keys.vault.azure.net/', keyName: 'state' } as const;
const vault = { provider: 'vault-transit', address: 'https://vault.acme.example/', mount: 'transit', keyName: 'state' } as const;

describe('KMS egress', () => {
  it('allows exactly the hosts each provider needs', () => {
    expect(kmsEgressRules(aws).map(rule => rule.host)).toEqual(['kms.eu-central-1.amazonaws.com']);
    expect(kmsEgressRules(gcp).map(rule => rule.host)).toEqual(['cloudkms.googleapis.com', 'oauth2.googleapis.com']);
    expect(kmsEgressRules(azure).map(rule => rule.host)).toEqual(['acme-keys.vault.azure.net', 'login.microsoftonline.com']);
    expect(kmsEgressRules(vault).map(rule => rule.host)).toEqual(['vault.acme.example']);
    for (const settings of [aws, gcp, azure, vault]) for (const rule of kmsEgressRules(settings)) expect(rule.purpose).toMatch(/configured/);
  });

  it('blocks every other host, records only metadata, and refuses redirects', async () => {
    const transport = new FakeHttp()
      .on('POST', /^https:\/\/kms\.eu-central-1\.amazonaws\.com\/$/, () => text(307, '', { location: 'https://kms.eu-central-1.amazonaws.com/other' }))
      .on('GET', /evil/, () => json(200, {}));
    const receipts: unknown[] = [];
    const http = createKmsHttp(transport, aws, { receipt: { record: async entry => { receipts.push(entry); }, summarize: async () => [] } });
    await expect(http.request({ method: 'GET', url: 'https://evil.example/' })).rejects.toBeInstanceOf(EgressBlockedError);
    expect(transport.calls).toHaveLength(0);
    expect(receipts).toEqual([expect.objectContaining({ host: 'evil.example', allowed: false })]);

    // A wrapper on the guarded client turns a redirect into a fixed failure and never follows it.
    const wrapper = createKeyWrapper(aws, { http, credentials: credentialSource({ AWS_ACCESS_KEY_ID: 'AKIAEXAMPLEPLANTED01', AWS_SECRET_ACCESS_KEY: 'planted' }), now });
    const error = await failure(wrapper.wrap(Buffer.alloc(32, 1), 'keysentry-state:v1:0123456789abcdef'));
    expect(error).toBeInstanceOf(KmsError);
    expect(transport.calls.map(call => call.url)).toEqual(['https://kms.eu-central-1.amazonaws.com/']);
    expect(JSON.stringify(receipts)).not.toContain('planted');
  });

  it('turns a blocked host into a fixed message', async () => {
    const http = createKmsHttp(new FakeHttp(), vault);
    // A wrapper for another Vault address cannot use this guarded client.
    const other = createKeyWrapper({ ...vault, address: 'https://other-vault.example/' }, { http, credentials: credentialSource({ VAULT_TOKEN: 'hvs.planted' }), now });
    const error = await failure(other.wrap(Buffer.alloc(32, 1), 'keysentry-state:v1:0123456789abcdef'));
    expect(error).toMatchObject({ code: 'blocked' });
    expect(error.message).not.toContain('other-vault');
  });
});
