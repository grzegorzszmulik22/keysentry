import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyAttestation } from '../../../src/box/attestation/index.js';
import { createJwksFetcher } from '../../../src/box/attestation/jwks.js';
import { FakeHttp, json } from '../../helpers/fake-http.js';
import { createTokenFactory, passingClaims, TEST_BOX_NONCE, TEST_CHALLENGE_NONCE, TEST_NOW, TEST_POLICY } from './helpers.js';

const factory = createTokenFactory();
const input = () => ({
  token: factory.sign(), jwks: async () => [factory.jwk], policy: TEST_POLICY,
  expectedNonces: [TEST_BOX_NONCE, TEST_CHALLENGE_NONCE], now: TEST_NOW,
});
function failed(result: Awaited<ReturnType<typeof verifyAttestation>>, name: string) {
  expect(result.ok).toBe(false);
  expect(result.checks.find((check) => check.name === name)?.ok).toBe(false);
  expect(result.checks.every((check) => typeof check.ok === 'boolean' && check.detail.length > 0)).toBe(true);
}

describe('attestation verification', () => {
  it('verifies an emulator token before returning bound claims and box key hash', async () => {
    const result = await verifyAttestation(input());
    expect(result.ok).toBe(true);
    expect(result.checks.every((check) => check.ok)).toBe(true);
    expect(result.claims).toEqual(passingClaims());
    expect(result.boxKeyHash).toBe(TEST_BOX_NONCE);
  });

  it.each<[string, Record<string, unknown>]>([
    ['alg none', { alg: 'none' }], ['alg HS256', { alg: 'HS256' }],
    ['alg PS256', { alg: 'PS256' }], ['alg lowercase', { alg: 'rs256' }],
    ['typ absent', { typ: undefined }], ['typ lowercase', { typ: 'jwt' }],
    ['kid absent', { kid: undefined }], ['kid empty', { kid: '' }],
    ['kid non-string', { kid: 42 }], ['critical extension', { crit: ['custom'] }],
    ['unencoded payload', { b64: false }],
  ])('rejects %s before fetching a key', async (_name, header) => {
    let calls = 0;
    const result = await verifyAttestation({ ...input(), token: factory.sign(undefined, header),
      jwks: async () => { calls++; return [factory.jwk]; } });
    failed(result, 'jwt-header');
    expect(calls).toBe(0);
    expect(result.claims).toBeNull();
    expect(result.boxKeyHash).toBeNull();
  });

  it('refetches once for an unknown kid, then accepts the rotated key', async () => {
    const calls: (boolean | undefined)[] = [];
    const result = await verifyAttestation({ ...input(), jwks: async (force?: boolean) => {
      calls.push(force);
      return calls.length === 1 ? [{ ...factory.jwk, kid: 'old-key' }] : [factory.jwk];
    } });
    expect(result.ok).toBe(true);
    expect(calls).toEqual([undefined, true]);
  });

  it('fails after exactly one refetch when the kid stays unknown', async () => {
    let calls = 0;
    const result = await verifyAttestation({ ...input(), jwks: async () => {
      calls++; return [{ ...factory.jwk, kid: 'old-key' }];
    } });
    failed(result, 'signing-key');
    expect(calls).toBe(2);
  });

  it('forces a real refresh through an unexpired JWKS cache', async () => {
    let calls = 0;
    const http = new FakeHttp().on('GET', /.*/, () => {
      calls++;
      return json(200, { keys: [{ ...factory.jwk, kid: calls === 1 ? 'old-key' : 'test-key' }] },
        { 'cache-control': 'max-age=3600' });
    });
    const jwks = createJwksFetcher(http, { now: () => TEST_NOW });
    await jwks();
    expect((await verifyAttestation({ ...input(), jwks })).ok).toBe(true);
    expect(http.calls).toHaveLength(2);
  });

  it('fails closed when fetching fails and does not return upstream error text', async () => {
    const result = await verifyAttestation({ ...input(), jwks: async () => { throw new Error('planted-private-value'); } });
    failed(result, 'signing-key');
    expect(JSON.stringify(result)).not.toContain('planted-private-value');
  });

  it('fails closed when the forced key rotation fetch fails', async () => {
    let calls = 0;
    const result = await verifyAttestation({ ...input(), jwks: async () => {
      if (++calls === 2) throw new Error('upstream');
      return [];
    } });
    failed(result, 'signing-key');
    expect(calls).toBe(2);
  });

  it('rejects ambiguous duplicate kids supplied by an injected fetcher', async () => {
    failed(await verifyAttestation({ ...input(), jwks: async () => [factory.jwk, factory.jwk] }), 'signing-key');
  });

  it('rejects a signature by another key and withholds all unverified claims', async () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const [h, p] = factory.sign().split('.');
    const token = `${h}.${p}.${sign('RSA-SHA256', Buffer.from(`${h}.${p}`), privateKey).toString('base64url')}`;
    const result = await verifyAttestation({ ...input(), token });
    failed(result, 'signature');
    expect(result.claims).toBeNull();
    expect(result.boxKeyHash).toBeNull();
    expect(result.checks.every((check) => check.name.startsWith('jwt-') || check.name === 'signing-key' || !check.ok)).toBe(true);
  });

  it('rejects tampered payload bytes', async () => {
    const [h, , s] = factory.sign().split('.');
    const payload = Buffer.from(JSON.stringify({ ...passingClaims(), secboot: false })).toString('base64url');
    failed(await verifyAttestation({ ...input(), token: `${h}.${payload}.${s}` }), 'signature');
  });

  it('rejects a malformed JWT with all checks available for display', async () => {
    const result = await verifyAttestation({ ...input(), token: 'invalid' });
    failed(result, 'jwt-format');
    expect(result.checks.map((check) => check.name)).toContain('nonce-challenge');
    expect(result.checks.map((check) => check.name)).toContain('service-account');
    expect(result.checks.every((check) => !check.ok)).toBe(true);
  });

  it.each<[string, (claims: any) => void]>([
    ['issuer', (c) => { c.iss = 'other'; }],
    ['audience', (c) => { c.aud = 'other'; }],
    ['time', (c) => { c.iat = TEST_NOW.getTime() / 1000 - 301; }],
    ['nonce-box-key', (c) => { c.eat_nonce[0] = createHash('sha256').update('other box').digest('base64url'); }],
    ['nonce-challenge', (c) => { c.eat_nonce[1] = createHash('sha256').update('prior session').digest('base64url'); }],
    ['nonce-set', (c) => { c.eat_nonce.push('extra nonce'); }],
    ['debug', (c) => { c.dbgstat = 'enabled'; }],
    ['support-stable', (c) => { c.submods.confidential_space.support_attributes = ['LATEST']; }],
    ['hardware', (c) => { c.hwmodel = 'GCP_SHIELDED_VM'; }],
    ['memory-monitoring', (c) => { c.submods.confidential_space.monitoring_enabled.memory = true; }],
    ['env-override', (c) => { c.submods.container.env_override = { EXAMPLE: 'value' }; }],
    ['cmd-override', (c) => { c.submods.container.cmd_override = ['other']; }],
    ['image-digest', (c) => { c.submods.container.image_digest = 'sha256:' + 'c'.repeat(64); }],
    ['project', (c) => { c.submods.gce.project_id = 'other'; }],
    ['service-account', (c) => { c.google_service_accounts = ['other@example.test']; }],
  ])('rejects an authentically signed token failing %s', async (name, change) => {
    const claims = passingClaims();
    change(claims);
    const result = await verifyAttestation({ ...input(), token: factory.sign(claims) });
    failed(result, name);
    expect(result.checks.find((check) => check.name === 'signature')?.ok).toBe(true);
    expect(result.boxKeyHash).toBeNull();
  });

  it('verifies a PKI token offline using the pinned test root', async () => {
    let calls = 0;
    const result = await verifyAttestation({ ...input(), token: factory.sign(undefined, { x5c: factory.x5c }),
      root: factory.root, jwks: async () => { calls++; throw new Error('must remain offline'); } });
    expect(result.ok).toBe(true);
    expect(calls).toBe(0);
  });

  it('does not fall back to JWKS for an untrusted PKI chain', async () => {
    let calls = 0;
    const result = await verifyAttestation({ ...input(), token: factory.sign(undefined, { x5c: factory.x5c }),
      jwks: async () => { calls++; return [factory.jwk]; } });
    failed(result, 'signing-key');
    expect(calls).toBe(0);
  });

  it('does not fall back to JWKS for a malformed x5c header', async () => {
    const result = await verifyAttestation({ ...input(), token: factory.sign(undefined, { x5c: null }) });
    failed(result, 'signing-key');
  });

  it('ignores untrusted remote-key URLs in a signed JWT header', async () => {
    expect((await verifyAttestation({ ...input(), token: factory.sign(undefined,
      { jku: 'https://other.test/keys', x5u: 'https://other.test/cert' }) })).ok).toBe(true);
  });
});
