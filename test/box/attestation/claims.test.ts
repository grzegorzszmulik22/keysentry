import { describe, expect, it } from 'vitest';
import { checkClaims } from '../../../src/box/attestation/claims.js';
import { passingClaims, TEST_BOX_NONCE, TEST_CHALLENGE_NONCE, TEST_NOW, TEST_POLICY } from './helpers.js';

const expected = [TEST_BOX_NONCE, TEST_CHALLENGE_NONCE];
function run(change: (claims: any) => void = () => {}) {
  const claims = passingClaims();
  change(claims);
  return checkClaims(claims, TEST_POLICY, expected, TEST_NOW);
}

describe('Confidential Space claims', () => {
  it('accepts production claims and reports each policy decision', () => {
    const checks = run();
    expect(checks.every((check) => check.ok)).toBe(true);
    expect(checks.map((check) => check.name)).toEqual([
      'issuer', 'audience', 'time', 'nonce-box-key', 'nonce-challenge', 'nonce-set',
      'secure-boot', 'debug', 'software', 'hardware', 'support-stable', 'memory-monitoring',
      'image-digest', 'env-override', 'cmd-override', 'project', 'service-account',
    ]);
    expect(checks.every((check) => check.detail.length > 0)).toBe(true);
  });

  it.each<[string, string, (claims: any) => void]>([
    ['issuer', 'wrong issuer', (c) => { c.iss += '/'; }],
    ['audience', 'wrong audience', (c) => { c.aud = 'other'; }],
    ['audience', 'malformed audiences', (c) => { c.aud = [TEST_POLICY.audience, 1]; }],
    ['time', 'expired token', (c) => { c.exp = TEST_NOW.getTime() / 1000 - 61; }],
    ['time', 'future not before', (c) => { c.nbf = TEST_NOW.getTime() / 1000 + 61; }],
    ['time', 'future issued at', (c) => { c.iat = TEST_NOW.getTime() / 1000 + 61; }],
    ['time', 'old issued at before expiry', (c) => { c.iat = TEST_NOW.getTime() / 1000 - 301; }],
    ['time', 'missing issued at', (c) => { delete c.iat; }],
    ['time', 'missing expiry', (c) => { delete c.exp; }],
    ['time', 'string date', (c) => { c.iat = String(c.iat); }],
    ['time', 'fractional date', (c) => { c.iat += 0.5; }],
    ['nonce-box-key', 'swapped box key', (c) => { c.eat_nonce = ['C'.repeat(42) + 'A', TEST_CHALLENGE_NONCE]; }],
    ['nonce-challenge', 'replayed challenge', (c) => { c.eat_nonce = [TEST_BOX_NONCE, 'D'.repeat(42) + 'A']; }],
    ['nonce-set', 'missing nonce', (c) => { c.eat_nonce = TEST_BOX_NONCE; }],
    ['nonce-set', 'extra nonce', (c) => { c.eat_nonce.push('E'.repeat(42) + 'A'); }],
    ['nonce-set', 'non-string nonce', (c) => { c.eat_nonce.push(3); }],
    ['secure-boot', 'disabled secure boot', (c) => { c.secboot = false; }],
    ['secure-boot', 'missing secure boot', (c) => { delete c.secboot; }],
    ['debug', 'debug image', (c) => { c.dbgstat = 'enabled'; }],
    ['debug', 'alternate debug spelling', (c) => { c.dbgstat = 'enable'; }],
    ['debug', 'non-production disabled status', (c) => { c.dbgstat = 'disabled'; }],
    ['software', 'revoked software', (c) => { c.swname = 'GCE'; }],
    ['hardware', 'shielded VM', (c) => { c.hwmodel = 'GCP_SHIELDED_VM'; }],
    ['hardware', 'SEV ES', (c) => { c.hwmodel = 'GCP_AMD_SEV_ES'; }],
    ['hardware', 'unknown hardware', (c) => { c.hwmodel = 'GCP_AMD_SEV_SNP'; }],
    ['hardware', 'ITA hardware name', (c) => { c.hwmodel = 'INTEL_TDX'; }],
    ['support-stable', 'latest alone', (c) => { c.submods.confidential_space.support_attributes = ['LATEST']; }],
    ['support-stable', 'missing support', (c) => { delete c.submods.confidential_space.support_attributes; }],
    ['memory-monitoring', 'memory monitoring on', (c) => { c.submods.confidential_space.monitoring_enabled.memory = true; }],
    ['memory-monitoring', 'malformed memory setting', (c) => { c.submods.confidential_space.monitoring_enabled.memory = 'false'; }],
    ['image-digest', 'unlisted image', (c) => { c.submods.container.image_digest = 'sha256:' + 'b'.repeat(64); }],
    ['env-override', 'environment override', (c) => { c.submods.container.env_override = { TOKEN: 'planted-private-value' }; }],
    ['env-override', 'malformed environment overrides', (c) => { c.submods.container.env_override = []; }],
    ['cmd-override', 'command override', (c) => { c.submods.container.cmd_override = ['/bin/sh']; }],
    ['cmd-override', 'malformed command override', (c) => { c.submods.container.cmd_override = ''; }],
    ['project', 'other project', (c) => { c.submods.gce.project_id = 'other'; }],
    ['service-account', 'other service account', (c) => { c.google_service_accounts = ['other@example.test']; }],
    ['service-account', 'mixed service accounts', (c) => { c.google_service_accounts.push('other@example.test'); }],
    ['service-account', 'empty service accounts', (c) => { c.google_service_accounts = []; }],
  ])('rejects %s: %s', (name, _description, change) => {
    const checks = run(change);
    expect(checks.find((check) => check.name === name)?.ok).toBe(false);
    expect(JSON.stringify(checks)).not.toContain('planted-private-value');
  });

  it('accepts either supported hardware only when allowed by the policy', () => {
    expect(run((c) => { c.hwmodel = 'GCP_AMD_SEV'; }).every((c) => c.ok)).toBe(true);
    const claims = passingClaims();
    claims.hwmodel = 'GCP_AMD_SEV';
    const checks = checkClaims(claims, { ...TEST_POLICY, hardwareModels: ['GCP_INTEL_TDX'] }, expected, TEST_NOW);
    expect(checks.find((c) => c.name === 'hardware')?.ok).toBe(false);
  });

  it('accepts an audience array containing the expected audience', () => {
    expect(run((c) => { c.aud = ['other', TEST_POLICY.audience]; }).every((c) => c.ok)).toBe(true);
  });

  it('compares the nonce set without depending on token order', () => {
    expect(run((c) => { c.eat_nonce.reverse(); }).every((c) => c.ok)).toBe(true);
  });

  it('allows base-image environment/arguments and empty override declarations', () => {
    expect(run((c) => {
      c.submods.container.env = { PATH: '/usr/bin' };
      c.submods.container.args = ['/box'];
      c.submods.container.env_override = {};
      c.submods.container.cmd_override = [];
      c.submods.confidential_space.support_attributes = ['STABLE'];
    }).every((c) => c.ok)).toBe(true);
  });

  it('accepts an absent memory flag, as specified in the facts recipe', () => {
    expect(run((c) => { delete c.submods.confidential_space.monitoring_enabled; }).every((c) => c.ok)).toBe(true);
  });

  it('honors exact time boundaries and applies defaults when omitted at runtime', () => {
    const claims = passingClaims();
    claims.iat = TEST_NOW.getTime() / 1000 - 300;
    claims.exp = TEST_NOW.getTime() / 1000 - 60;
    claims.nbf = claims.iat;
    const policy = { ...TEST_POLICY, clockSkewSeconds: undefined, maxTokenAgeSeconds: undefined };
    expect(checkClaims(claims, policy as any, expected, TEST_NOW).every((c) => c.ok)).toBe(true);
    claims.iat = TEST_NOW.getTime() / 1000 + 60;
    claims.nbf = claims.iat;
    claims.exp = claims.iat + 300;
    expect(checkClaims(claims, TEST_POLICY, expected, TEST_NOW).every((c) => c.ok)).toBe(true);
  });

  it.each([[], [TEST_BOX_NONCE], [TEST_BOX_NONCE, TEST_BOX_NONCE], ['x', TEST_CHALLENGE_NONCE]].map((nonces) => ({ nonces })))(
    'refuses an incomplete or malformed expected session binding %#', ({ nonces }) => {
      const checks = checkClaims(passingClaims(), TEST_POLICY, nonces, TEST_NOW);
      expect(checks.filter((c) => c.name.startsWith('nonce-')).every((c) => !c.ok)).toBe(true);
    },
  );

  it.each([null, [], 'text', { submods: { container: null, confidential_space: [], gce: 'other' } }].map((claims) => ({ claims })))(
    'handles missing and malformed nested claims without throwing %#', ({ claims }) => {
      const checks = checkClaims(claims, TEST_POLICY, expected, TEST_NOW);
      expect(checks.some((c) => !c.ok)).toBe(true);
    },
  );
});
