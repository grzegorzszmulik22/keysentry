import { createHash } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { runDoctor, TOKEN_CAPABILITIES } from '../../src/doctor/index.js';
import { createCredentialSource } from '../../src/vault/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { FakeHttp, json, text } from '../helpers/fake-http.js';

type Input = Parameters<typeof runDoctor>[0];

function input(overrides: Partial<Input> = {}): Input {
  const vault = overrides.vault ?? createFakeVault();
  const env = overrides.env ?? {};
  return {
    vault, env, credentials: createCredentialSource(vault, env), enabledHosts: [],
    nodeVersion: '22.23.4', integrity: { status: 'ok' }, sandboxed: true, ...overrides,
  };
}

describe('doctor', () => {
  test.each([
    ['ok', 'ok', /matches the local release manifest/i],
    ['mismatch', 'fail', /reinstall from the official package/i],
    ['dev', 'info', /development|source/i],
    ['missing-manifest', 'warn', /manifest/i],
  ] as const)('reports %s installation integrity', async (status, expected, detail) => {
    const { items } = await runDoctor(input({ integrity: { status } }));
    expect(items[0]).toMatchObject({ area: 'install', status: expected });
    expect(items[0]!.detail).toMatch(detail);
    if (status === 'mismatch' || status === 'missing-manifest') expect(items[0]!.fix).toMatch(/^https:\/\/|^keysentry |^npm /);
  });

  test.each([
    ['22.23.3', '22.23.4'], ['24.22.0', '24.22.1'], ['26.12.0', '26.12.1'],
  ])('explains when Node %s is too old for the sandbox', async (nodeVersion, minimum) => {
    const { items } = await runDoctor(input({ nodeVersion, sandboxed: false }));
    const node = items.find(item => item.area === 'node')!;
    expect(node.status).toBe('warn');
    expect(node.detail).toContain(nodeVersion);
    expect(node.detail).toContain(`older than ${minimum}`);
    expect(node.detail).toMatch(/sandbox.*off/i);
    expect(node.fix).toMatch(/^https:\/\//);
  });

  test('reports the minimum Node version while sandboxed', async () => {
    const node = (await runDoctor(input())).items.find(item => item.area === 'node')!;
    expect(node).toMatchObject({ status: 'ok' });
    expect(node.detail).toContain('22.23.4');
    expect(node.detail).toMatch(/sandbox.*on/i);
  });

  test('warns about an outdated Node release even when permissions are already active', async () => {
    const node = (await runDoctor(input({ nodeVersion: '24.14.1', sandboxed: true }))).items.find(item => item.area === 'node')!;
    expect(node.status).toBe('warn');
    expect(node.detail).toMatch(/sandbox.*on/i);
    expect(node.detail).toContain('older than 24.22.1');
    expect(node.fix).toBe('https://nodejs.org/en/download');
  });

  test('explains an unsupported Node line and an explicit sandbox opt-out', async () => {
    const unsupported = await runDoctor(input({ nodeVersion: '25.9.0', sandboxed: false }));
    expect(unsupported.items.find(item => item.area === 'node')!.detail).toContain('line is not supported');
    const optedOut = await runDoctor(input({ env: { KEYSENTRY_NO_SANDBOX: '1' }, sandboxed: false }));
    expect(optedOut.items.find(item => item.area === 'node')!.detail).toContain('opted out with KEYSENTRY_NO_SANDBOX=1');
  });

  test('reports the vault backend and its weakness', async () => {
    const vault = { ...createFakeVault(), weakness: 'This vault lasts only for this process.' };
    const result = await runDoctor(input({ vault }));
    expect(result.items.find(item => item.area === 'vault')).toMatchObject({
      status: 'warn', detail: expect.stringContaining('This vault lasts only for this process.'),
    });
    expect(JSON.stringify(result.items)).toContain('memory');
  });

  test.each(['env', 'memory'] as const)('warns that the %s vault cannot recover interrupted rotations', async backend => {
    const vault = { ...createFakeVault(), backend };
    const { items } = await runDoctor(input({ vault }));
    expect(items).toContainEqual(expect.objectContaining({
      area: 'vault', status: 'warn',
      detail: expect.stringContaining('Your vault keeps rotation values in memory only; if keysentry stops mid-rotation, the new key cannot be recovered. Use the OS credential store or the encrypted file for rotations.'),
    }));
  });

  test('flags env credentials as weaker and names the narrower token', async () => {
    const result = await runDoctor(input({ enabledHosts: ['railway'], env: { RAILWAY_TOKEN: 'unique-env-credential' } }));
    expect(result.items).toContainEqual(expect.objectContaining({
      area: 'tokens', status: 'warn', title: expect.stringContaining('RAILWAY_TOKEN'),
      detail: expect.stringContaining('stored in an environment variable'), fix: 'keysentry vault import-env',
    }));
    expect(result.items).toContainEqual(expect.objectContaining({
      area: 'tokens', status: 'info', detail: expect.stringMatching(/project token/i),
      fix: expect.stringMatching(/^https:\/\//),
    }));
    expect(JSON.stringify(result.items)).toMatch(/environment.*project|project.*environment/i);
  });

  test('warns for missing enabled-host credentials and skips local dotenv credentials', async () => {
    const { items } = await runDoctor(input({ enabledHosts: ['vercel', 'dotenv'] }));
    expect(items).toContainEqual(expect.objectContaining({
      area: 'tokens', status: 'warn', title: expect.stringContaining('VERCEL_TOKEN'), fix: 'keysentry vault set VERCEL_TOKEN',
    }));
    expect(items.filter(item => item.area === 'tokens')).toHaveLength(1);
    expect(JSON.stringify(items)).not.toContain('DOTENV_TOKEN');
  });

  test('reports a separate read-role credential from the vault', async () => {
    const vault = createFakeVault({
      'cred/GITHUB_TOKEN': Buffer.from('unique-write-value'),
      'cred/GITHUB_TOKEN@read': Buffer.from('unique-read-value'),
    });
    const { items } = await runDoctor(input({ vault, enabledHosts: ['github-actions'] }));
    expect(items).toContainEqual(expect.objectContaining({
      area: 'tokens', status: 'ok', title: expect.stringContaining('GITHUB_TOKEN'),
      detail: expect.stringContaining('separate read-role token'),
    }));
    expect(JSON.stringify(items)).not.toContain('unique-write-value');
    expect(JSON.stringify(items)).not.toContain('unique-read-value');
  });

  test('does not call two identical role values separate tokens', async () => {
    const vault = createFakeVault({
      'cred/GITHUB_TOKEN': Buffer.from('same-role-value'),
      'cred/GITHUB_TOKEN@read': Buffer.from('same-role-value'),
    });
    const { items } = await runDoctor(input({ vault, enabledHosts: ['github-actions'] }));
    expect(items).toContainEqual(expect.objectContaining({
      area: 'tokens', status: 'info', detail: expect.stringMatching(/Secrets: read/),
    }));
    expect(items.some(item => item.status === 'ok' && item.detail.includes('separate read-role token'))).toBe(false);
  });

  test('includes configured providers and their capabilities without requiring enabled hosts', async () => {
    const vault = createFakeVault({ 'cred/OPENAI_ADMIN_KEY': Buffer.from('unique-provider-credential') });
    const { items } = await runDoctor(input({ vault }));
    expect(items).toContainEqual(expect.objectContaining({ area: 'tokens', title: expect.stringContaining('OPENAI_ADMIN_KEY'), status: 'ok' }));
    expect(JSON.stringify(items)).toMatch(/service.account/i);
    expect(JSON.stringify(items)).not.toContain('ANTHROPIC_ADMIN_KEY');
  });

  test('keeps areas in install, node, vault, tokens, agent, probe order', async () => {
    const http = new FakeHttp().on('GET', /^https:\/\/api.github.com\/user$/, () => json(200, { login: 'octocat' }));
    const { items } = await runDoctor(input({
      enabledHosts: ['github-actions'], env: { GITHUB_TOKEN: 'unique-github-value', AI_AGENT: 'claude-code_2.1.3_agent' }, probe: { http },
    }));
    expect([...new Set(items.map(item => item.area))]).toEqual(['install', 'node', 'vault', 'tokens', 'agent', 'probe']);
    expect(items.find(item => item.area === 'agent')).toMatchObject({
      status: 'info', detail: expect.stringContaining('keysentry will refuse changes in this terminal'),
    });
  });

  test('makes no network call without probe', async () => {
    const http = new FakeHttp();
    const result = await runDoctor(input({ enabledHosts: ['github-actions'], env: { GITHUB_TOKEN: 'unique-no-probe-value' } }));
    expect(http.calls).toHaveLength(0);
    expect(result.fingerprints).toEqual({});
    expect(result.items.some(item => item.area === 'probe')).toBe(false);
  });

  test('probes GitHub with the write role and fingerprints sorted classic scopes only', async () => {
    const vault = createFakeVault({
      'cred/GITHUB_TOKEN': Buffer.from('github-write-token'), 'cred/GITHUB_TOKEN@read': Buffer.from('github-read-token'),
    });
    const http = new FakeHttp().on('GET', /^https:\/\/api.github.com\/user$/, () => json(200, { login: 'octocat' }, { 'X-OAuth-Scopes': 'repo, read:org, gist' }));
    const result = await runDoctor(input({ vault, enabledHosts: ['github-actions'], probe: { http } }));
    expect(http.calls).toHaveLength(1);
    expect(http.calls[0]).toMatchObject({ method: 'GET', url: 'https://api.github.com/user', headers: { Authorization: 'Bearer github-write-token' } });
    expect(result.fingerprints.github).toBe(createHash('sha256').update('gist,read:org,repo').digest('hex'));
    expect(result.items).toContainEqual(expect.objectContaining({ area: 'probe', status: 'ok', detail: expect.stringMatching(/octocat.*gist.*read:org.*repo/) }));
  });

  test('falls back to a read-role GitHub token and reports absent scopes', async () => {
    const vault = createFakeVault({ 'cred/GITHUB_TOKEN@read': Buffer.from('github-read-only-token') });
    const http = new FakeHttp().on('GET', /^https:\/\/api.github.com\/user$/, () => json(200, { login: 'reader' }));
    const result = await runDoctor(input({ vault, probe: { http } }));
    expect(http.calls[0]!.headers!.Authorization).toBe('Bearer github-read-only-token');
    expect(result.items.find(item => item.area === 'probe')!.detail).toContain('fine-grained token (no scopes header)');
    expect(result.fingerprints.github).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  test('warns when a probed token scopes changed since the last run', async () => {
    const http = new FakeHttp().on('GET', /^https:\/\/api.github.com\/user$/, () => json(200, { login: 'octocat' }, { 'x-oauth-scopes': 'repo' }));
    const result = await runDoctor(input({ env: { GITHUB_TOKEN: 'scope-change-token' }, probe: { http }, previous: { github: 'old-fingerprint' } }));
    expect(result.items).toContainEqual(expect.objectContaining({
      area: 'probe', status: 'warn', detail: expect.stringContaining("This token's permissions changed since the last doctor run"),
    }));
  });

  test('does not warn when scope order alone changes', async () => {
    const http = new FakeHttp().on('GET', /^https:\/\/api.github.com\/user$/, () => json(200, { login: 'octocat' }, { 'x-oauth-scopes': 'repo, gist' }));
    const result = await runDoctor(input({
      env: { GITHUB_TOKEN: 'stable-scopes-token' }, probe: { http },
      previous: { github: createHash('sha256').update('gist,repo').digest('hex') },
    }));
    expect(result.items.filter(item => item.area === 'probe').every(item => item.status === 'ok')).toBe(true);
  });

  test.each(['network', 'http', 'json', 'login'])('turns %s probe failures into a warning without echoing errors or bodies', async failure => {
    const secret = 'doctor-error-secret-unique';
    const http = new FakeHttp().on('GET', /^https:\/\/api.github.com\/user$/, () => {
      if (failure === 'network') throw new Error(`Authorization: Bearer ${secret}`);
      if (failure === 'http') return text(401, secret);
      if (failure === 'json') return text(200, secret);
      return json(200, { login: 42 });
    });
    const result = await runDoctor(input({ env: { GITHUB_TOKEN: secret }, probe: { http } }));
    expect(result.items).toContainEqual(expect.objectContaining({ area: 'probe', status: 'warn', fix: expect.stringMatching(/^keysentry |^https:\/\//) }));
    expect(result.fingerprints).toEqual({});
    expect(JSON.stringify(result.items)).not.toContain(secret);
  });

  test('skips the GitHub request when no token is present', async () => {
    const http = new FakeHttp();
    const result = await runDoctor(input({ probe: { http } }));
    expect(http.calls).toHaveLength(0);
    expect(result.items).toContainEqual(expect.objectContaining({ area: 'probe', status: 'info', detail: expect.stringContaining('GITHUB_TOKEN') }));
  });

  test('never returns credential values even when a probe response repeats them', async () => {
    const writeToken = 'doctor-unique-write-credential';
    const readToken = 'doctor-unique-read-credential';
    const providerToken = 'doctor-unique-provider-credential';
    const vault = createFakeVault({ 'cred/GITHUB_TOKEN': Buffer.from(writeToken), 'cred/GITHUB_TOKEN@read': Buffer.from(readToken) });
    const http = new FakeHttp().on('GET', /^https:\/\/api.github.com\/user$/, () => json(200, { login: writeToken }, { 'x-oauth-scopes': `repo,${readToken},${providerToken}` }));
    const { items } = await runDoctor(input({ vault, enabledHosts: ['github-actions'], env: { OPENAI_ADMIN_KEY: providerToken }, probe: { http } }));
    for (const value of [writeToken, readToken, providerToken]) expect(JSON.stringify(items)).not.toContain(value);
  });

  test('capability guidance covers verified platforms with a source for every token', () => {
    expect(Object.keys(TOKEN_CAPABILITIES).sort()).toEqual([
      'anthropic', 'aws', 'aws-secrets-manager', 'clerk', 'cloudflare', 'cloudflare-workers', 'coolify', 'digitalocean', 'doppler',
      'fly', 'github-actions', 'google', 'groq', 'heroku', 'infisical', 'kubernetes', 'mistral', 'neon', 'netlify', 'openai',
      'openrouter', 'postmark', 'railway', 'render', 'replicate', 'resend', 'sendgrid', 'supabase-functions', 'twilio', 'upstash',
      'vault-kv', 'vercel', 'zeabur',
    ]);
    for (const capability of Object.values(TOKEN_CAPABILITIES)) {
      expect(capability.source).toMatch(/^https:\/\//);
      expect(capability.keysentryUses.scan).toBeTruthy();
      expect(capability.keysentryUses.rotate).toBeTruthy();
      for (const token of capability.tokens) {
        expect(token.source).toMatch(/^https:\/\//);
        expect(token.howToCreate).toMatch(/https:\/\//);
        expect(token.scope).toBeTruthy();
      }
    }
  });
});
