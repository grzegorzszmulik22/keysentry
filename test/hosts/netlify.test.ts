import { describe, expect, it } from 'vitest';
import { createNetlifyHost, type NetlifyHostOptions } from '../../src/hosts/netlify.js';
import type { ServiceRef } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const base = 'https://api.netlify.com/api/v1';
const token = 'netlify-test-token';
const readHeaders = { Authorization: `Bearer ${token}` };
const writeHeaders = { ...readHeaders, 'Content-Type': 'application/json' };
const hookToken = 'test-site-hook-access-token';

const site1 = {
  id: 'site-1', name: 'shop', account_id: 'acct-1', account_slug: 'acme', account_name: 'Acme',
  default_hooks_data: { access_token: hookToken },
  build_settings: { repo_url: 'https://github.com/acme/shop', repo_branch: 'main' },
  published_deploy: { id: 'dep-live', commit_ref: 'abc123', locked: false, state: 'ready' },
};
const site2 = { id: 'site-2', name: 'blog', account_id: 'acct-1', account_slug: 'acme' };

const site1Env = [
  { key: 'OPENAI_API_KEY', is_secret: false, scopes: ['builds', 'functions'], values: [
    { id: 'v1', context: 'all', value: 'test-openai-all' },
    { id: 'v2', context: 'production', value: 'test-openai-prod' },
  ] },
  { key: 'STRIPE_SECRET', is_secret: true, values: [
    { id: 'v3', context: 'production', value: 'masked-production' },
    { id: 'v4', context: 'deploy-preview', value: 'masked-preview' },
    { id: 'v5', context: 'dev', value: 'test-stripe-dev' },
  ] },
  { key: 'BRANCHY', values: [
    { id: 'v6', context: 'branch-deploy', value: 'test-branch-deploy' },
    { id: 'v7', context: 'branch', context_parameter: 'staging', value: 'test-staging' },
  ] },
];
const sharedEnv = [{ key: 'TEAM_TOKEN', is_secret: false, values: [{ id: 's1', context: 'all', value: 'test-team' }] }];

function ref(environmentId: string, overrides: Partial<ServiceRef> = {}): ServiceRef {
  return {
    host: 'netlify', projectId: 'acct-1', projectName: 'acme', serviceId: 'site-1', serviceName: 'shop',
    environmentId, environmentName: environmentId, ...overrides,
  };
}
const shared = (environmentId: string) => ref(environmentId, { serviceId: '', serviceName: 'shared' });

type Extra = Partial<Omit<NetlifyHostOptions, 'token' | 'http' | 'log'>> & { warn?: (msg: string) => void };
const hostFor = (http: FakeHttp, extra: Extra = {}) => {
  const { warn, ...options } = extra;
  return createNetlifyHost({ token, http, ...options, log: { ...silentLogger, ...(warn ? { warn } : {}) } });
};

function envRoutes(http: FakeHttp, siteEnv: unknown = site1Env, teamEnv: unknown = sharedEnv): FakeHttp {
  return http
    .on('GET', /\/accounts\/acct-1\/env\?site_id=site-1$/, () => json(200, siteEnv))
    .on('GET', /\/accounts\/acct-1\/env\?site_id=site-2$/, () => json(200, []))
    .on('GET', /\/accounts\/acct-1\/env$/, () => json(200, teamEnv));
}

async function failure(promise: Promise<unknown>): Promise<string> {
  const error = await promise.then(() => undefined, (caught: unknown) => caught);
  expect(error).toBeInstanceOf(Error);
  return String(error);
}

describe('Netlify host', () => {
  it('reports readable values, per-key writes and a production build step', () => {
    const host = hostFor(new FakeHttp());
    expect(host.id).toBe('netlify');
    expect(host.capabilities).toEqual({ readValues: true, batchWrite: false, redeploy: true });
  });

  it('lists sites across Link pages, per-context services, discovered branch values and shared team variables', async () => {
    const http = envRoutes(new FakeHttp()
      .on('GET', /\/sites\?filter=all&page=1&per_page=100$/, () => json(200, [site1], {
        link: '<https://api.netlify.com/api/v1/sites?filter=all&page=2&per_page=100>; rel="next", <https://api.netlify.com/api/v1/sites?filter=all&page=2&per_page=100>; rel="last"',
      }))
      .on('GET', /\/sites\?filter=all&page=2&per_page=100$/, () => json(200, [site2], {
        link: '<https://api.netlify.com/api/v1/sites?filter=all&page=1&per_page=100>; rel="prev"',
      })));

    const services = await hostFor(http).listServices();
    expect(services).toEqual([
      ref('production'), ref('deploy-preview'), ref('branch-deploy'), ref('branch:staging'),
      ...['production', 'deploy-preview', 'branch-deploy'].map((context) => ref(context, { serviceId: 'site-2', serviceName: 'blog' })),
      shared('production'), shared('deploy-preview'), shared('branch-deploy'),
    ]);
    expect(http.calls.map((call) => [call.method, call.url, call.headers])).toEqual([
      ['GET', `${base}/sites?filter=all&page=1&per_page=100`, readHeaders],
      ['GET', `${base}/sites?filter=all&page=2&per_page=100`, readHeaders],
      ['GET', `${base}/accounts/acct-1/env?site_id=site-1`, readHeaders],
      ['GET', `${base}/accounts/acct-1/env?site_id=site-2`, readHeaders],
      ['GET', `${base}/accounts/acct-1/env`, readHeaders],
    ]);
  });

  it('pages by size when no Link header is present and stops when a page adds nothing new', async () => {
    const full = Array.from({ length: 100 }, (_, index) => ({ ...site2, id: `site-${index + 10}` }));
    const http = envRoutes(new FakeHttp()
      .on('GET', /\/sites\?filter=all&page=\d+&per_page=100$/, () => json(200, full))
      .on('GET', /\/accounts\/acct-1\/env\?site_id=site-\d+$/, () => json(200, [])), [], []);
    expect(await failure(hostFor(http).listServices())).toMatch(/Netlify pagination/);
    expect(http.calls.filter((call) => call.url.includes('/sites?'))).toHaveLength(2);
  });

  it('skips shared variables with a warning when the token cannot read them', async () => {
    const warnings: string[] = [];
    const http = new FakeHttp()
      .on('GET', /\/sites\/site-1$/, () => json(200, site1))
      .on('GET', /\/accounts\/acct-1\/env\?site_id=site-1$/, () => json(200, []))
      .on('GET', /\/accounts\/acct-1\/env$/, () => json(403, { code: 403, message: 'test-private-error-marker' }));
    const services = await hostFor(http, { siteIds: ['site-1'], contexts: ['production', 'dev'], warn: (msg) => warnings.push(msg) }).listServices();
    expect(services).toEqual([ref('production'), ref('dev')]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).not.toContain('test-private-error-marker');
  });

  it('lists a team by slug and can turn shared variables off', async () => {
    const http = envRoutes(new FakeHttp().on('GET', /\/acme%20team\/sites\?page=1&per_page=100$/, () => json(200, [site2])));
    expect(await hostFor(http, { accountSlug: 'acme team', shared: false }).listServices()).toEqual(
      ['production', 'deploy-preview', 'branch-deploy'].map((context) => ref(context, { serviceId: 'site-2', serviceName: 'blog' })),
    );
    expect(http.calls.map((call) => call.url)).toEqual([
      `${base}/acme%20team/sites?page=1&per_page=100`,
      `${base}/accounts/acct-1/env?site_id=site-2`,
    ]);
  });

  it('keeps listing a site when its branch discovery read fails', async () => {
    const warnings: string[] = [];
    const http = new FakeHttp()
      .on('GET', /\/sites\/site-1$/, () => json(200, site1))
      .on('GET', /\/accounts\/acct-1\/env\?site_id=site-1$/, () => json(500, {}));
    expect(await hostFor(http, { siteIds: ['site-1'], contexts: ['production'], shared: false, warn: (msg) => warnings.push(msg) }).listServices())
      .toEqual([ref('production')]);
    expect(warnings).toHaveLength(1);
  });

  it.each([
    ['production', [
      { name: 'OPENAI_API_KEY', value: 'test-openai-prod', sealed: false },
      { name: 'STRIPE_SECRET', sealed: true },
    ]],
    ['deploy-preview', [
      { name: 'OPENAI_API_KEY', value: 'test-openai-all', sealed: false },
      { name: 'STRIPE_SECRET', sealed: true },
    ]],
    ['branch-deploy', [
      { name: 'OPENAI_API_KEY', value: 'test-openai-all', sealed: false },
      { name: 'BRANCHY', value: 'test-branch-deploy', sealed: false },
    ]],
    ['dev', [
      { name: 'OPENAI_API_KEY', value: 'test-openai-all', sealed: false },
      { name: 'STRIPE_SECRET', value: 'test-stripe-dev', sealed: false },
    ]],
    ['branch:staging', [
      { name: 'BRANCHY', value: 'test-staging', sealed: false },
    ]],
  ] as const)('reads the effective %s values and seals secret values', async (context, expected) => {
    const http = envRoutes(new FakeHttp());
    const vars = await hostFor(http).readVariables(ref(context));
    expect(vars).toEqual(expected);
    expect(JSON.stringify(vars)).not.toContain('masked-');
    expect(http.calls).toEqual([{ method: 'GET', url: `${base}/accounts/acct-1/env?site_id=site-1`, headers: readHeaders }]);
  });

  it('reads shared variables without a site id', async () => {
    const http = envRoutes(new FakeHttp());
    expect(await hostFor(http).readVariables(shared('production'))).toEqual([{ name: 'TEAM_TOKEN', value: 'test-team', sealed: false }]);
    expect(http.calls[0]?.url).toBe(`${base}/accounts/acct-1/env`);
  });

  it('seals ambiguous values and secrets that only inherit a value', async () => {
    const warnings: string[] = [];
    const http = envRoutes(new FakeHttp(), [
      { key: 'TWICE', values: [{ context: 'production', value: 'test-a' }, { context: 'production', value: 'test-b' }] },
      { key: 'SECRET_ALL', is_secret: true, values: [{ context: 'all', value: 'masked' }] },
    ]);
    expect(await hostFor(http, { warn: (msg) => warnings.push(msg) }).readVariables(ref('dev'))).toEqual([{ name: 'SECRET_ALL', sealed: true }]);
    expect(await hostFor(http, { warn: (msg) => warnings.push(msg) }).readVariables(ref('production'))).toEqual([
      { name: 'TWICE', sealed: true },
      { name: 'SECRET_ALL', sealed: true },
    ]);
    expect(warnings).toHaveLength(1);
    expect(warnings.join(' ')).not.toContain('test-a');
  });

  it('updates the exact context value, the inherited all-context value, or a branch value with per-key PATCHes', async () => {
    const http = envRoutes(new FakeHttp()).on('PATCH', /\/accounts\/acct-1\/env\/[^?]+\?site_id=site-1$/, () => json(201, {}));
    const host = hostFor(http);
    await host.writeVariables(ref('production'), { OPENAI_API_KEY: 'test-new-prod', STRIPE_SECRET: 'test-new-stripe' }, { skipDeploy: true });
    await host.writeVariables(ref('deploy-preview'), { OPENAI_API_KEY: 'test-new-all' }, { skipDeploy: true });
    await host.writeVariables(ref('branch:staging'), { BRANCHY: 'test-new-staging' }, { skipDeploy: true });
    await host.writeVariables(ref('branch-deploy'), { STRIPE_SECRET: 'test-new-branch-deploy' }, { skipDeploy: false });

    const patches = http.calls.filter((call) => call.method === 'PATCH');
    expect(patches).toEqual([
      { method: 'PATCH', url: `${base}/accounts/acct-1/env/OPENAI_API_KEY?site_id=site-1`, headers: writeHeaders, body: JSON.stringify({ context: 'production', value: 'test-new-prod' }) },
      { method: 'PATCH', url: `${base}/accounts/acct-1/env/STRIPE_SECRET?site_id=site-1`, headers: writeHeaders, body: JSON.stringify({ context: 'production', value: 'test-new-stripe' }) },
      { method: 'PATCH', url: `${base}/accounts/acct-1/env/OPENAI_API_KEY?site_id=site-1`, headers: writeHeaders, body: JSON.stringify({ context: 'all', value: 'test-new-all' }) },
      { method: 'PATCH', url: `${base}/accounts/acct-1/env/BRANCHY?site_id=site-1`, headers: writeHeaders, body: JSON.stringify({ context: 'branch', context_parameter: 'staging', value: 'test-new-staging' }) },
      { method: 'PATCH', url: `${base}/accounts/acct-1/env/STRIPE_SECRET?site_id=site-1`, headers: writeHeaders, body: JSON.stringify({ context: 'branch-deploy', value: 'test-new-branch-deploy' }) },
    ]);
    // Writes never start builds.
    expect(http.calls.filter((call) => call.method === 'POST')).toEqual([]);
  });

  it('creates missing site variables in one request after updating existing ones', async () => {
    const http = envRoutes(new FakeHttp())
      .on('PATCH', /\/env\/OPENAI_API_KEY\?site_id=site-1$/, () => json(201, {}))
      .on('POST', /\/accounts\/acct-1\/env\?site_id=site-1$/, () => json(201, []));
    await hostFor(http).writeVariables(ref('branch:staging'), { NEW_KEY: 'test-new-1', OPENAI_API_KEY: 'test-new-2', NEW_TWO: 'test-new-3' }, { skipDeploy: true });
    expect(http.calls.slice(1)).toEqual([
      { method: 'PATCH', url: `${base}/accounts/acct-1/env/OPENAI_API_KEY?site_id=site-1`, headers: writeHeaders, body: JSON.stringify({ context: 'branch', context_parameter: 'staging', value: 'test-new-2' }) },
      { method: 'POST', url: `${base}/accounts/acct-1/env?site_id=site-1`, headers: writeHeaders, body: JSON.stringify([
        { key: 'NEW_KEY', values: [{ context: 'branch', context_parameter: 'staging', value: 'test-new-1' }] },
        { key: 'NEW_TWO', values: [{ context: 'branch', context_parameter: 'staging', value: 'test-new-3' }] },
      ]) },
    ]);
  });

  it('writes shared variables at team level and never creates new team-wide variables', async () => {
    const http = envRoutes(new FakeHttp()).on('PATCH', /\/accounts\/acct-1\/env\/TEAM_TOKEN$/, () => json(201, {}));
    await hostFor(http).writeVariables(shared('production'), { TEAM_TOKEN: 'test-new-team' }, { skipDeploy: true });
    expect(http.calls.at(-1)).toEqual({
      method: 'PATCH', url: `${base}/accounts/acct-1/env/TEAM_TOKEN`, headers: writeHeaders, body: JSON.stringify({ context: 'all', value: 'test-new-team' }),
    });

    const refused = envRoutes(new FakeHttp());
    expect(await failure(hostFor(refused).writeVariables(shared('production'), { TEAM_TOKEN: 'test-new', NEW_TEAM_KEY: 'test-new' }, { skipDeploy: true })))
      .toMatch(/Netlify/);
    expect(refused.calls.map((call) => call.method)).toEqual(['GET']);
  });

  it('refuses ambiguous targets before changing anything', async () => {
    const http = envRoutes(new FakeHttp(), [
      { key: 'OK', values: [{ context: 'production', value: 'test-a' }] },
      { key: 'TWICE', values: [{ context: 'production', value: 'test-a' }, { context: 'production', value: 'test-b' }] },
    ]);
    expect(await failure(hostFor(http).writeVariables(ref('production'), { OK: 'test-new', TWICE: 'test-new' }, { skipDeploy: true }))).toMatch(/Netlify/);
    expect(http.calls.map((call) => call.method)).toEqual(['GET']);
  });

  it.each(['', '.', '..'])('rejects the unsafe variable name %j before any request', async (name) => {
    const http = new FakeHttp();
    await expect(hostFor(http).writeVariables(ref('production'), { OK: 'test-new', [name]: 'test-new' }, { skipDeploy: true })).rejects.toThrow(/Netlify/);
    expect(http.calls).toEqual([]);
  });

  it('rejects an unknown deploy context before any request', async () => {
    const http = new FakeHttp();
    await expect(hostFor(http).readVariables(ref('preview'))).rejects.toThrow(/Netlify/);
    await expect(hostFor(http).writeVariables(ref('branch:'), { OK: 'test-new' }, { skipDeploy: true })).rejects.toThrow(/Netlify/);
    expect(http.calls).toEqual([]);
  });

  it('does nothing for an empty update', async () => {
    const http = new FakeHttp();
    await hostFor(http).writeVariables(ref('production'), {}, { skipDeploy: true });
    expect(http.calls).toEqual([]);
  });

  it('rebuilds the published production commit and returns the new deploy id', async () => {
    const http = new FakeHttp()
      .on('GET', /\/sites\/site-1$/, () => json(200, site1))
      .on('POST', /\/sites\/site-1\/builds\?commit_sha=abc123$/, () => json(200, { id: 'build-1', deploy_id: 'dep-new', done: false }));
    expect(await hostFor(http).redeploy(ref('production'))).toBe('dep-new');
    expect(http.calls).toEqual([
      { method: 'GET', url: `${base}/sites/site-1`, headers: readHeaders },
      { method: 'POST', url: `${base}/sites/site-1/builds?commit_sha=abc123`, headers: readHeaders },
    ]);
  });

  it('warns and builds the production branch head when no published commit is known', async () => {
    const warnings: string[] = [];
    const http = new FakeHttp()
      .on('GET', /\/sites\/site-1$/, () => json(200, { ...site1, published_deploy: null }))
      .on('POST', /\/sites\/site-1\/builds$/, () => json(200, { id: 'build-1', deploy_id: 'dep-new' }));
    expect(await hostFor(http, { warn: (msg) => warnings.push(msg) }).redeploy(ref('production'))).toBe('dep-new');
    expect(http.calls[1]?.url).toBe(`${base}/sites/site-1/builds`);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).not.toContain(hookToken);
  });

  it.each([
    ['locked publishing', { ...site1, published_deploy: { ...site1.published_deploy, locked: true } }],
    ['no linked repository', { ...site1, build_settings: {} }],
    ['stopped builds', { ...site1, build_settings: { ...site1.build_settings, stop_builds: true } }],
  ])('returns null without building for %s', async (_label, current) => {
    const warnings: string[] = [];
    const http = new FakeHttp()
      .on('GET', /\/sites\/site-1$/, () => json(200, current))
      .on('POST', /\/builds/, () => json(200, { id: 'unexpected', deploy_id: 'unexpected' }));
    expect(await hostFor(http, { warn: (msg) => warnings.push(msg) }).redeploy(ref('production'))).toBeNull();
    expect(http.calls.map((call) => call.method)).toEqual(['GET']);
    expect(warnings).toHaveLength(1);
  });

  it('returns null without requests for other contexts, branches and shared variables', async () => {
    const http = new FakeHttp();
    for (const service of [ref('deploy-preview'), ref('branch-deploy'), ref('dev'), ref('branch:staging'), shared('production')]) {
      expect(await hostFor(http).redeploy(service)).toBeNull();
    }
    expect(http.calls).toEqual([]);
  });

  it.each([
    ['ready', 'dep-new', 'success'],
    ['ready', 'dep-later', 'failed'],
    ['error', 'dep-live', 'failed'],
    ['rejected', 'dep-live', 'failed'],
    ['building', 'dep-live', 'pending'],
    ['enqueued', 'dep-live', 'pending'],
  ] as const)('maps deploy state %s (published %s) to %s', async (state, published, expected) => {
    const http = new FakeHttp()
      .on('GET', /\/deploys\/dep-new$/, () => json(200, { id: 'dep-new', state, site_id: 'site-1' }))
      .on('GET', /\/sites\/site-1$/, () => json(200, { ...site1, published_deploy: { id: published } }));
    expect(await hostFor(http).deploymentStatus(ref('production'), 'dep-new')).toBe(expected);
    expect(http.calls[0]).toEqual({ method: 'GET', url: `${base}/deploys/dep-new`, headers: readHeaders });
    expect(http.calls).toHaveLength(state === 'ready' ? 2 : 1);
  });

  it('treats a skipped build as failed', async () => {
    const http = new FakeHttp().on('GET', /\/deploys\/dep-new$/, () => json(200, { id: 'dep-new', state: 'ready', skipped: true }));
    expect(await hostFor(http).deploymentStatus(ref('production'), 'dep-new')).toBe('failed');
  });

  it.each(['http', 'transport', 'json'] as const)('sanitizes %s failures during writes', async (kind) => {
    const marker = 'test-private-error-marker';
    const http = envRoutes(new FakeHttp()).on('PATCH', /\/env\//, () => {
      if (kind === 'transport') throw new Error(`${token} ${marker}`);
      return kind === 'http' ? json(422, { message: marker }) : text(201, marker);
    });
    const message = await failure(hostFor(http).writeVariables(ref('production'), { OPENAI_API_KEY: marker }, { skipDeploy: true }));
    expect(message).toMatch(/Netlify/);
    expect(message).not.toContain(marker);
    expect(message).not.toContain(token);
  });

  it('rejects malformed site and variable payloads without echoing them', async () => {
    const sites = new FakeHttp().on('GET', /\/sites\?/, () => json(200, [{ id: 'site-1', name: { x: hookToken } }]));
    const siteMessage = await failure(hostFor(sites).listServices());
    expect(siteMessage).toMatch(/Netlify/);
    expect(siteMessage).not.toContain(hookToken);

    const env = envRoutes(new FakeHttp(), [{ key: 'K', values: [{ context: 'production', value: { leaked: 'test-private-response-marker' } }] }]);
    const envMessage = await failure(hostFor(env).readVariables(ref('production')));
    expect(envMessage).toMatch(/Netlify/);
    expect(envMessage).not.toContain('test-private-response-marker');
  });
});
