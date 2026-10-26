import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { HttpRequest, ProviderAdapter, ProviderContext } from '../../src/types.js';
import { stripeProvider } from '../../src/providers/stripe.js';
import { githubProvider } from '../../src/providers/github.js';
import { supabaseProvider } from '../../src/providers/supabase.js';
import { databaseProvider } from '../../src/providers/database.js';
import { createGuidedAdapter } from '../../src/providers/guided.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const slackProvider = createGuidedAdapter('slack');
const sendgridProvider = createGuidedAdapter('sendgrid');
const token = (prefix = ''): string => prefix + randomBytes(32).toString('base64url');
const ctx = (http: FakeHttp, siblingVars?: Record<string, string>): ProviderContext => ({
  http, credentials: {}, log: silentLogger, siblingVars,
});
const exactUrl = (url: string): RegExp => new RegExp(`^${url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);

interface NetworkCase {
  name: string;
  provider: ProviderAdapter;
  method: HttpRequest['method'];
  url: string;
  body: unknown;
  prefix?: string;
  siblingVars?: Record<string, string>;
  forbiddenIsLimited: boolean;
}

const networkCases: NetworkCase[] = [
  { name: 'Stripe', provider: stripeProvider, method: 'GET', url: 'https://api.stripe.com/v1/balance', body: { object: 'balance', available: [], pending: [], livemode: false }, prefix: 'rk_test_', forbiddenIsLimited: true },
  { name: 'GitHub', provider: githubProvider, method: 'GET', url: 'https://api.github.com/user', body: { login: 'octocat', id: 1, type: 'User' }, prefix: 'ghp_', forbiddenIsLimited: true },
  { name: 'Supabase', provider: supabaseProvider, method: 'GET', url: 'https://project.supabase.co/rest/v1/', body: { swagger: '2.0', info: { title: 'PostgREST API' }, paths: {} }, siblingVars: { SUPABASE_URL: 'https://project.supabase.co/' }, forbiddenIsLimited: true },
  { name: 'Slack', provider: slackProvider, method: 'POST', url: 'https://slack.com/api/auth.test', body: { ok: true, url: 'https://workspace.slack.com/', team: 'workspace', user: 'test-user', team_id: 'T123', user_id: 'U123' }, prefix: 'xoxb-', forbiddenIsLimited: false },
  { name: 'SendGrid', provider: sendgridProvider, method: 'GET', url: 'https://api.sendgrid.com/v3/scopes', body: { scopes: ['mail.send'] }, prefix: 'SG.', forbiddenIsLimited: true },
];

describe.each(networkCases)('$name verification', ({ provider, method, url, body, prefix, siblingVars, forbiddenIsLimited }) => {
  it('sends the authenticated request through the injected client', async () => {
    const secret = token(prefix);
    const http = new FakeHttp().on(method, exactUrl(url), () => json(200, body));
    const result = await provider.verify(secret, ctx(http, siblingVars));
    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(http.calls.length).toBe(1);
    const call = http.calls[0]!;
    expect(call.method).toBe(method);
    expect(call.url).toBe(url);
    expect(call.headers?.Authorization === `Bearer ${secret}`).toBe(true);
    expect(call.url.includes(secret)).toBe(false);
    if (provider.id === 'github') {
      expect(result.identity).toBe('octocat');
      expect(call.headers?.Accept).toBe('application/vnd.github+json');
      expect(call.headers?.['X-GitHub-Api-Version']).toBe('2022-11-28');
    }
    if (provider.id === 'supabase') expect(call.headers?.apikey === secret).toBe(true);
    if (provider.id === 'slack') {
      expect(call.body).toBe('');
      expect(call.headers?.['Content-Type']).toBe('application/x-www-form-urlencoded');
      expect(result.identity).toBe('test-user');
    } else expect(call.body).toBeUndefined();
    expect(JSON.stringify(result).includes(secret)).toBe(false);
  });

  it('rejects HTTP 401 without exposing the response body', async () => {
    const secret = token(prefix);
    const http = new FakeHttp().on(method, exactUrl(url), () => json(401, { error: secret }));
    const result = await provider.verify(secret, ctx(http, siblingVars));
    expect(result.ok).toBe(false);
    expect(result.status).toBe(401);
    expect(JSON.stringify(result).includes(secret)).toBe(false);
  });

  it('handles HTTP 403 according to endpoint restrictions', async () => {
    const secret = token(prefix);
    const http = new FakeHttp().on(method, exactUrl(url), () => json(403, { error: secret }));
    const result = await provider.verify(secret, ctx(http, siblingVars));
    expect(result.ok).toBe(forbiddenIsLimited);
    expect(result.status).toBe(403);
    if (forbiddenIsLimited) expect(result.identity).toMatch(/limited/i);
    expect(JSON.stringify(result).includes(secret)).toBe(false);
  });

  it('does not leak credentials from transport exceptions', async () => {
    const secret = token(prefix);
    const http = new FakeHttp().on(method, exactUrl(url), () => { throw new Error(`transport echoed ${secret}`); });
    const outcome = await provider.verify(secret, ctx(http, siblingVars)).catch((error: unknown) => ({ error: String(error), ok: false }));
    expect(outcome.ok).toBe(false);
    expect(JSON.stringify(outcome).includes(secret)).toBe(false);
  });

  it('rejects server failures without returning the provider error text', async () => {
    const secret = token(prefix);
    const http = new FakeHttp().on(method, exactUrl(url), () => text(500, secret));
    const result = await provider.verify(secret, ctx(http, siblingVars));
    expect(result.ok).toBe(false);
    expect(result.status).toBe(500);
    expect(JSON.stringify(result).includes(secret)).toBe(false);
  });
});

describe('special guided verification', () => {
  it('leaves Stripe webhook secrets unverified and explains their own rotation path', async () => {
    const http = new FakeHttp();
    expect(await stripeProvider.verify(token('whsec_'), ctx(http))).toEqual({ ok: true, identity: 'unverified' });
    expect(http.calls.length).toBe(0);
    expect(stripeProvider.guidance().steps.join(' ')).toMatch(/webhook.+endpoint.+settings/i);
  });

  it('requires a sibling Supabase URL before contacting a server', async () => {
    const http = new FakeHttp();
    expect(await supabaseProvider.verify(token(), ctx(http))).toEqual({ ok: true, identity: 'unverified' });
    expect(http.calls.length).toBe(0);
  });

  it.each([
    'ftp://project.supabase.co',
    'http://project.supabase.co',
    'https://user:password@project.supabase.co',
    'https://project.supabase.co?apikey=unsafe',
    'https://project.supabase.co#unsafe',
    'https://project.supabase.co/rest/v1/',
    'javascript:unsafe',
    'not a URL',
  ])('rejects an unsafe Supabase URL without transmitting the key: %s', async (url) => {
    const secret = token();
    const http = new FakeHttp();
    const result = await supabaseProvider.verify(secret, ctx(http, { SUPABASE_URL: url }));
    expect(result.ok).toBe(false);
    expect(http.calls.length).toBe(0);
    expect(JSON.stringify(result).includes(secret)).toBe(false);
    expect(JSON.stringify(result).includes(url)).toBe(false);
  });

  it.each(['http://localhost:54321', 'http://127.0.0.1:54321', 'http://[::1]:54321', 'https://api.example.com'])('supports a Supabase HTTPS or local origin: %s', async (origin) => {
    const url = `${origin}/rest/v1/`;
    const http = new FakeHttp().on('GET', exactUrl(url), () => json(200, {}));
    expect((await supabaseProvider.verify(token(), ctx(http, { SUPABASE_URL: origin }))).ok).toBe(true);
    expect(http.calls.length).toBe(1);
    expect(http.calls[0]?.url).toBe(url);
  });

  it.each(['invalid_auth', 'token_revoked', 'account_inactive', 'not_authed'])('rejects a Slack API error in a successful HTTP response: %s', async (error) => {
    const http = new FakeHttp().on('POST', /^https:\/\/slack\.com\/api\/auth\.test$/, () => json(200, { ok: false, error }));
    const result = await slackProvider.verify(token('xoxb-'), ctx(http));
    expect(result.ok).toBe(false);
    expect(result.status).toBe(200);
  });

  it('does not echo arbitrary Slack API error fields', async () => {
    const secret = token('xoxp-');
    const http = new FakeHttp().on('POST', /^https:\/\/slack\.com\/api\/auth\.test$/, () => json(200, { ok: false, error: secret }));
    const result = await slackProvider.verify(secret, ctx(http));
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result).includes(secret)).toBe(false);
  });

  it.each(['hex', 'base64'] as const)('does not reflect an unrelated configured %s credential as the Slack identity', async (encoding) => {
    const unrelated = randomBytes(32).toString(encoding);
    const http = new FakeHttp().on('POST', /^https:\/\/slack\.com\/api\/auth\.test$/, () => json(200, { ok: true, user: unrelated }));
    const context = ctx(http);
    context.credentials = { OTHER_ADMIN_KEY: unrelated, OPTIONAL_ADMIN_KEY: undefined };
    const result = await slackProvider.verify(token('xoxb-'), context);
    expect(result.ok).toBe(true);
    expect(JSON.stringify(result).includes(unrelated)).toBe(false);
    expect(result.identity).toBe('Slack account');
  });

  it('does not authenticate Slack webhook URLs as tokens', async () => {
    const http = new FakeHttp();
    expect(await slackProvider.verify(`https://hooks.slack.com/services/${token()}`, ctx(http))).toEqual({ ok: true, identity: 'unverified' });
    expect(http.calls.length).toBe(0);
  });

  it('rejects malformed Slack authentication responses', async () => {
    const http = new FakeHttp().on('POST', /^https:\/\/slack\.com\/api\/auth\.test$/, () => text(200, '<html>not JSON</html>'));
    const outcome = await slackProvider.verify(token('xoxb-'), ctx(http)).catch(() => ({ ok: false }));
    expect(outcome.ok).toBe(false);
  });

  it('prevents the provider from reflecting a credential as the GitHub identity', async () => {
    const secret = token('ghp_');
    const http = new FakeHttp().on('GET', /^https:\/\/api\.github\.com\/user$/, () => json(200, { login: secret }));
    const result = await githubProvider.verify(secret, ctx(http));
    expect(result.ok).toBe(true);
    expect(JSON.stringify(result).includes(secret)).toBe(false);
  });
});

describe('guidance and unverified providers', () => {
  it.each(['twilio', 'google', 'private-key', 'crypto-wallet', 'unknown'] as const)('leaves %s unverified without network access', async (id) => {
    const provider = createGuidedAdapter(id);
    const http = new FakeHttp();
    expect(provider.id).toBe(id);
    expect(provider.method).toBe('guided');
    expect(await provider.verify(token(), ctx(http))).toEqual({ ok: true, identity: 'unverified' });
    expect(http.calls.length).toBe(0);
    expect(provider.guidance().steps.length).toBeGreaterThan(1);
  });

  it('warns wallet holders to move funds before changing variables', () => {
    expect(createGuidedAdapter('crypto-wallet').guidance().steps[0]).toBe('Move funds to a new wallet first; rotating the variable does not protect funds already exposed.');
  });

  it('requires changing database passwords at the database first', async () => {
    const http = new FakeHttp();
    expect(await databaseProvider.verify(token(), ctx(http))).toEqual({ ok: true, identity: 'unverified' });
    expect(http.calls.length).toBe(0);
    expect(databaseProvider.guidance().steps[0]).toMatch(/password.+database.+first/i);
  });

  it('returns independent guidance arrays so a caller cannot alter future runbooks', () => {
    const provider = createGuidedAdapter('crypto-wallet');
    const guidance = provider.guidance();
    guidance.steps.shift();
    expect(provider.guidance().steps[0]).toBe('Move funds to a new wallet first; rotating the variable does not protect funds already exposed.');
  });
});
