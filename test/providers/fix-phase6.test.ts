// fix-phase6: provider-level fixes (notes/fix-phase6.md H1, H2, H3, H4, L2).
import { randomBytes, randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createGoogleProvider, publicGoogleKeyGuidance } from '../../src/providers/google.js';
import { neonProvider } from '../../src/providers/neon.js';
import { sendgridProvider } from '../../src/providers/sendgrid.js';
import { mutationRequest, PLANNED_FORM_PREFIX, ProviderMutationUncertainError } from '../../src/providers/shared.js';
import { twilioKeySidFor, twilioProvider } from '../../src/providers/twilio.js';
import { upstashProvider } from '../../src/providers/upstash.js';
import { automaticCredentialsConfigured } from '../../src/providers/index.js';
import type { HttpRequest, ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger } from '../helpers/fake-http.js';

const hex = () => randomBytes(16).toString('hex');
const twilioSecret = () => `Zq${randomBytes(30).toString('base64url').replace(/[-_]/g, 'x').slice(0, 30)}`;
const basic = (user: string, password: string) => `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;

async function rejection(operation: Promise<unknown>): Promise<unknown> {
  try { await operation; } catch (error) { return error; }
  return undefined;
}

describe('shared mutationRequest (H4)', () => {
  const ctx = (respond: (req: HttpRequest) => ReturnType<typeof json>): ProviderContext => ({
    http: { async request(req) { return respond(req); } }, credentials: { X_ADMIN_KEY: 'admin-secret-value' }, log: silentLogger,
  });
  const req: HttpRequest = { method: 'POST', url: 'https://api.example.test/keys', headers: {} };

  it('reports no answer and 5xx as an uncertain outcome, and returns every other answer', async () => {
    const thrown = await rejection(mutationRequest({ ...ctx(() => json(200, {})), http: { async request() { throw new Error('admin-secret-value'); } } }, req, 'Example'));
    expect(thrown).toBeInstanceOf(ProviderMutationUncertainError);
    expect(thrown).toMatchObject({ code: 'MUTATION_UNCERTAIN', atomic: false, keyRef: null });
    expect(String(thrown)).not.toContain('admin-secret-value');
    expect(await rejection(mutationRequest(ctx(() => json(503, {})), req, 'Example', { atomic: true })))
      .toMatchObject({ code: 'MUTATION_UNCERTAIN', atomic: true, message: expect.stringMatching(/HTTP 503.*may already have happened/) });
    expect((await mutationRequest(ctx(() => json(501, {})), req, 'Example')).status).toBe(501);
    expect((await mutationRequest(ctx(() => json(409, {})), req, 'Example')).status).toBe(409);
  });

  it('refuses a credential in the URL before sending anything, as a definite failure', async () => {
    let sent = 0;
    const error = await rejection(mutationRequest({ ...ctx(() => json(200, {})), http: { async request() { sent += 1; return json(200, {}); } } },
      { ...req, url: 'https://api.example.test/keys/admin-secret-value' }, 'Example'));
    expect(sent).toBe(0);
    expect(error).not.toBeInstanceOf(ProviderMutationUncertainError);
  });
});

describe('Twilio pair proof (H3)', () => {
  function setup(opts: { proofStatus: number; policy?: unknown }) {
    const account = `AC${hex()}`;
    const sid = `SK${hex()}`;
    const secret = twilioSecret();
    const admin = { sid: `SK${hex()}`, secret: twilioSecret() };
    const http = new FakeHttp()
      .on('GET', new RegExp(`/Accounts/${account}/Applications\\.json`), req =>
        req.headers?.Authorization === basic(sid, secret) ? json(opts.proofStatus, opts.proofStatus === 200 ? { applications: [] } : { code: 20003 }) : json(401, { code: 20003 }))
      .on('GET', new RegExp(`^https://iam\\.twilio\\.com/v1/Keys/${sid}$`), () => json(200, { sid, policy: opts.policy ?? null }))
      .on('GET', /^https:\/\/iam\.twilio\.com\/v1\/Keys\?/, () => json(401, { code: 20003 }));
    const ctx: ProviderContext = { http, log: silentLogger,
      credentials: { TWILIO_ADMIN_KEY_SID: admin.sid, TWILIO_ADMIN_KEY: admin.secret, TWILIO_ADMIN_ACCOUNT_SID: account },
      siblingVars: { TWILIO_ACCOUNT_SID: account, TWILIO_API_KEY: sid, TWILIO_API_SECRET: secret } };
    return { account, sid, secret, admin, http, ctx };
  }
  const policy = { allow: ['/twilio/messaging/messages/create'] };

  it('creates nothing when a Restricted key secret does not authenticate as its paired SID', async () => {
    const s = setup({ proofStatus: 200, policy });
    s.ctx.siblingVars!.TWILIO_API_SECRET = twilioSecret();
    const error = await rejection(twilioProvider.rotate!(s.ctx.siblingVars!.TWILIO_API_SECRET!, s.ctx));
    expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(s.http.callsTo('POST', /\/v1\/Keys$/)).toHaveLength(0);
    expect(s.http.callsTo('GET', /\/v1\/Keys\/SK/)).toHaveLength(0);
  });

  it('accepts a 403 as proof for a Restricted key and copies its policy', async () => {
    const s = setup({ proofStatus: 403, policy });
    const newSid = `SK${hex()}`;
    s.http.on('POST', /^https:\/\/iam\.twilio\.com\/v1\/Keys$/, req => json(201, { sid: newSid, secret: twilioSecret(),
      policy: JSON.parse(new URLSearchParams(req.body ?? '').get('Policy') ?? 'null') }));
    const result = await twilioProvider.rotate!(s.secret, s.ctx);
    expect(result).toMatchObject({ oldKeyRef: s.sid, newKeyRef: newSid, companions: { TWILIO_API_KEY: newSid } });
  });

  it('never pairs a secret with a SID that is the conventional partner of another secret', async () => {
    const s = setup({ proofStatus: 200 });
    const webhook = twilioSecret();
    s.ctx.siblingVars!.TWILIO_WEBHOOK_SECRET = webhook;
    expect(twilioKeySidFor(['TWILIO_WEBHOOK_SECRET'], s.ctx.siblingVars!)).toBeNull();
    expect(twilioKeySidFor(['TWILIO_API_SECRET'], s.ctx.siblingVars!)).toBe(s.sid);
    // With no competing secret, the only SID in the service is still the fallback.
    expect(twilioKeySidFor(['MY_TWILIO_SECRET'], { MY_TWILIO_SECRET: webhook, MY_TWILIO_KEY: s.sid })).toBe(s.sid);
    const error = await rejection(twilioProvider.rotate!(webhook, s.ctx));
    expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(s.http.calls).toHaveLength(0);
    expect(await twilioProvider.resolveKeyRef!(webhook, s.ctx)).toBeNull();
  });

  it('reports an unanswered or unreadable key creation as a possible stray key', async () => {
    for (const respond of [() => { throw new Error('network'); }, () => json(502, {}), () => json(201, { secret: 'x' })]) {
      const s = setup({ proofStatus: 200 });
      s.http.on('POST', /^https:\/\/iam\.twilio\.com\/v1\/Keys$/, respond);
      const error = await rejection(twilioProvider.rotate!(s.secret, s.ctx));
      expect(error).toMatchObject({ code: 'MUTATION_UNCERTAIN', atomic: false });
      expect(String(error)).not.toContain(s.secret);
    }
  });

  it('names an unusable replacement it could not delete', async () => {
    const s = setup({ proofStatus: 200 });
    const newSid = `SK${hex()}`;
    s.http.on('POST', /^https:\/\/iam\.twilio\.com\/v1\/Keys$/, () => json(201, { sid: newSid, secret: s.secret, policy: null }))
      .on('DELETE', /\/v1\/Keys\//, () => json(500, {}));
    expect(await rejection(twilioProvider.rotate!(s.secret, s.ctx))).toMatchObject({ code: 'MUTATION_UNCERTAIN', keyRef: newSid });
  });
});

describe('Google keys that ship in clients (H1) and uncertain creation (H4)', () => {
  const project = 'demo-project';
  const name = `projects/${project}/locations/global/keys/old-key`;
  const oldValue = `AIza${'Q'.repeat(12)}7hZ-k2_${'w'.repeat(16)}`;
  function routes(restrictions: unknown) {
    return new FakeHttp()
      .on('GET', /\/v2\/projects\/demo-project\/locations\/global\/keys$/, () => json(200, { keys: [{ name }] }))
      .on('GET', /\/keys\/old-key\/keyString$/, () => json(200, { keyString: oldValue }))
      .on('GET', /\/keys\/old-key$/, () => json(200, { name, displayName: 'web', ...(restrictions === undefined ? {} : { restrictions }) }));
  }
  const ctx = (http: FakeHttp): ProviderContext => ({ http, log: silentLogger,
    credentials: { GOOGLE_OAUTH_ACCESS_TOKEN: `ya29.${'a'.repeat(40)}`, GOOGLE_API_KEYS_PROJECT: project } });
  const provider = createGoogleProvider({ sleep: async () => {} });

  it.each([
    { browserKeyRestrictions: { allowedReferrers: ['https://example.com/*'] } },
    { androidKeyRestrictions: { allowedApplications: [{ sha1Fingerprint: 'AA:BB', packageName: 'com.example' }] } },
    { iosKeyRestrictions: { allowedBundleIds: ['com.example.app'] } },
  ])('keeps a client-restricted key guided and asks the engine to retain the old key (%o)', async (restrictions) => {
    const http = routes(restrictions);
    const error = await rejection(provider.rotate!(oldValue, ctx(http)));
    expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED', retainOldKey: true });
    expect(http.callsTo('POST', /\/keys$/)).toHaveLength(0);
  });

  it('reports a creation request without an answer, or one still running, as a possible unused key', async () => {
    const unanswered = routes({ apiTargets: [{ service: 'generativelanguage.googleapis.com' }] })
      .on('POST', /\/locations\/global\/keys$/, () => { throw new Error('timeout'); });
    expect(await rejection(provider.rotate!(oldValue, ctx(unanswered)))).toMatchObject({ code: 'MUTATION_UNCERTAIN', keyRef: null });
    const running = routes(undefined)
      .on('POST', /\/locations\/global\/keys$/, () => json(200, { name: 'operations/slow', done: false }))
      .on('GET', /\/v2\/operations\/slow$/, () => json(200, { name: 'operations/slow', done: false }));
    const error = await rejection(provider.rotate!(oldValue, ctx(running)));
    expect(error).toMatchObject({ code: 'MUTATION_UNCERTAIN' });
    expect(String(error)).toMatch(/still running/);
    const failed = routes(undefined)
      .on('POST', /\/locations\/global\/keys$/, () => json(200, { name: 'operations/e', done: true, error: { code: 9 } }));
    expect(await rejection(provider.rotate!(oldValue, ctx(failed)))).not.toMatchObject({ code: 'MUTATION_UNCERTAIN' });
  });

  it('gives public-key guidance that never promises an automatic deletion', () => {
    const guidance = publicGoogleKeyGuidance();
    expect(guidance.url).toBe('https://console.cloud.google.com/apis/credentials');
    expect(guidance.steps.join(' ')).toMatch(/restrictions protect it, not secrecy/);
    expect(guidance.steps.join(' ')).toMatch(/keysentry does not delete it/);
  });
});

describe('Upstash resets (H2, H4)', () => {
  const endpoint = 'eu1-quiet-fox-777';
  const db = { database_id: 'db-7', endpoint, state: 'active', password: 'p'.repeat(31) + '1', rest_token: `AX${'t'.repeat(30)}`, read_only_rest_token: `Ar${'r'.repeat(30)}` };
  const ctx = (http: FakeHttp, siblingVars: Record<string, string>): ProviderContext => ({ http, log: silentLogger, siblingVars,
    credentials: { UPSTASH_ADMIN_EMAIL: 'ops@example.com', UPSTASH_ADMIN_KEY: randomUUID() } });

  it('reports a reset that got a server error as a possibly rolled credential', async () => {
    const http = new FakeHttp()
      .on('GET', /\/v2\/redis\/databases$/, () => json(200, [db]))
      .on('POST', /\/v2\/redis\/reset-password\/db-7$/, () => json(503, {}));
    expect(await rejection(upstashProvider.rotate!(db.rest_token, ctx(http, { UPSTASH_REDIS_REST_TOKEN: db.rest_token }))))
      .toMatchObject({ code: 'MUTATION_UNCERTAIN', atomic: true });
  });

  it('answers every planned form, including an unchanged read-only token, and omits only unknown ones', async () => {
    const fresh = { password: 'n'.repeat(31) + '2', rest_token: `AY${'u'.repeat(30)}` };
    const url = `rediss://default:${db.password}@${endpoint}.upstash.io:6379`;
    const form = (id: string) => `${PLANNED_FORM_PREFIX}${id}`;
    for (const readOnly of [db.read_only_rest_token, undefined]) {
      const http = new FakeHttp()
        .on('GET', /\/v2\/redis\/databases$/, () => json(200, [db]))
        .on('POST', /\/v2\/redis\/reset-password\/db-7$/, () => json(200, { ...db, ...fresh, read_only_rest_token: readOnly }));
      const result = await upstashProvider.rotate!(db.rest_token, ctx(http, {
        UPSTASH_REDIS_REST_TOKEN: db.rest_token, [form('url')]: url, [form('ro')]: db.read_only_rest_token,
      }));
      expect(result.newValue).toBe(fresh.rest_token);
      expect(result.companions?.[form('url')]).toBe(`rediss://default:${fresh.password}@${endpoint}.upstash.io:6379`);
      expect(result.companions?.[form('ro')]).toBe(readOnly);
    }
  });
});

describe('SendGrid and Neon key creation with an unknown outcome (H4)', () => {
  it('SendGrid: a creation request without an answer may have left a key', async () => {
    const segment = (length: number) => randomBytes(length).toString('base64url').slice(0, length);
    const oldId = segment(22);
    const oldValue = `SG.${oldId}.${segment(43)}`;
    const admin = `SG.${segment(22)}.${segment(43)}`;
    const http = new FakeHttp()
      .on('GET', /\/v3\/scopes$/, () => json(200, { scopes: ['mail.send'] }))
      .on('GET', /\/v3\/api_keys\//, () => json(200, { result: [{ api_key_id: oldId, name: 'p', scopes: ['mail.send'] }] }))
      .on('POST', /\/v3\/api_keys$/, () => { throw new Error('timeout'); });
    const error = await rejection(sendgridProvider.rotate!(oldValue, { http, log: silentLogger, credentials: { SENDGRID_ADMIN_KEY: admin } }));
    expect(error).toMatchObject({ code: 'MUTATION_UNCERTAIN' });
    expect(String(error)).not.toContain(oldValue);
  });

  it('Neon: an unreadable creation response names the possible stray key', async () => {
    const oldValue = `napi_${randomBytes(32).toString('hex')}`;
    const admin = `napi_${randomBytes(32).toString('hex')}`;
    const user = randomUUID();
    const http = new FakeHttp()
      .on('GET', /\/api\/v2\/auth$/, () => json(200, { account_id: user, auth_method: 'api_key_user' }))
      .on('POST', /\/api\/v2\/api_keys$/, () => json(200, { id: 4242 }));
    expect(await rejection(neonProvider.rotate!(oldValue, { http, log: silentLogger, credentials: { NEON_ADMIN_KEY: admin } })))
      .toMatchObject({ code: 'MUTATION_UNCERTAIN', keyRef: '4242' });
  });
});

describe('automatic credential sets (L2)', () => {
  it('treats Google credentials as alternatives and Twilio TWILIO_ADMIN_ACCOUNT_SID as conditional', () => {
    const has = (...names: string[]) => new Set(names);
    expect(automaticCredentialsConfigured('google', has('GOOGLE_API_KEYS_ADMIN_KEY'))).toBe(true);
    expect(automaticCredentialsConfigured('google', has('GOOGLE_OAUTH_ACCESS_TOKEN', 'GOOGLE_API_KEYS_PROJECT'))).toBe(true);
    expect(automaticCredentialsConfigured('google', has('GOOGLE_OAUTH_ACCESS_TOKEN'))).toBe(false);
    expect(automaticCredentialsConfigured('twilio', has('TWILIO_ADMIN_KEY_SID', 'TWILIO_ADMIN_KEY'))).toBe(true);
    expect(automaticCredentialsConfigured('twilio', has('TWILIO_ADMIN_KEY'))).toBe(false);
    expect(automaticCredentialsConfigured('upstash', has('UPSTASH_ADMIN_KEY'))).toBe(false);
    expect(automaticCredentialsConfigured('aws', has())).toBe(true);
  });
});
