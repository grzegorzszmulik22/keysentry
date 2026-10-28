import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { TwilioGuidedRotationRequiredError, twilioProvider } from '../../src/providers/twilio.js';
import type { HttpRequest, ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const hex = (bytes = 16) => randomBytes(bytes).toString('hex');
const keySid = () => `SK${hex()}`;
const accountSid = () => `AC${hex()}`;
// API key secrets are mixed-case alphanumerics; Auth Tokens are 32 lowercase hex characters.
const apiSecret = () => `Zq${randomBytes(30).toString('base64url').replace(/[-_]/g, 'x').slice(0, 30)}`;
const basic = (user: string, password: string) => `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;

interface Setup {
  http: FakeHttp;
  ctx: ProviderContext;
  account: string;
  oldSid: string;
  oldSecret: string;
  adminSid: string;
  adminSecret: string;
}

function setup(siblings?: Record<string, string>): Setup {
  const http = new FakeHttp();
  const account = accountSid();
  const oldSid = keySid();
  const oldSecret = apiSecret();
  const adminSid = keySid();
  const adminSecret = apiSecret();
  const ctx: ProviderContext = {
    http,
    credentials: { TWILIO_ADMIN_KEY_SID: adminSid, TWILIO_ADMIN_KEY: adminSecret, TWILIO_ADMIN_ACCOUNT_SID: account },
    siblingVars: siblings ?? { TWILIO_ACCOUNT_SID: account, TWILIO_API_KEY: oldSid, TWILIO_API_SECRET: oldSecret, PORT: '3000' },
    log: silentLogger,
  };
  return { http, ctx, account, oldSid, oldSecret, adminSid, adminSecret };
}

const applicationsUrl = (account: string) =>
  new RegExp(`^https://api\\.twilio\\.com/2010-04-01/Accounts/${account}/Applications\\.json\\?PageSize=1$`);
const keyUrl = (sid: string) => new RegExp(`^https://iam\\.twilio\\.com/v1/Keys/${sid}$`);
const listProbeUrl = (account: string) => new RegExp(`^https://iam\\.twilio\\.com/v1/Keys\\?AccountSid=${account}&PageSize=1$`);

function standardRoutes(s: Setup, opts: { probeStatus?: number; policy?: unknown; newSid?: string; newSecret?: string } = {}) {
  const newSid = opts.newSid ?? keySid();
  const newSecret = opts.newSecret ?? apiSecret();
  s.http
    .on('GET', keyUrl(s.oldSid), (req) => {
      expect(req.headers?.Authorization === basic(s.adminSid, s.adminSecret)).toBe(true);
      return json(200, { sid: s.oldSid, friendly_name: 'production', policy: opts.policy ?? null,
        date_created: 'Mon, 13 Jun 2016 22:50:08 +0000', date_updated: 'Mon, 13 Jun 2016 22:50:08 +0000' });
    })
    .on('GET', applicationsUrl(s.account), (req) => {
      expect(req.headers?.Authorization === basic(s.oldSid, s.oldSecret)).toBe(true);
      return json(200, { applications: [], page: 0, page_size: 1 });
    })
    .on('GET', listProbeUrl(s.account), (req) => {
      expect(req.headers?.Authorization === basic(s.oldSid, s.oldSecret)).toBe(true);
      return json(opts.probeStatus ?? 401, { code: 20003, message: 'Authenticate' });
    })
    .on('POST', /^https:\/\/iam\.twilio\.com\/v1\/Keys$/, (req) => {
      const body = new URLSearchParams(req.body ?? '');
      const policy = body.get('Policy');
      return json(201, { sid: newSid, secret: newSecret, friendly_name: body.get('FriendlyName'),
        policy: policy === null ? null : JSON.parse(policy) });
    });
  return { newSid, newSecret };
}

async function rejection(operation: Promise<unknown>): Promise<unknown> {
  try {
    await operation;
  } catch (error) {
    return error;
  }
  return undefined;
}

function leaks(value: unknown, ...secrets: string[]): boolean {
  const serialized = value instanceof Error ? `${value.name} ${value.message}` : JSON.stringify(value);
  return secrets.some(secret => serialized.includes(secret));
}

const mutations = (calls: HttpRequest[]) => calls.filter(call => call.method !== 'GET');

describe('twilioProvider verify', () => {
  it('verifies an API key secret with its paired SID through a cheap account read', async () => {
    const s = setup();
    s.http.on('GET', applicationsUrl(s.account), (req) => {
      expect(req.headers?.Authorization === basic(s.oldSid, s.oldSecret)).toBe(true);
      expect(req.body).toBeUndefined();
      return json(200, { applications: [], page: 0 });
    });
    expect(await twilioProvider.verify(s.oldSecret, s.ctx)).toEqual({ ok: true, status: 200, identity: 'Twilio API key' });
    expect(s.http.calls).toHaveLength(1);
  });

  it('verifies an account Auth Token with the Account SID as the username', async () => {
    const account = accountSid();
    const token = hex();
    const s = setup({ TWILIO_ACCOUNT_SID: account, TWILIO_AUTH_TOKEN: token });
    s.http.on('GET', applicationsUrl(account), (req) => {
      expect(req.headers?.Authorization === basic(account, token)).toBe(true);
      return json(200, { applications: [] });
    });
    expect(await twilioProvider.verify(token, s.ctx)).toEqual({ ok: true, status: 200, identity: 'Twilio account' });
  });

  it('pairs a secret with the SID that shares its variable prefix', async () => {
    const account = accountSid();
    const [sidA, sidB] = [keySid(), keySid()];
    const [secretA, secretB] = [apiSecret(), apiSecret()];
    const s = setup({ TWILIO_ACCOUNT_SID: account, SMS_API_KEY: sidA, SMS_API_SECRET: secretA,
      VOICE_API_KEY_SID: sidB, VOICE_API_KEY_SECRET: secretB });
    s.http.on('GET', applicationsUrl(account), (req) => {
      expect(req.headers?.Authorization === basic(sidB, secretB)).toBe(true);
      return json(200, { applications: [] });
    });
    expect((await twilioProvider.verify(secretB, s.ctx)).ok).toBe(true);
    expect(await twilioProvider.resolveKeyRef!(secretB, s.ctx) === sidB).toBe(true);
  });

  it('reports invalid credentials without echoing the response body', async () => {
    const s = setup();
    s.http.on('GET', applicationsUrl(s.account), () => json(401, { message: s.oldSecret, code: 20003 }));
    const result = await twilioProvider.verify(s.oldSecret, s.ctx);
    expect(result.ok).toBe(false);
    expect(result.status).toBe(401);
    expect(leaks(result, s.oldSecret, s.adminSecret)).toBe(false);
  });

  it('treats a 403 as valid-but-limited for API keys only', async () => {
    const s = setup();
    s.http.on('GET', applicationsUrl(s.account), () => json(403, { message: 'denied' }));
    const limited = await twilioProvider.verify(s.oldSecret, s.ctx);
    expect(limited.ok).toBe(true);
    expect(limited.identity).toMatch(/limited/);

    const account = accountSid();
    const token = hex();
    const t = setup({ TWILIO_ACCOUNT_SID: account, TWILIO_AUTH_TOKEN: token });
    t.http.on('GET', applicationsUrl(account), () => json(403, { message: 'denied' }));
    expect((await twilioProvider.verify(token, t.ctx)).ok).toBe(false);
  });

  it('sanitizes transport and parse failures', async () => {
    for (const kind of ['transport', 'parse'] as const) {
      const s = setup();
      s.http.on('GET', applicationsUrl(s.account), () => {
        if (kind === 'transport') throw new Error(`${s.oldSecret} ${s.adminSecret}`);
        return text(200, s.oldSecret);
      });
      const result = await twilioProvider.verify(s.oldSecret, s.ctx);
      expect(result.ok).toBe(false);
      expect(leaks(result, s.oldSecret, s.adminSecret)).toBe(false);
    }
  });

  it('reports unverified without a request when the pair is incomplete or ambiguous', async () => {
    const secret = apiSecret();
    for (const siblings of [
      { TWILIO_API_SECRET: secret },
      { TWILIO_ACCOUNT_SID: accountSid(), TWILIO_API_SECRET: secret, ONE_SID: keySid(), TWO_SID: keySid() },
      { TWILIO_AUTH_TOKEN: hex() },
    ]) {
      const s = setup(siblings);
      s.ctx.credentials = {};
      const value = siblings.TWILIO_API_SECRET ?? siblings.TWILIO_AUTH_TOKEN!;
      expect(await twilioProvider.verify(value, s.ctx)).toEqual({ ok: true, identity: 'unverified' });
      expect(s.http.calls).toHaveLength(0);
    }
  });

  it('uses the configured admin account SID when the service lists only the key pair', async () => {
    const s = setup();
    s.ctx.siblingVars = { TWILIO_API_KEY: s.oldSid, TWILIO_API_SECRET: s.oldSecret };
    s.http.on('GET', applicationsUrl(s.account), () => json(200, { applications: [] }));
    expect((await twilioProvider.verify(s.oldSecret, s.ctx)).ok).toBe(true);
  });
});

describe('twilioProvider rotate', () => {
  it('creates a Standard replacement and returns the new SID as a companion', async () => {
    const s = setup();
    const [newSid, newSecret] = [keySid(), apiSecret()];
    // FakeHttp uses the first matching route, so this POST assertion precedes the shared routes.
    s.http.on('POST', /^https:\/\/iam\.twilio\.com\/v1\/Keys$/, (req) => {
      expect(req.headers?.Authorization === basic(s.adminSid, s.adminSecret)).toBe(true);
      expect(req.headers?.['Content-Type']).toBe('application/x-www-form-urlencoded');
      const body = new URLSearchParams(req.body ?? '');
      expect([...body.keys()].sort()).toEqual(['AccountSid', 'FriendlyName']);
      expect(body.get('AccountSid') === s.account).toBe(true);
      expect(body.get('FriendlyName')).toMatch(/^keysentry-\d{4}-\d{2}-\d{2}T/);
      expect(body.get('FriendlyName')!.length <= 64).toBe(true);
      return json(201, { sid: newSid, secret: newSecret, friendly_name: body.get('FriendlyName'), policy: null });
    });
    standardRoutes(s, { newSid, newSecret });
    const result = await twilioProvider.rotate!(s.oldSecret, s.ctx);
    expect(result.newValue === newSecret).toBe(true);
    expect(result.oldKeyRef === s.oldSid).toBe(true);
    expect(result.newKeyRef === newSid).toBe(true);
    expect(result.oldRevoked).toBe(false);
    expect(result.companions).toEqual({ TWILIO_API_KEY: newSid });
    // The pair is proven (the secret authenticates as the SID) before the key's policy is read.
    expect(s.http.calls.map(call => `${call.method} ${new URL(call.url).host}${new URL(call.url).pathname}`)).toEqual([
      `GET api.twilio.com/2010-04-01/Accounts/${s.account}/Applications.json`,
      `GET iam.twilio.com/v1/Keys/${s.oldSid}`,
      'GET iam.twilio.com/v1/Keys',
      'POST iam.twilio.com/v1/Keys',
    ]);
    const post = s.http.calls[3]!;
    expect(post.body?.includes(s.oldSecret)).toBe(false);
  });

  it('updates every variable that holds the old SID', async () => {
    const s = setup();
    s.ctx.siblingVars = { TWILIO_ACCOUNT_SID: s.account, TWILIO_API_KEY: s.oldSid, TWILIO_API_SECRET: s.oldSecret, TWILIO_KEY_SID_COPY: s.oldSid };
    const { newSid } = standardRoutes(s);
    const result = await twilioProvider.rotate!(s.oldSecret, s.ctx);
    expect(result.companions).toEqual({ TWILIO_API_KEY: newSid, TWILIO_KEY_SID_COPY: newSid });
  });

  it('copies a Restricted key policy after proving the pair, without probing for Main access', async () => {
    const s = setup();
    const policy = { allow: ['/twilio/messaging/messages/read', '/twilio/messaging/messages/create'] };
    const { newSid } = standardRoutes(s, { policy });
    const result = await twilioProvider.rotate!(s.oldSecret, s.ctx);
    expect(result.newKeyRef === newSid).toBe(true);
    const post = s.http.callsTo('POST', /\/v1\/Keys$/)[0]!;
    const body = new URLSearchParams(post.body ?? '');
    expect([...body.keys()].sort()).toEqual(['AccountSid', 'FriendlyName', 'KeyType', 'Policy']);
    expect(body.get('KeyType')).toBe('restricted');
    expect(JSON.parse(body.get('Policy')!)).toEqual(policy);
    // One authentication as the old key proves the pair; a Restricted key is never probed for Main access.
    const proofs = s.http.callsTo('GET', /Applications\.json/);
    expect(proofs).toHaveLength(1);
    expect(proofs[0]!.headers?.Authorization === basic(s.oldSid, s.oldSecret)).toBe(true);
    expect(s.http.callsTo('GET', /\/v1\/Keys\?/)).toHaveLength(0);
  });

  it('requires guided rotation when the old key can manage keys (a Main key)', async () => {
    const s = setup();
    standardRoutes(s, { probeStatus: 200 });
    const error = await rejection(twilioProvider.rotate!(s.oldSecret, s.ctx));
    expect(error instanceof TwilioGuidedRotationRequiredError).toBe(true);
    expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED', provider: 'twilio' });
    expect(mutations(s.http.calls)).toHaveLength(0);
  });

  it.each([429, 500])('requires guided rotation when the Main-key probe is inconclusive (HTTP %s)', async (status) => {
    const s = setup();
    standardRoutes(s, { probeStatus: status });
    expect(await rejection(twilioProvider.rotate!(s.oldSecret, s.ctx))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(mutations(s.http.calls)).toHaveLength(0);
  });

  it('requires guided rotation for the account Auth Token before any request', async () => {
    const account = accountSid();
    const token = hex();
    const s = setup({ TWILIO_ACCOUNT_SID: account, TWILIO_AUTH_TOKEN: token });
    s.ctx.credentials.TWILIO_ADMIN_ACCOUNT_SID = account;
    const error = await rejection(twilioProvider.rotate!(token, s.ctx));
    expect(error).toMatchObject({ name: 'TwilioGuidedRotationRequiredError', code: 'GUIDED_ROTATION_REQUIRED' });
    expect(leaks(error, token)).toBe(false);
    expect(s.http.calls).toHaveLength(0);
  });

  it('requires guided rotation when the key belongs to another account', async () => {
    const s = setup();
    s.ctx.siblingVars = { ...s.ctx.siblingVars, TWILIO_ACCOUNT_SID: accountSid() };
    expect(await rejection(twilioProvider.rotate!(s.oldSecret, s.ctx))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(s.http.calls).toHaveLength(0);
  });

  it('requires guided rotation when the service does not name the account', async () => {
    const s = setup();
    s.ctx.siblingVars = { TWILIO_API_KEY: s.oldSid, TWILIO_API_SECRET: s.oldSecret };
    expect(await rejection(twilioProvider.rotate!(s.oldSecret, s.ctx))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(s.http.calls).toHaveLength(0);
  });

  it('requires guided rotation when the old key metadata cannot be reproduced', async () => {
    const s0 = setup();
    for (const response of [
      json(404, { message: 'not found' }),
      json(200, { sid: s0.oldSid, friendly_name: 'x' }),
      json(200, { sid: keySid(), policy: null }),
      json(200, { sid: s0.oldSid, policy: { allow: [] } }),
      json(200, { sid: s0.oldSid, policy: { allow: ['/twilio/x'], deny: ['/twilio/y'] } }),
      json(200, { sid: s0.oldSid, policy: { allow: [7] } }),
      json(200, { sid: s0.oldSid, policy: 'all' }),
      json(500, { message: s0.adminSecret }),
      text(200, s0.oldSecret),
    ]) {
      const s = setup();
      s.ctx.siblingVars = { TWILIO_ACCOUNT_SID: s.account, TWILIO_API_KEY: s0.oldSid, TWILIO_API_SECRET: s.oldSecret };
      s.http.on('GET', keyUrl(s0.oldSid), () => response)
        .on('POST', /\/v1\/Keys$/, () => json(201, { sid: keySid(), secret: apiSecret(), policy: null }));
      const error = await rejection(twilioProvider.rotate!(s.oldSecret, s.ctx));
      expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED', provider: 'twilio' });
      expect(leaks(error, s.oldSecret, s.adminSecret, s0.adminSecret, s0.oldSecret)).toBe(false);
      expect(mutations(s.http.calls)).toHaveLength(0);
    }
  });

  it('requires guided rotation when the old Standard key does not authenticate', async () => {
    const s = setup();
    s.http.on('GET', applicationsUrl(s.account), () => json(401, { message: 'bad' }));
    standardRoutes(s);
    expect(await rejection(twilioProvider.rotate!(s.oldSecret, s.ctx))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(mutations(s.http.calls)).toHaveLength(0);
  });

  it('refuses to rotate the management key itself', async () => {
    const s = setup();
    s.ctx.credentials.TWILIO_ADMIN_KEY_SID = s.oldSid;
    s.ctx.credentials.TWILIO_ADMIN_KEY = s.oldSecret;
    expect(await rejection(twilioProvider.rotate!(s.oldSecret, s.ctx))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(s.http.calls).toHaveLength(0);
  });

  it('requires the management credentials before any request', async () => {
    for (const missing of ['TWILIO_ADMIN_KEY_SID', 'TWILIO_ADMIN_KEY', 'TWILIO_ADMIN_ACCOUNT_SID']) {
      const s = setup();
      delete s.ctx.credentials[missing];
      const error = await rejection(twilioProvider.rotate!(s.oldSecret, s.ctx));
      expect(String(error)).toMatch(new RegExp(missing));
      expect(s.http.calls).toHaveLength(0);
    }
  });

  it('accepts the Account SID and Auth Token as the management credential', async () => {
    const s = setup();
    const authToken = hex();
    s.ctx.credentials = { TWILIO_ADMIN_KEY_SID: s.account, TWILIO_ADMIN_KEY: authToken };
    s.adminSid = s.account;
    s.adminSecret = authToken;
    standardRoutes(s);
    expect((await twilioProvider.rotate!(s.oldSecret, s.ctx)).oldKeyRef === s.oldSid).toBe(true);
  });

  it('removes a replacement whose permissions differ from the request', async () => {
    const s = setup();
    const newSid = keySid();
    s.http.on('POST', /\/v1\/Keys$/, () => json(201, { sid: newSid, secret: apiSecret(), policy: { allow: ['/twilio'] } }))
      .on('DELETE', keyUrl(newSid), (req) => {
        expect(req.headers?.Authorization === basic(s.adminSid, s.adminSecret)).toBe(true);
        return text(204, '');
      });
    standardRoutes(s);
    const error = await rejection(twilioProvider.rotate!(s.oldSecret, s.ctx));
    expect(error).toBeInstanceOf(Error);
    expect(s.http.callsTo('DELETE', keyUrl(newSid))).toHaveLength(1);

    const t = setup();
    t.http.on('POST', /\/v1\/Keys$/, () => json(201, { sid: newSid, secret: apiSecret(), policy: { allow: ['/twilio'] } }))
      .on('DELETE', keyUrl(newSid), () => json(500, { message: t.adminSecret }));
    standardRoutes(t);
    const unremoved = await rejection(twilioProvider.rotate!(t.oldSecret, t.ctx));
    expect(String(unremoved)).toMatch(/Twilio Console/);
    expect(unremoved).not.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(leaks(unremoved, t.adminSecret)).toBe(false);
  });

  it('rejects malformed creation responses without echoing values', async () => {
    const newSecret = apiSecret();
    for (const body of [{ sid: keySid() }, { sid: 'bad', secret: newSecret, policy: null }, { secret: newSecret, policy: null },
      { sid: keySid(), secret: '', policy: null }]) {
      const s = setup();
      s.http.on('POST', /\/v1\/Keys$/, () => json(201, body));
      standardRoutes(s);
      const error = await rejection(twilioProvider.rotate!(s.oldSecret, s.ctx));
      expect(error).toBeInstanceOf(Error);
      expect(leaks(error, newSecret, s.oldSecret, s.adminSecret)).toBe(false);
    }
  });

  it.each([400, 401, 500])('sanitizes HTTP %s creation failures', async (status) => {
    const s = setup();
    s.http.on('POST', /\/v1\/Keys$/, () => json(status, { message: `${s.adminSecret} ${s.oldSecret}` }));
    standardRoutes(s);
    const error = await rejection(twilioProvider.rotate!(s.oldSecret, s.ctx));
    expect(String(error)).toMatch(new RegExp(`HTTP ${status}`));
    expect(leaks(error, s.adminSecret, s.oldSecret)).toBe(false);
  });

  it('never rotates by reference because the SID variable and key type are unknown', async () => {
    const s = setup();
    expect(await rejection(twilioProvider.rotateByRef!(s.oldSid, s.ctx))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(s.http.calls).toHaveLength(0);
  });
});

describe('twilioProvider revoke, resolve and list', () => {
  it('deletes a key by SID with the management credential', async () => {
    const s = setup();
    s.http.on('DELETE', keyUrl(s.oldSid), (req) => {
      expect(req.headers?.Authorization === basic(s.adminSid, s.adminSecret)).toBe(true);
      expect(req.body).toBeUndefined();
      return text(204, '');
    });
    await twilioProvider.revoke!(s.oldSid, s.ctx);
    expect(s.http.calls).toHaveLength(1);
  });

  it('refuses malformed refs and the management key itself before any request', async () => {
    const s = setup();
    for (const ref of ['bad', `${keySid()}/x`, s.adminSid, s.oldSecret, accountSid()]) {
      expect(await rejection(twilioProvider.revoke!(ref, s.ctx))).toBeInstanceOf(Error);
    }
    expect(s.http.calls).toHaveLength(0);
  });

  it('sanitizes deletion failures', async () => {
    const s = setup();
    s.http.on('DELETE', keyUrl(s.oldSid), () => json(404, { message: s.adminSecret }));
    const error = await rejection(twilioProvider.revoke!(s.oldSid, s.ctx));
    expect(String(error)).toMatch(/HTTP 404/);
    expect(leaks(error, s.adminSecret)).toBe(false);
  });

  it('resolves the paired SID only after the pair authenticates', async () => {
    const s = setup();
    s.http.on('GET', applicationsUrl(s.account), () => json(200, { applications: [] }));
    expect(await twilioProvider.resolveKeyRef!(s.oldSecret, s.ctx) === s.oldSid).toBe(true);

    const t = setup();
    t.http.on('GET', applicationsUrl(t.account), () => json(401, {}));
    expect(await twilioProvider.resolveKeyRef!(t.oldSecret, t.ctx)).toBeNull();

    const account = accountSid();
    const token = hex();
    const u = setup({ TWILIO_ACCOUNT_SID: account, TWILIO_AUTH_TOKEN: token });
    expect(await twilioProvider.resolveKeyRef!(token, u.ctx)).toBeNull();
    expect(u.http.calls).toHaveLength(0);
  });

  it('lists every page and stops at a cursor that does not advance or leaves the API', async () => {
    const s = setup();
    const sids = [keySid(), keySid(), keySid()];
    const first = `https://iam.twilio.com/v1/Keys?AccountSid=${s.account}&PageSize=100`;
    const second = `https://iam.twilio.com/v1/Keys?AccountSid=${s.account}&PageSize=100&Page=1&PageToken=PA1`;
    s.http
      .on('GET', /PageToken=PA1$/, (req) => {
        expect(req.headers?.Authorization === basic(s.adminSid, s.adminSecret)).toBe(true);
        return json(200, { keys: [{ sid: sids[2], friendly_name: 'third' }], meta: { next_page_url: second } });
      })
      .on('GET', /\/v1\/Keys\?AccountSid=[^&]+&PageSize=100$/, (req) => {
        expect(req.url).toBe(first);
        return json(200, { keys: [
          { sid: sids[0], friendly_name: 'first', date_created: 'Mon, 13 Jun 2016 22:50:08 +0000', flags: ['rest_api'] },
          { sid: sids[1], friendly_name: 'second' },
        ], meta: { page: 0, page_size: 100, next_page_url: second } });
      });
    const keys = await twilioProvider.listKeys!(s.ctx);
    expect(keys.map(key => key.keyRef)).toEqual(sids);
    expect(keys[0]).toEqual({ keyRef: sids[0], name: 'first', createdAt: '2016-06-13T22:50:08.000Z' });
    expect(s.http.calls).toHaveLength(2);

    const t = setup();
    t.http.on('GET', /\/v1\/Keys\?/, () => json(200, { keys: [], meta: { next_page_url: `https://evil.example/v1/Keys?AccountSid=${t.account}` } }));
    expect(await rejection(twilioProvider.listKeys!(t.ctx))).toBeInstanceOf(Error);
    expect(t.http.calls).toHaveLength(1);
  });

  it('describes guided steps for both credential kinds', () => {
    expect(twilioProvider.id).toBe('twilio');
    expect(twilioProvider.method).toBe('auto');
    const guidance = twilioProvider.guidance();
    expect(guidance.url).toMatch(/^https:\/\/console\.twilio\.com\//);
    expect(guidance.steps.join(' ')).toMatch(/secondary Auth Token/);
    expect(guidance.steps.join(' ')).toMatch(/API key/);
  });
});
