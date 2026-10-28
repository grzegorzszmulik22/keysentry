import { randomBytes, randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { UpstashGuidedRotationRequiredError, upstashProvider } from '../../src/providers/upstash.js';
import type { HttpRequest, ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const token = (prefix = 'A') => `${prefix}${randomBytes(40).toString('base64url')}`;
const password = () => randomBytes(24).toString('hex');
const basic = (user: string, pass: string) => `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;

const databasesUrl = /^https:\/\/api\.upstash\.com\/v2\/redis\/databases$/;
const resetUrl = (id: string) => new RegExp(`^https://api\\.upstash\\.com/v2/redis/reset-password/${id}$`);
const usersUrl = /^https:\/\/api\.upstash\.com\/v2\/qstash\/users$/;
const rotateTokenUrl = (id: string) => new RegExp(`^https://api\\.upstash\\.com/v2/qstash/rotate-token/${id}$`);

interface Db { database_id: string; endpoint: string; port: number; password: string; rest_token: string; read_only_rest_token: string; state: string }

function database(): Db {
  return { database_id: randomUUID(), endpoint: `merry-cat-${randomBytes(3).toString('hex')}`, port: 6379,
    password: password(), rest_token: token(), read_only_rest_token: token('Ar'), state: 'active' };
}

const redisUrl = (db: Db, pass = db.password) => `rediss://default:${pass}@${db.endpoint}.upstash.io:${db.port}`;

interface Setup { http: FakeHttp; ctx: ProviderContext; email: string; adminKey: string; db: Db }

function setup(siblings: (db: Db) => Record<string, string> = () => ({})): Setup {
  const http = new FakeHttp();
  const db = database();
  const email = 'owner@example.com';
  const adminKey = randomUUID();
  return { http, db, email, adminKey,
    ctx: { http, credentials: { UPSTASH_ADMIN_EMAIL: email, UPSTASH_ADMIN_KEY: adminKey }, siblingVars: siblings(db), log: silentLogger } };
}

function listRoutes(s: Setup, others: Db[] = []) {
  s.http.on('GET', databasesUrl, (req) => {
    expect(req.headers?.Authorization === basic(s.email, s.adminKey)).toBe(true);
    return json(200, [...others, s.db].map(db => ({ ...db, database_name: 'cache', region: 'global', tls: true })));
  });
}

function resetRoute(s: Setup, fresh: Partial<Db> = {}) {
  const next = { password: password(), rest_token: token(), read_only_rest_token: token('Ar'), ...fresh };
  s.http.on('POST', resetUrl(s.db.database_id), (req) => {
    expect(req.headers?.Authorization === basic(s.email, s.adminKey)).toBe(true);
    expect(req.body).toBeUndefined();
    return json(200, { ...s.db, ...next });
  });
  return next;
}

async function rejection(operation: Promise<unknown>): Promise<unknown> {
  try {
    await operation;
  } catch (error) {
    return error;
  }
  return undefined;
}

const leaks = (value: unknown, ...secrets: string[]) => {
  const serialized = value instanceof Error ? `${value.name} ${value.message}` : JSON.stringify(value);
  return secrets.some(secret => serialized.includes(secret));
};
const mutations = (calls: HttpRequest[]) => calls.filter(call => call.method !== 'GET');

describe('upstashProvider verify', () => {
  it('verifies a Redis REST token against the paired REST URL with PING', async () => {
    const s = setup(db => ({ UPSTASH_REDIS_REST_URL: `https://${db.endpoint}.upstash.io`, UPSTASH_REDIS_REST_TOKEN: db.rest_token }));
    s.http.on('GET', new RegExp(`^https://${s.db.endpoint}\\.upstash\\.io/ping$`), (req) => {
      expect(req.headers?.Authorization === `Bearer ${s.db.rest_token}`).toBe(true);
      expect(req.body).toBeUndefined();
      return json(200, { result: 'PONG' });
    });
    expect(await upstashProvider.verify(s.db.rest_token, s.ctx)).toEqual({ ok: true, status: 200, identity: 'Upstash Redis REST token' });
  });

  it('pairs Vercel KV token names with their REST URL', async () => {
    const other = database();
    const s = setup(db => ({ KV_REST_API_URL: `https://${db.endpoint}.upstash.io/`, KV_REST_API_READ_ONLY_TOKEN: db.read_only_rest_token,
      CACHE_REST_URL: `https://${other.endpoint}.upstash.io` }));
    s.http.on('GET', new RegExp(`^https://${s.db.endpoint}\\.upstash\\.io/ping$`), () => json(200, { result: 'PONG' }));
    expect((await upstashProvider.verify(s.db.read_only_rest_token, s.ctx)).ok).toBe(true);
  });

  it('reports a rejected REST token as invalid without echoing the body', async () => {
    const s = setup(db => ({ UPSTASH_REDIS_REST_URL: `https://${db.endpoint}.upstash.io`, UPSTASH_REDIS_REST_TOKEN: db.rest_token }));
    s.http.on('GET', /\/ping$/, () => json(401, { error: s.db.rest_token }));
    const result = await upstashProvider.verify(s.db.rest_token, s.ctx);
    expect(result.ok).toBe(false);
    expect(result.status).toBe(401);
    expect(leaks(result, s.db.rest_token)).toBe(false);
  });

  it('never sends a token to a REST URL outside upstash.io', async () => {
    for (const url of ['https://evil.example.com', 'http://x.upstash.io', 'https://user:pw@x.upstash.io', 'https://x.upstash.io/path',
      'https://x.upstash.io?q=1', 'https://x.upstash.io.evil.com', 'https://qstash.upstash.io']) {
      const s = setup(db => ({ UPSTASH_REDIS_REST_URL: url, UPSTASH_REDIS_REST_TOKEN: db.rest_token }));
      expect(await upstashProvider.verify(s.db.rest_token, s.ctx)).toEqual({ ok: true, identity: 'unverified' });
      expect(s.http.calls).toHaveLength(0);
    }
  });

  it('verifies a QStash token in each documented region until one accepts it', async () => {
    const value = token('eyJ');
    const s = setup(() => ({ QSTASH_TOKEN: value }));
    s.http.on('GET', /^https:\/\/qstash-eu-central-1\.upstash\.io\/v2\/queues$/, () => json(401, { error: value }))
      .on('GET', /^https:\/\/qstash-us-east-1\.upstash\.io\/v2\/queues$/, (req) => {
        expect(req.headers?.Authorization === `Bearer ${value}`).toBe(true);
        return json(200, []);
      });
    expect(await upstashProvider.verify(value, s.ctx)).toEqual({ ok: true, status: 200, identity: 'Upstash QStash token' });
    expect(s.http.calls).toHaveLength(2);

    const t = setup(() => ({ QSTASH_TOKEN: value, QSTASH_URL: 'https://qstash.upstash.io' }));
    t.http.on('GET', /^https:\/\/qstash\.upstash\.io\/v2\/queues$/, () => json(401, {}));
    const rejected = await upstashProvider.verify(value, t.ctx);
    expect(rejected.ok).toBe(false);
    expect(t.http.calls).toHaveLength(1);
  });

  it('never sends QStash signing keys anywhere', async () => {
    const s = setup(() => ({ QSTASH_TOKEN: token('eyJ'), QSTASH_CURRENT_SIGNING_KEY: 'sig_abcdefghijklmnopqrstuvwx' }));
    expect(await upstashProvider.verify('sig_abcdefghijklmnopqrstuvwx', s.ctx)).toEqual({ ok: true, identity: 'unverified' });
    expect(s.http.calls).toHaveLength(0);
  });

  it('falls back to the only REST URL when the conventionally named one is not a REST URL', async () => {
    const s = setup(db => ({ REDIS_URL: redisUrl(db), REDIS_TOKEN: db.rest_token, CACHE_ENDPOINT: `https://${db.endpoint}.upstash.io` }));
    s.http.on('GET', new RegExp(`^https://${s.db.endpoint}\\.upstash\\.io/ping$`), () => json(200, { result: 'PONG' }));
    expect((await upstashProvider.verify(s.db.rest_token, s.ctx)).ok).toBe(true);
    expect(s.http.calls).toHaveLength(1);
  });

  it('reports Redis URLs and unpaired values as unverified without a request', async () => {
    const s = setup(db => ({ REDIS_URL: redisUrl(db), SOME_TOKEN: 'x'.repeat(30) }));
    expect(await upstashProvider.verify(redisUrl(s.db), s.ctx)).toEqual({ ok: true, identity: 'unverified' });
    expect(await upstashProvider.verify('x'.repeat(30), s.ctx)).toEqual({ ok: true, identity: 'unverified' });
    expect(s.http.calls).toHaveLength(0);
  });
});

describe('upstashProvider rotate (Redis)', () => {
  it('resets the database password and rewrites every same-service form of the credential', async () => {
    const s = setup(db => ({
      UPSTASH_REDIS_REST_URL: `https://${db.endpoint}.upstash.io`, UPSTASH_REDIS_REST_TOKEN: db.rest_token,
      KV_REST_API_TOKEN: db.rest_token, REDIS_URL: redisUrl(db), KV_URL: `redis://default:${db.password}@${db.endpoint}.upstash.io:6379/0`,
      REDIS_PASSWORD: db.password, KV_REST_API_READ_ONLY_TOKEN: db.read_only_rest_token, NODE_ENV: 'production',
      OTHER_REDIS_URL: `rediss://default:${db.password}@another-db.upstash.io:6379`,
    }));
    listRoutes(s, [database()]);
    const fresh = resetRoute(s);
    const result = await upstashProvider.rotate!(s.db.rest_token, s.ctx);
    expect(result.newValue === fresh.rest_token).toBe(true);
    expect(result.oldKeyRef).toBe(s.db.database_id);
    expect(result.newKeyRef).toBe(s.db.database_id);
    expect(result.oldRevoked).toBe(true);
    expect(result.companions).toEqual({
      REDIS_URL: `rediss://default:${fresh.password}@${s.db.endpoint}.upstash.io:6379`,
      KV_URL: `redis://default:${fresh.password}@${s.db.endpoint}.upstash.io:6379/0`,
      REDIS_PASSWORD: fresh.password,
      KV_REST_API_READ_ONLY_TOKEN: fresh.read_only_rest_token,
    });
    expect(result.notes).toMatch(/stopped working/);
    expect(leaks(result.notes, s.db.password, fresh.password, s.db.rest_token, fresh.rest_token)).toBe(false);
    expect(mutations(s.http.calls)).toHaveLength(1);
  });

  it('rotates a Redis URL and returns the URL with the new password', async () => {
    const s = setup(db => ({ REDIS_URL: redisUrl(db), UPSTASH_REDIS_REST_TOKEN: db.rest_token }));
    listRoutes(s);
    const fresh = resetRoute(s);
    const result = await upstashProvider.rotate!(redisUrl(s.db), s.ctx);
    expect(result.newValue === redisUrl(s.db, fresh.password)).toBe(true);
    expect(result.companions).toEqual({ UPSTASH_REDIS_REST_TOKEN: fresh.rest_token });
  });

  it('notes a read-only token that may have changed when the reset response omits it', async () => {
    const s = setup(db => ({ UPSTASH_REDIS_REST_TOKEN: db.rest_token, KV_REST_API_READ_ONLY_TOKEN: db.read_only_rest_token }));
    listRoutes(s);
    s.http.on('POST', resetUrl(s.db.database_id), () => {
      const { read_only_rest_token: _omitted, ...rest } = s.db;
      return json(200, { ...rest, password: password(), rest_token: token() });
    });
    const result = await upstashProvider.rotate!(s.db.rest_token, s.ctx);
    expect(result.companions).toBeUndefined();
    expect(result.notes).toMatch(/read-only/);
  });

  it('requires guided rotation before any reset when the credential cannot be identified exactly', async () => {
    const cases: [string, (s: Setup) => string][] = [
      ['read-only token', s => { listRoutes(s); return s.db.read_only_rest_token; }],
      ['unknown value', s => { listRoutes(s); s.http.on('GET', usersUrl, () => json(200, [])); return token(); }],
      ['ambiguous', s => {
        s.http.on('GET', databasesUrl, () => json(200, [s.db, { ...database(), rest_token: s.db.rest_token }]));
        return s.db.rest_token;
      }],
      ['protected credentials', s => {
        const { password: _p, ...withoutPassword } = s.db;
        s.http.on('GET', databasesUrl, () => json(200, [withoutPassword]));
        return s.db.rest_token;
      }],
      ['inactive', s => { s.http.on('GET', databasesUrl, () => json(200, [{ ...s.db, state: 'suspended' }])); return s.db.rest_token; }],
      ['wrong host', s => { listRoutes(s); return `rediss://default:${s.db.password}@elsewhere.upstash.io:6379`; }],
      ['list 401', s => { s.http.on('GET', databasesUrl, () => json(401, { error: s.adminKey })); return s.db.rest_token; }],
      ['list malformed', s => { s.http.on('GET', databasesUrl, () => text(200, s.adminKey)); return s.db.rest_token; }],
      ['bad id', s => { s.http.on('GET', databasesUrl, () => json(200, [{ ...s.db, database_id: '../x' }])); return s.db.rest_token; }],
    ];
    for (const [, arrange] of cases) {
      const s = setup();
      const value = arrange(s);
      s.http.on('POST', /./, () => json(200, {}));
      const error = await rejection(upstashProvider.rotate!(value, s.ctx));
      expect(error instanceof UpstashGuidedRotationRequiredError).toBe(true);
      expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED', provider: 'upstash' });
      expect(leaks(error, s.db.password, s.db.rest_token, s.adminKey)).toBe(false);
      expect(mutations(s.http.calls)).toHaveLength(0);
    }
  });

  it('requires the management credentials before any request', async () => {
    for (const missing of ['UPSTASH_ADMIN_EMAIL', 'UPSTASH_ADMIN_KEY']) {
      const s = setup();
      delete s.ctx.credentials[missing];
      expect(String(await rejection(upstashProvider.rotate!(s.db.rest_token, s.ctx)))).toMatch(new RegExp(missing));
      expect(s.http.calls).toHaveLength(0);
    }
  });

  it('reports a reset without usable new credentials as urgent and value-free', async () => {
    for (const fresh of [{ password: undefined, rest_token: undefined }, { rest_token: '' }]) {
      const s = setup();
      listRoutes(s);
      s.http.on('POST', resetUrl(s.db.database_id), () => json(200, { ...s.db, ...fresh }));
      const error = await rejection(upstashProvider.rotate!(s.db.rest_token, s.ctx));
      expect(String(error)).toMatch(/old credentials may already be invalid/);
      expect(error).not.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
      expect(leaks(error, s.db.password, s.db.rest_token)).toBe(false);
    }
  });

  it.each([400, 500])('sanitizes HTTP %s reset failures', async (status) => {
    const s = setup();
    listRoutes(s);
    s.http.on('POST', resetUrl(s.db.database_id), () => json(status, { error: `${s.adminKey} ${s.db.password}` }));
    const error = await rejection(upstashProvider.rotate!(s.db.rest_token, s.ctx));
    expect(String(error)).toMatch(new RegExp(`HTTP ${status}`));
    // Only an unanswered or 5xx reset may already have happened.
    expect(/may already have happened/.test(String(error))).toBe(status === 500);
    expect(leaks(error, s.adminKey, s.db.password)).toBe(false);
  });

  it('says an unanswered reset may already have happened', async () => {
    const s = setup();
    listRoutes(s);
    s.http.on('POST', resetUrl(s.db.database_id), () => { throw new Error(`${s.adminKey} ${s.db.password}`); });
    const error = await rejection(upstashProvider.rotate!(s.db.rest_token, s.ctx));
    expect(String(error)).toMatch(/may already have happened/);
    expect(error).not.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(leaks(error, s.adminKey, s.db.password)).toBe(false);
  });
});

describe('upstashProvider rotate (QStash) and references', () => {
  it('rotates a QStash token found in the management user list', async () => {
    const user = { id: randomUUID(), token: token('eyJ'), read_only_token: token('eyR'), region: 'us-east-1', state: 'active' };
    const fresh = { token: token('eyJ'), read_only_token: token('eyR') };
    const s = setup(() => ({ QSTASH_TOKEN: user.token, QSTASH_READ_ONLY_TOKEN: user.read_only_token, QSTASH_CURRENT_SIGNING_KEY: 'sig_x' }));
    listRoutes(s);
    s.http.on('GET', usersUrl, (req) => {
      expect(req.headers?.Authorization === basic(s.email, s.adminKey)).toBe(true);
      return json(200, [user]);
    }).on('POST', rotateTokenUrl(user.id), (req) => {
      expect(req.headers?.Authorization === basic(s.email, s.adminKey)).toBe(true);
      return json(200, { ...user, ...fresh });
    });
    const result = await upstashProvider.rotate!(user.token, s.ctx);
    expect(result.newValue === fresh.token).toBe(true);
    expect(result.oldKeyRef).toBe(user.id);
    expect(result.oldRevoked).toBe(true);
    expect(result.companions).toEqual({ QSTASH_READ_ONLY_TOKEN: fresh.read_only_token });
    expect(mutations(s.http.calls).map(call => call.url)).toEqual([`https://api.upstash.com/v2/qstash/rotate-token/${user.id}`]);

    const t = setup();
    listRoutes(t);
    t.http.on('GET', usersUrl, () => json(200, [user])).on('POST', /./, () => json(200, {}));
    expect(await rejection(upstashProvider.rotate!(user.read_only_token, t.ctx))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(mutations(t.http.calls)).toHaveLength(0);
  });

  it('reports a QStash rotation without a new token as urgent', async () => {
    const user = { id: randomUUID(), token: token('eyJ') };
    const s = setup();
    listRoutes(s);
    s.http.on('GET', usersUrl, () => json(200, [user])).on('POST', rotateTokenUrl(user.id), () => json(200, { id: user.id, token: user.token }));
    const error = await rejection(upstashProvider.rotate!(user.token, s.ctx));
    expect(String(error)).toMatch(/may already be invalid/);
    expect(leaks(error, user.token)).toBe(false);
  });

  it('resolves exact matches to database or QStash user ids', async () => {
    const user = { id: randomUUID(), token: token('eyJ') };
    const s = setup();
    listRoutes(s);
    s.http.on('GET', usersUrl, () => json(200, [user]));
    expect(await upstashProvider.resolveKeyRef!(s.db.rest_token, s.ctx)).toBe(s.db.database_id);
    expect(await upstashProvider.resolveKeyRef!(redisUrl(s.db), s.ctx)).toBe(s.db.database_id);
    expect(await upstashProvider.resolveKeyRef!(user.token, s.ctx)).toBe(user.id);
    expect(await upstashProvider.resolveKeyRef!(token(), s.ctx)).toBeNull();
  });

  it('lists every current form of a database or QStash user by reference, for the engine to look for', async () => {
    const user = { id: randomUUID(), token: token('eyJ'), read_only_token: token('eyR') };
    const other = database();
    const s = setup();
    listRoutes(s, [other]);
    s.http.on('GET', usersUrl, () => json(200, [user]));
    const forms = (await upstashProvider.credentialForms(s.db.database_id, s.ctx))!;
    expect(forms.values).toEqual(expect.arrayContaining([s.db.password, s.db.rest_token, s.db.read_only_rest_token, redisUrl(s.db)]));
    for (const value of [s.db.password, `${s.db.rest_token}\n`, s.db.read_only_rest_token, redisUrl(s.db),
      `redis://:${s.db.password}@${s.db.endpoint}.upstash.io:6380/0?ssl=true`]) expect(forms.holds(value)).toBe(true);
    for (const value of [other.password, other.rest_token, redisUrl(other), `rediss://default:${s.db.password}@elsewhere.example.com:6379`, user.token]) {
      expect(forms.holds(value)).toBe(false);
    }
    const qstash = (await upstashProvider.credentialForms(user.id, s.ctx))!;
    expect(qstash.values.sort()).toEqual([user.token, user.read_only_token].sort());
    expect(qstash.holds(user.read_only_token)).toBe(true);
    expect(qstash.holds(s.db.password)).toBe(false);
    expect(await upstashProvider.credentialForms(randomUUID(), s.ctx)).toBeNull();
    expect(mutations(s.http.calls)).toEqual([]);
  });

  it('never rotates by reference', async () => {
    const s = setup();
    expect(await rejection(upstashProvider.rotateByRef!(s.db.database_id, s.ctx))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(s.http.calls).toHaveLength(0);
  });

  it('declares an atomic roll and gives console guidance', () => {
    expect(upstashProvider.id).toBe('upstash');
    expect(upstashProvider.method).toBe('atomic-roll');
    expect(upstashProvider.revoke).toBeUndefined();
    const guidance = upstashProvider.guidance();
    expect(guidance.url).toBe('https://console.upstash.com/');
    expect(guidance.steps.join(' ')).toMatch(/Reset token/);
  });
});
