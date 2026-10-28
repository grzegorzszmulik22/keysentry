import { generateKeyPairSync, randomBytes, verify as verifySignature } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  createGoogleProvider, GOOGLE_CREDENTIALS, GoogleGuidedRotationRequiredError, googleProvider,
} from '../../src/providers/google.js';
import type { HttpRequest, ProviderContext } from '../../src/types.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const PEM = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
const ADMIN_EMAIL = 'rotator@demo-project.iam.gserviceaccount.com';
const PROJECT = '123456789012';
const KEYS = `projects/${PROJECT}/locations/global/keys`;
const OLD = `${KEYS}/old-key`;
const OTHER = `${KEYS}/other-key`;
const NEW = `${KEYS}/new-key`;
const API = 'https://apikeys.googleapis.com/v2';
const LIST = /^https:\/\/apikeys\.googleapis\.com\/v2\/projects\/demo-project\/locations\/global\/keys$/;
const TOKEN = /^https:\/\/oauth2\.googleapis\.com\/token$/;

const apiKey = () => `AIza${randomBytes(27).toString('base64url').slice(0, 35)}`;
const accessToken = () => `ya29.${randomBytes(32).toString('base64url')}`;
const serviceAccount = (overrides: Record<string, unknown> = {}) => JSON.stringify({
  type: 'service_account', project_id: 'demo-project', private_key_id: 'abc123def456', private_key: PEM,
  client_email: ADMIN_EMAIL, token_uri: 'https://oauth2.googleapis.com/token', ...overrides,
});
const provider = (sleeps: number[] = []) => createGoogleProvider({ sleep: async (ms) => { sleeps.push(ms); }, now: () => new Date() });

function context(http: FakeHttp, credentials: Record<string, string | undefined> = { GOOGLE_API_KEYS_ADMIN_KEY: serviceAccount() }): ProviderContext {
  return { http, credentials, log: silentLogger };
}

function decodeJwt(assertion: string) {
  const [header, claims, signature] = assertion.split('.');
  const valid = verifySignature('sha256', Buffer.from(`${header}.${claims}`), publicKey, Buffer.from(signature!, 'base64url'));
  return {
    valid,
    header: JSON.parse(Buffer.from(header!, 'base64url').toString('utf8')) as Record<string, unknown>,
    claims: JSON.parse(Buffer.from(claims!, 'base64url').toString('utf8')) as Record<string, unknown>,
  };
}

/** Token endpoint that checks the RS256 JWT bearer assertion and returns `token`. */
function tokenRoute(http: FakeHttp, token: string, scope = 'https://www.googleapis.com/auth/cloud-platform') {
  return http.on('POST', TOKEN, (req) => {
    expect(req.headers?.['Content-Type']).toBe('application/x-www-form-urlencoded');
    expect(req.headers?.Authorization).toBeUndefined();
    const form = new URLSearchParams(req.body!);
    expect([...form.keys()].sort()).toEqual(['assertion', 'grant_type']);
    expect(form.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer');
    const jwt = decodeJwt(form.get('assertion')!);
    expect(jwt.valid).toBe(true);
    expect(jwt.header).toEqual({ alg: 'RS256', typ: 'JWT', kid: 'abc123def456' });
    expect(jwt.claims.iss).toBe(ADMIN_EMAIL);
    expect(jwt.claims.scope).toBe(scope);
    expect(jwt.claims.aud).toBe('https://oauth2.googleapis.com/token');
    expect(Number(jwt.claims.exp) - Number(jwt.claims.iat)).toBe(3600);
    expect(Math.abs(Number(jwt.claims.iat) - Date.now() / 1000)).toBeLessThan(60);
    return json(200, { access_token: token, token_type: 'Bearer', expires_in: 3599 });
  });
}

function bearer(req: HttpRequest, token: string) {
  expect(req.headers?.Authorization === `Bearer ${token}`).toBe(true);
}

const restricted = {
  apiTargets: [{ service: 'generativelanguage.googleapis.com' }, { service: 'translate.googleapis.com', methods: ['Get*'] }],
  serverKeyRestrictions: { allowedIps: ['203.0.113.7', '198.51.100.0/24'] },
};
const oldMetadata = (overrides: Record<string, unknown> = {}) => ({
  name: OLD, uid: 'aecd7943-98ff-4ce2-a876-ec1b37c671ca', displayName: 'Production Gemini',
  createTime: '2026-01-01T00:00:00Z', updateTime: '2026-01-02T00:00:00Z', etag: 'k0bsYGkIvSxDVwNxyw49NQ==',
  restrictions: restricted, annotations: { team: 'web' }, ...overrides,
});

/** Two-page listing; the old key is on the second page. */
function lookupRoutes(http: FakeHttp, token: string, oldValue: string, metadata = oldMetadata()) {
  return http
    .on('GET', LIST, (req) => { bearer(req, token); return json(200, { keys: [{ name: OTHER, displayName: 'other' }], nextPageToken: 'page-2' }); })
    .on('GET', /\/projects\/demo-project\/locations\/global\/keys\?pageToken=page-2$/, (req) => {
      bearer(req, token);
      return json(200, { keys: [{ name: OLD, displayName: 'Production Gemini' }] });
    })
    .on('GET', /\/keys\/other-key\/keyString$/, () => json(200, { keyString: apiKey() }))
    .on('GET', /\/keys\/old-key\/keyString$/, (req) => { bearer(req, token); return json(200, { keyString: oldValue }); })
    .on('GET', /\/keys\/old-key$/, (req) => { bearer(req, token); return json(200, metadata); });
}

function noValueInUrls(http: FakeHttp, ...values: string[]) {
  for (const call of http.calls) for (const value of values) expect(call.url.includes(value)).toBe(false);
}

async function rejection(operation: Promise<unknown>): Promise<unknown> {
  try { await operation; } catch (error) { return error; }
  throw new Error('expected rejection');
}

describe('Google provider: API key verification', () => {
  it('verifies an API key with the Gemini models list through the x-goog-api-key header', async () => {
    const value = apiKey();
    const http = new FakeHttp().on('GET', /.*/, (req) => {
      expect(req.url).toBe('https://generativelanguage.googleapis.com/v1beta/models?pageSize=1');
      expect(req.headers?.['x-goog-api-key'] === value).toBe(true);
      expect(req.headers?.Authorization).toBeUndefined();
      expect(req.body).toBeUndefined();
      return json(200, { models: [{ name: 'models/gemini-2.5-flash' }], nextPageToken: 'x' });
    });
    expect(await googleProvider.verify(value, context(http, {}))).toEqual({ ok: true, status: 200, identity: 'Gemini API key' });
    expect(http.calls).toHaveLength(1);
  });

  it.each([400, 401, 429, 500])('rejects HTTP %i without echoing the body', async (status) => {
    const value = apiKey();
    const http = new FakeHttp().on('GET', /models/, () => json(status, { error: { message: `API key not valid ${value}`, status: 'INVALID_ARGUMENT' } }));
    const result = await googleProvider.verify(value, context(http, {}));
    expect(result).toMatchObject({ ok: false, status });
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it.each([
    ['API_KEY_SERVICE_BLOCKED', true], ['API_KEY_IP_ADDRESS_BLOCKED', true], ['API_KEY_HTTP_REFERRER_BLOCKED', true],
    ['API_KEY_ANDROID_APP_BLOCKED', true], ['API_KEY_IOS_APP_BLOCKED', true], ['SERVICE_DISABLED', true],
    ['API_KEY_INVALID', false], [undefined, false],
  ] as const)('maps a 403 with ErrorInfo reason %s to ok=%s', async (reason, ok) => {
    const value = apiKey();
    const details = reason ? [{ '@type': 'type.googleapis.com/google.rpc.ErrorInfo', reason, domain: 'googleapis.com' }] : [];
    const http = new FakeHttp().on('GET', /models/, () => json(403, { error: { code: 403, message: value, details } }));
    const result = await googleProvider.verify(value, context(http, {}));
    expect(result.ok).toBe(ok);
    expect(result.status).toBe(403);
    if (ok) expect(result.identity).toMatch(/limited/);
    expect(JSON.stringify(result).includes(value)).toBe(false);
  });

  it('sanitizes transport failures and malformed success bodies', async () => {
    for (const kind of ['transport', 'text', 'shape'] as const) {
      const value = apiKey();
      const http = new FakeHttp().on('GET', /models/, () => {
        if (kind === 'transport') throw new Error(value);
        return kind === 'text' ? text(200, value) : json(200, { models: value });
      });
      const result = await googleProvider.verify(value, context(http, {}));
      expect(result.ok).toBe(false);
      expect(JSON.stringify(result).includes(value)).toBe(false);
    }
  });
});

describe('Google provider: service-account JSON keys', () => {
  it('verifies a service-account key by exchanging a read-only JWT bearer assertion it signs itself', async () => {
    const value = serviceAccount();
    const http = tokenRoute(new FakeHttp(), accessToken(), 'https://www.googleapis.com/auth/cloud-platform.read-only');
    expect(await googleProvider.verify(value, context(http, {}))).toEqual({ ok: true, status: 200, identity: ADMIN_EMAIL });
    expect(http.calls).toHaveLength(1);
  });

  it('reports a rejected or malformed service-account key without echoing secrets', async () => {
    const value = serviceAccount();
    const http = new FakeHttp().on('POST', TOKEN, () => json(400, { error: 'invalid_grant', error_description: PEM }));
    const rejected = await googleProvider.verify(value, context(http, {}));
    expect(rejected).toMatchObject({ ok: false, status: 400 });
    expect(JSON.stringify(rejected).includes('PRIVATE KEY')).toBe(false);
    const malformed = await googleProvider.verify(serviceAccount({ private_key: 'not a key' }), context(new FakeHttp(), {}));
    expect(malformed.ok).toBe(false);
    for (const token_uri of ['https://evil.example/token']) {
      const http2 = new FakeHttp();
      expect((await googleProvider.verify(serviceAccount({ token_uri }), context(http2, {}))).ok).toBe(false);
      expect(http2.calls).toHaveLength(0);
    }
  });

  it('requires guided rotation for service-account keys before any request', async () => {
    const http = new FakeHttp();
    const error = await rejection(googleProvider.rotate!(serviceAccount(), context(http)));
    expect(error).toBeInstanceOf(GoogleGuidedRotationRequiredError);
    expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED', provider: 'google' });
    expect(String(error).includes('PRIVATE KEY')).toBe(false);
    expect(http.calls).toHaveLength(0);
    expect(await googleProvider.resolveKeyRef!(serviceAccount(), context(http))).toBeNull();
    expect(http.calls).toHaveLength(0);
  });
});

describe('Google provider: API key rotation', () => {
  it('finds the key without putting its value in a URL and creates a copy with identical restrictions', async () => {
    const oldValue = apiKey();
    const newValue = apiKey();
    const token = accessToken();
    const sleeps: number[] = [];
    const http = lookupRoutes(tokenRoute(new FakeHttp(), token), token, oldValue)
      .on('POST', new RegExp(`^${API.replace(/\./g, '\\.')}/projects/${PROJECT}/locations/global/keys$`), (req) => {
        bearer(req, token);
        expect(req.headers?.['Content-Type']).toBe('application/json');
        expect(JSON.parse(req.body!)).toEqual({ displayName: 'Production Gemini', restrictions: restricted, annotations: { team: 'web' } });
        return json(200, { name: 'operations/akmf.p7-1', done: false });
      })
      .on('GET', /^https:\/\/apikeys\.googleapis\.com\/v2\/operations\/akmf\.p7-1$/, (req) => {
        bearer(req, token);
        const done = http.callsTo('GET', /operations/).length > 1;
        return json(200, done
          ? { name: 'operations/akmf.p7-1', done: true, response: { '@type': 'type.googleapis.com/google.api.apikeys.v2.Key', name: NEW, keyString: newValue, restrictions: restricted } }
          : { name: 'operations/akmf.p7-1', done: false });
      });

    const result = await provider(sleeps).rotate!(oldValue, context(http));
    expect(result.newValue === newValue).toBe(true);
    expect({ ...result, newValue: '<new>' }).toEqual({ newValue: '<new>', oldKeyRef: OLD, newKeyRef: NEW, oldRevoked: false });
    expect(sleeps).toEqual([500, 1000]);
    expect(http.calls.map(call => `${call.method} ${call.url.replace(API, '')}`)).toEqual([
      'POST https://oauth2.googleapis.com/token',
      `GET /projects/demo-project/locations/global/keys`,
      `GET /projects/demo-project/locations/global/keys?pageToken=page-2`,
      `GET /${OTHER}/keyString`,
      `GET /${OLD}/keyString`,
      `GET /${OLD}`,
      `POST /projects/${PROJECT}/locations/global/keys`,
      'GET /operations/akmf.p7-1',
      'GET /operations/akmf.p7-1',
    ]);
    noValueInUrls(http, oldValue, newValue, token);
    expect(http.calls.some(call => call.method === 'DELETE')).toBe(false);
  });

  it('uses an OAuth access token with an explicit project and fetches the key string when the operation omits it', async () => {
    const oldValue = apiKey();
    const newValue = apiKey();
    const token = accessToken();
    // Server (IP) restrictions are copied; browser, Android and iOS keys ship in clients and stay guided (below).
    const bound = oldMetadata({ restrictions: { serverKeyRestrictions: { allowedIps: ['203.0.113.7'] } },
      annotations: undefined, serviceAccountEmail: 'gemini@demo-project.iam.gserviceaccount.com' });
    const http = new FakeHttp()
      .on('GET', /\/projects\/my-project\/locations\/global\/keys$/, (req) => { bearer(req, token); return json(200, { keys: [{ name: OLD }] }); })
      .on('GET', /\/keys\/old-key\/keyString$/, () => json(200, { keyString: oldValue }))
      .on('GET', /\/keys\/old-key$/, () => json(200, bound))
      .on('POST', /\/projects\/123456789012\/locations\/global\/keys$/, (req) => {
        expect(JSON.parse(req.body!)).toEqual({ displayName: 'Production Gemini', serviceAccountEmail: 'gemini@demo-project.iam.gserviceaccount.com',
          restrictions: { serverKeyRestrictions: { allowedIps: ['203.0.113.7'] } } });
        return json(200, { name: 'operations/akmf.p7-2', done: true, response: { name: NEW } });
      })
      .on('GET', /\/keys\/new-key\/keyString$/, (req) => { bearer(req, token); return json(200, { keyString: newValue }); });
    const result = await provider().rotate!(oldValue, context(http, { GOOGLE_OAUTH_ACCESS_TOKEN: token, GOOGLE_API_KEYS_PROJECT: 'my-project' }));
    expect(result.newValue === newValue).toBe(true);
    expect(result.newKeyRef).toBe(NEW);
    expect(http.callsTo('POST', TOKEN)).toHaveLength(0);
    expect(http.callsTo('GET', /operations/)).toHaveLength(0);
  });

  it('copies an unrestricted key as unrestricted and says so', async () => {
    const oldValue = apiKey();
    const token = accessToken();
    const http = lookupRoutes(tokenRoute(new FakeHttp(), token), token, oldValue, oldMetadata({ restrictions: undefined, annotations: {}, displayName: undefined }))
      .on('POST', /\/locations\/global\/keys$/, (req) => {
        const body = JSON.parse(req.body!) as Record<string, unknown>;
        expect(Object.keys(body)).toEqual(['displayName']);
        expect(body.displayName).toMatch(/^keysentry \d{4}-\d{2}-\d{2}$/);
        return json(200, { name: 'operations/x', done: true, response: { name: NEW, keyString: apiKey() } });
      });
    const result = await provider().rotate!(oldValue, context(http));
    expect(result.notes).toMatch(/no API or application restrictions/);
  });

  it.each([
    ['an unknown key field', { expireTime: '2027-01-01T00:00:00Z' }],
    ['an unknown restriction', { restrictions: { ...restricted, newRestriction: {} } }],
    ['an unknown nested field', { restrictions: { serverKeyRestrictions: { allowedIps: ['203.0.113.7'], mode: 'x' } } }],
    ['two client restrictions', { restrictions: { serverKeyRestrictions: { allowedIps: [] }, iosKeyRestrictions: { allowedBundleIds: ['a.b'] } } }],
    ['malformed API targets', { restrictions: { apiTargets: [{ service: '' }] } }],
    ['malformed Android apps', { restrictions: { androidKeyRestrictions: { allowedApplications: [{ packageName: 'a.b' }] } } }],
    ['non-string annotations', { annotations: { team: 1 } }],
    ['an unusual bound service account', { serviceAccountEmail: 'someone@example.com' }],
    ['a deleted key', { deleteTime: '2026-10-01T00:00:00Z' }],
    ['a mismatched name', { name: OTHER }],
    ['an overlong display name', { displayName: 'x'.repeat(64) }],
  ])('requires guided rotation before creation for %s', async (_label, patch) => {
    const oldValue = apiKey();
    const token = accessToken();
    const http = lookupRoutes(tokenRoute(new FakeHttp(), token), token, oldValue, oldMetadata(patch))
      .on('POST', /\/locations\/global\/keys$/, () => json(200, { name: 'operations/x', done: true, response: { name: NEW, keyString: apiKey() } }));
    const error = await rejection(provider().rotate!(oldValue, context(http)));
    expect(error).toMatchObject({ name: 'GoogleGuidedRotationRequiredError', code: 'GUIDED_ROTATION_REQUIRED' });
    expect(String(error).includes(oldValue)).toBe(false);
    expect(http.callsTo('POST', /apikeys/)).toHaveLength(0);
  });

  it('requires guided rotation without network access when no management credential is configured', async () => {
    const http = new FakeHttp();
    for (const credentials of [{}, { GOOGLE_API_KEYS_PROJECT: 'demo-project' }, { GOOGLE_API_KEYS_ADMIN_KEY: '  ' }]) {
      const error = await rejection(provider().rotate!(apiKey(), context(http, credentials)));
      expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
      expect(String(error)).toMatch(/GOOGLE_API_KEYS_ADMIN_KEY/);
    }
    expect(http.calls).toHaveLength(0);
  });

  it('requires guided rotation when no project is known or the key is not in it', async () => {
    const token = accessToken();
    const noProject = new FakeHttp();
    const error = await rejection(provider().rotate!(apiKey(), context(noProject, { GOOGLE_OAUTH_ACCESS_TOKEN: token })));
    expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(String(error)).toMatch(/GOOGLE_API_KEYS_PROJECT/);
    expect(noProject.calls).toHaveLength(0);

    const oldValue = apiKey();
    const missing = lookupRoutes(tokenRoute(new FakeHttp(), token), token, apiKey());
    expect(await rejection(provider().rotate!(oldValue, context(missing)))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(missing.calls.every(call => call.method === 'GET' || TOKEN.test(call.url))).toBe(true);
    noValueInUrls(missing, oldValue);
  });

  it.each([400, 403])('turns a synchronous create rejection (HTTP %i) into guided rotation', async (status) => {
    const oldValue = apiKey();
    const token = accessToken();
    const http = lookupRoutes(tokenRoute(new FakeHttp(), token), token, oldValue)
      .on('POST', /\/locations\/global\/keys$/, () => json(status, { error: { message: oldValue } }));
    const error = await rejection(provider().rotate!(oldValue, context(http)));
    expect(error).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
    expect(String(error).includes(oldValue)).toBe(false);
  });

  it('reports server errors, failed operations and stuck operations with fixed text', async () => {
    const cases: [string, (http: FakeHttp) => void, RegExp][] = [
      ['5xx', http => http.on('POST', /\/locations\/global\/keys$/, () => json(503, { error: { message: 'x' } })), /HTTP 503/],
      ['operation error', http => http.on('POST', /\/locations\/global\/keys$/, () => json(200, { name: 'operations/e', done: true, error: { code: 9, message: 'leak' } })), /creation failed/],
      ['stuck', http => http.on('POST', /\/locations\/global\/keys$/, () => json(200, { name: 'operations/s', done: false }))
        .on('GET', /\/operations\/s$/, () => json(200, { name: 'operations/s', done: false })), /still running/],
      ['bad key string', http => http.on('POST', /\/locations\/global\/keys$/, () => json(200, { name: 'operations/k', done: true, response: { name: NEW, keyString: 'short' } })), /invalid replacement/],
      ['reused value', http => http.on('POST', /\/locations\/global\/keys$/, () => json(200, { name: 'operations/k', done: true, response: { name: OLD, keyString: apiKey() } })), /invalid replacement/],
      // The create call was accepted, so an operation may be running: the outcome is unknown.
      ['bad operation name', http => http.on('POST', /\/locations\/global\/keys$/, () => json(200, { name: '../../x', done: false })), /unused replacement may appear/],
    ];
    for (const [, extend, message] of cases) {
      const oldValue = apiKey();
      const token = accessToken();
      const sleeps: number[] = [];
      const http = lookupRoutes(tokenRoute(new FakeHttp(), token), token, oldValue);
      extend(http);
      const error = await rejection(provider(sleeps).rotate!(oldValue, context(http)));
      expect(error).not.toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
      expect(String(error)).toMatch(message);
      expect(String(error)).not.toMatch(/leak/);
      expect(String(error).includes(oldValue)).toBe(false);
      if (/still running/.test(String(error))) expect(sleeps.length).toBe(13);
    }
  });

  it('reports token endpoint and credential problems without echoing secrets', async () => {
    const http = new FakeHttp().on('POST', TOKEN, () => json(400, { error: 'invalid_grant', error_description: PEM }));
    const error = await rejection(provider().rotate!(apiKey(), context(http)));
    expect(String(error)).toMatch(/OAuth token request failed \(HTTP 400\)/);
    expect(String(error).includes('PRIVATE KEY')).toBe(false);

    const bad = new FakeHttp();
    for (const admin of ['{"type":"service_account"}', 'not json', serviceAccount({ universe_domain: 'example.com' })]) {
      const failure = await rejection(provider().rotate!(apiKey(), context(bad, { GOOGLE_API_KEYS_ADMIN_KEY: admin })));
      expect(String(failure)).toMatch(/GOOGLE_API_KEYS_ADMIN_KEY is not a usable/);
    }
    const project = await rejection(provider().rotate!(apiKey(), context(bad, { GOOGLE_OAUTH_ACCESS_TOKEN: accessToken(), GOOGLE_API_KEYS_PROJECT: 'Bad Project!' })));
    expect(String(project)).toMatch(/GOOGLE_API_KEYS_PROJECT is not a valid/);
    expect(String(project)).not.toMatch(/Bad Project/);
    expect(bad.calls).toHaveLength(0);
  });

  it('stops on a page token that does not advance', async () => {
    const token = accessToken();
    const http = tokenRoute(new FakeHttp(), token)
      .on('GET', /\/locations\/global\/keys(\?pageToken=again)?$/, () => json(200, { keys: [], nextPageToken: 'again' }));
    expect(String(await rejection(provider().rotate!(apiKey(), context(http))))).toMatch(/invalid key list/);
    expect(http.callsTo('GET', /keys/).length).toBe(2);
  });
});

describe('Google provider: references, revocation and listing', () => {
  it('rotates by reference from metadata alone', async () => {
    const token = accessToken();
    const newValue = apiKey();
    const http = tokenRoute(new FakeHttp(), token)
      .on('GET', /\/keys\/old-key$/, (req) => { bearer(req, token); return json(200, oldMetadata()); })
      .on('POST', /\/projects\/123456789012\/locations\/global\/keys$/, (req) => {
        expect(JSON.parse(req.body!)).toEqual({ displayName: 'Production Gemini', restrictions: restricted, annotations: { team: 'web' } });
        return json(200, { name: 'operations/r', done: true, response: { name: NEW, keyString: newValue } });
      });
    const result = await provider().rotateByRef!(OLD, context(http));
    expect(result.newValue === newValue).toBe(true);
    expect(result).toMatchObject({ oldKeyRef: OLD, newKeyRef: NEW, oldRevoked: false });
    expect(http.callsTo('GET', /keyString|locations\/global\/keys$/)).toHaveLength(0);
  });

  it('refuses malformed or secret-shaped references before any request', async () => {
    const http = new FakeHttp();
    for (const ref of ['old-key', `${OLD}/../x`, `projects/p/locations/us/keys/k`, apiKey(), `${KEYS}/${serviceAccount()}`]) {
      expect(await rejection(provider().rotateByRef!(ref, context(http)))).toMatchObject({ code: 'GUIDED_ROTATION_REQUIRED' });
      expect(String(await rejection(provider().revoke!(ref, context(http))))).toMatch(/valid API key reference/);
    }
    expect(http.calls).toHaveLength(0);
  });

  it('revokes with DELETE on the resource name and waits for the operation', async () => {
    const token = accessToken();
    const sleeps: number[] = [];
    const http = tokenRoute(new FakeHttp(), token)
      .on('DELETE', /.*/, (req) => {
        expect(req.url).toBe(`${API}/${OLD}`);
        bearer(req, token);
        expect(req.body).toBeUndefined();
        return json(200, { name: 'operations/d', done: false });
      })
      .on('GET', /\/operations\/d$/, () => json(200, { name: 'operations/d', done: true, response: { name: OLD } }));
    await provider(sleeps).revoke!(OLD, context(http));
    expect(sleeps).toEqual([500]);
  });

  it('reports revocation failures with fixed text', async () => {
    for (const [response, message] of [
      [json(404, { error: { message: OLD } }), /HTTP 404/],
      [json(200, { name: 'operations/d', done: true, error: { code: 7 } }), /deletion failed/],
      [text(200, 'oops'), /invalid response/],
    ] as const) {
      const http = tokenRoute(new FakeHttp(), accessToken()).on('DELETE', /old-key$/, () => response);
      expect(String(await rejection(provider().revoke!(OLD, context(http))))).toMatch(message);
    }
    const unconfigured = new FakeHttp();
    expect(String(await rejection(provider().revoke!(OLD, context(unconfigured, {}))))).toMatch(/Missing provider credential/);
    expect(unconfigured.calls).toHaveLength(0);
  });

  it('resolves a value to its key name and never throws', async () => {
    const value = apiKey();
    const token = accessToken();
    const http = lookupRoutes(tokenRoute(new FakeHttp(), token), token, value);
    expect(await provider().resolveKeyRef!(value, context(http))).toBe(OLD);
    noValueInUrls(http, value);

    expect(await provider().resolveKeyRef!(value, context(new FakeHttp(), {}))).toBeNull();
    const failing = tokenRoute(new FakeHttp(), token).on('GET', LIST, () => json(500, { error: { message: value } }));
    expect(await provider().resolveKeyRef!(value, context(failing))).toBeNull();
    const notFound = lookupRoutes(tokenRoute(new FakeHttp(), token), token, apiKey());
    expect(await provider().resolveKeyRef!(value, context(notFound))).toBeNull();
  });

  it('lists keys in the configured project with names and creation times', async () => {
    const token = accessToken();
    const http = tokenRoute(new FakeHttp(), token)
      .on('GET', LIST, () => json(200, { keys: [{ name: OLD, displayName: 'Production Gemini', createTime: '2026-01-01T00:00:00Z' }], nextPageToken: 'n' }))
      .on('GET', /keys\?pageToken=n$/, () => json(200, { keys: [{ name: OTHER, displayName: apiKey() }] }));
    expect(await provider().listKeys!(context(http))).toEqual([
      { keyRef: OLD, name: 'Production Gemini', createdAt: '2026-01-01T00:00:00Z' },
      { keyRef: OTHER },
    ]);
    const duplicate = tokenRoute(new FakeHttp(), token).on('GET', LIST, () => json(200, { keys: [{ name: OLD }, { name: OLD }] }));
    expect(String(await rejection(provider().listKeys!(context(duplicate))))).toMatch(/invalid key list/);
  });

  it('exports its adapter shape and credential names', () => {
    expect(googleProvider.id).toBe('google');
    expect(googleProvider.method).toBe('auto');
    expect(GOOGLE_CREDENTIALS).toEqual(['GOOGLE_API_KEYS_ADMIN_KEY', 'GOOGLE_OAUTH_ACCESS_TOKEN', 'GOOGLE_API_KEYS_PROJECT']);
    const guidance = googleProvider.guidance();
    expect(guidance.url).toBe('https://console.cloud.google.com/apis/credentials');
    expect(guidance.steps.join(' ')).toMatch(/service-account JSON key/);
  });
});
