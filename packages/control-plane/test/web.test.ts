import { createHash, createHmac, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { request } from 'node:http';
import ts from 'typescript';
import { afterEach, describe, expect, it } from 'vitest';
import { encode } from '../../../test/approvals/webauthn/helpers.js';
import { json } from '../../../test/helpers/fake-http.js';
import type { HttpClient, HttpRequest } from '../../../src/types.js';
import { createAccounts } from '../src/accounts.js';
import { createBilling } from '../src/billing.js';
import { createRelayStore } from '../src/relay.js';
import { createControlPlaneServer } from '../src/server.js';
import { createMemoryStorage } from '../src/storage.js';
import { UI_ASSETS } from '../src/ui-assets.js';
// @ts-expect-error The build script is plain JavaScript without declarations.
import { buildControlPlaneUi } from '../scripts/build-ui.mjs';

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; "
  + "frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types 'none'";
const WEBHOOK_SECRET = 'whsec_web0test0only';
const API_KEY = 'rk_test_web0test0only';
const deviceKey = generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

interface Reply { status: number; headers: Record<string, string | string[] | undefined>; text: string; json<T = Record<string, unknown>>(): T }
function call(port: number, path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method: init.method ?? 'GET', agent: false, headers: { Host: `127.0.0.1:${port}`, ...init.headers } }, res => {
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(Buffer.from(chunk)));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode!, headers: res.headers, text, json: <T>() => JSON.parse(text) as T });
      });
    });
    req.on('error', reject);
    req.end(init.body);
  });
}

/** A software passkey with UP+UV that answers discoverable (no allow-list) sign-ins, as a platform authenticator does. */
function passkey(rpId: string, origin: string) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const credentialId = randomBytes(16);
  const cose = encode(new Map<number, unknown>([[1, 1], [3, -8], [-1, 6], [-2, Buffer.from(publicKey.export({ format: 'jwk' }).x!, 'base64url')]]));
  let counter = 0;
  const b64 = (value: Buffer) => value.toString('base64url');
  return {
    id: b64(credentialId),
    registration(challenge: string) {
      const length = Buffer.alloc(2); length.writeUInt16BE(credentialId.length);
      const authData = Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), length, credentialId, cose]);
      return { clientDataJSON: b64(Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin }))),
        attestationObject: b64(encode(new Map<string, unknown>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]))) };
    },
    assertion(challenge: string) {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }));
      const count = Buffer.alloc(4); count.writeUInt32BE(++counter);
      const authenticatorData = Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([0x05]), count]);
      const signature = sign(null, Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]), privateKey);
      return { credentialId: b64(credentialId), clientDataJSON: b64(clientDataJSON), authenticatorData: b64(authenticatorData), signature: b64(signature) };
    },
  };
}

/** Stripe's Checkout Session and Subscription endpoints, in memory. */
function fakeStripe() {
  const calls: HttpRequest[] = [];
  let reply: ((req: HttpRequest) => ReturnType<typeof json>) | null = null;
  const http: HttpClient = { async request(req) {
    calls.push(req);
    if (req.headers?.authorization !== `Bearer ${API_KEY}`) return json(401, { error: { message: 'planted' } });
    if (reply) return reply(req);
    if (req.method === 'POST' && req.url === 'https://api.stripe.com/v1/checkout/sessions') {
      const form = new URLSearchParams(req.body);
      return json(200, { id: 'cs_test_web', object: 'checkout.session', mode: form.get('mode'), client_reference_id: form.get('client_reference_id'),
        url: 'https://checkout.stripe.com/c/pay/cs_test_web' });
    }
    if (req.method === 'GET' && req.url === 'https://api.stripe.com/v1/subscriptions/sub_web') {
      return json(200, { id: 'sub_web', customer: 'cus_web', status: 'active', items: { has_more: false, data: [{ price: { id: 'price_web' } }] } });
    }
    return json(404, {});
  } };
  return { http, calls, fail(next: typeof reply) { reply = next; } };
}

const servers: { close(): Promise<void> }[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

async function start(options: { provision?: boolean; checkout?: boolean } = {}) {
  const storage = createMemoryStorage();
  const stripe = fakeStripe();
  const provisioned: { name: string; deviceKey: string }[] = [];
  let accounts!: ReturnType<typeof createAccounts>;
  const billing = () => createBilling({ storage, accounts, endpointSecret: WEBHOOK_SECRET, priceId: 'price_web', stripe: { http: stripe.http, apiKey: API_KEY } });
  let billingService: ReturnType<typeof billing> | undefined;
  const server = createControlPlaneServer({
    origin: 'http://127.0.0.1:0',
    accounts: origin => (accounts = createAccounts({ storage, origin })),
    billing: {
      handle: (raw, signature) => (billingService ??= billing()).handle(raw, signature),
      ...(options.checkout === false ? {} : { checkout: input => (billingService ??= billing()).checkout(input) }),
    },
    relay: createRelayStore({ storage }),
    ...(options.provision === false ? {} : { provisioner: { async provision(input: { name: string; deviceKey: string }) { provisioned.push(input); return { name: input.name, status: 'PENDING' }; } } }),
  });
  servers.push(server);
  const { port, origin } = await server.listen();
  const browser = { Origin: origin, 'Content-Type': 'application/json' };
  const key = passkey('127.0.0.1', origin);
  async function signUp() {
    const challenge = (await call(port, '/auth/register/challenge', { method: 'POST', headers: browser, body: '{}' })).json<{ id: string; challenge: string; userId: string }>();
    const finish = await call(port, '/auth/register/finish', { method: 'POST', headers: browser, body: JSON.stringify({ challengeId: challenge.id, ...key.registration(challenge.challenge) }) });
    expect(finish.status).toBe(200);
    const body = finish.json<{ account: { id: string }; csrf: string }>();
    expect(body.account.id).toBe(Buffer.from(challenge.userId, 'base64url').toString('hex'));
    return { cookie: String(finish.headers['set-cookie']).split(';')[0]!, csrf: body.csrf, accountId: body.account.id };
  }
  async function webhook(event: Record<string, unknown>) {
    const raw = JSON.stringify(event); const t = Math.floor(Date.now() / 1000);
    const signature = `t=${t},v1=${createHmac('sha256', WEBHOOK_SECRET).update(`${t}.${raw}`).digest('hex')}`;
    return call(port, '/billing/webhook', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Stripe-Signature': signature }, body: raw });
  }
  return { port, origin, browser, key, stripe, provisioned, storage, signUp, webhook };
}

describe('web page routes', () => {
  it('serves the page and its files with the strict CSP, their own media types and no caching', async () => {
    const { port } = await start();
    for (const [path, type] of [['/', 'text/html; charset=utf-8'], ['/?checkout=done', 'text/html; charset=utf-8'], ['/?checkout=cancelled', 'text/html; charset=utf-8'],
      ['/app/app.js', 'text/javascript; charset=utf-8'], ['/app/app.css', 'text/css; charset=utf-8'], ['/app/icon.svg', 'image/svg+xml']] as const) {
      const reply = await call(port, path);
      expect(reply.status, path).toBe(200);
      expect(reply.headers['content-type']).toBe(type);
      expect(reply.headers['content-security-policy']).toBe(CSP);
      expect(reply.headers['x-content-type-options']).toBe('nosniff');
      expect(reply.headers['x-frame-options']).toBe('DENY');
      expect(reply.headers['cross-origin-opener-policy']).toBe('same-origin');
      expect(reply.headers['cache-control']).toBe('no-store');
      expect(reply.text).toBe(UI_ASSETS[path.startsWith('/?') ? '/' : path]!.body);
    }
  });
  it('refuses other paths, queries and methods on the page routes', async () => {
    const { port } = await start();
    for (const path of ['/app/', '/app/missing.js', '/app/app.ts', '/app/../server.ts', '/index.html', '/?checkout=other', '/?x=1', '/favicon.ico']) {
      expect((await call(port, path)).status, path).toBe(404);
    }
    expect((await call(port, '/', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status).toBe(405);
    expect((await call(port, '/', { headers: { Host: 'evil.example' } })).status).toBe(403);
  });
  it('has no inline script, inline style or event handler, and the script never builds HTML from strings', () => {
    const html = UI_ASSETS['/']!.body;
    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
    expect(scripts).toHaveLength(1);
    expect(scripts[0]![1]).toMatch(/\bsrc="\/app\/app\.js"/);
    expect(scripts[0]![2]).toBe('');
    expect(html).not.toMatch(/<style\b|\sstyle=|\son[a-z]+=|javascript:/i);
    for (const match of html.matchAll(/\s(?:src|href)="([^"]+)"/g)) expect(match[1], 'same-origin references only').toMatch(/^(?:\/app\/|#)/);
    const js = UI_ASSETS['/app/app.js']!.body;
    expect(js).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|setTimeout\(\s*['"`]/);
    expect(js).not.toMatch(/localStorage|sessionStorage|indexedDB/);
    for (const match of js.matchAll(/api\('([^']+)'/g)) expect(match[1]).toMatch(/^\/(?:auth|session|account|billing|boxes)/);
    const css = UI_ASSETS['/app/app.css']!.body;
    expect(css).not.toMatch(/@import|url\(/i);
    expect(UI_ASSETS['/app/icon.svg']!.body).not.toMatch(/<script|on[a-z]+=|href=/i);
  });
  it('labels every form control and keeps a live status region and a skip link', () => {
    const html = UI_ASSETS['/']!.body;
    const controls = [...html.matchAll(/<(?:input|textarea)\b[^>]*\bid="([^"]+)"/g)].map(match => match[1]!);
    expect(controls).toEqual(['box-name', 'device-key']);
    for (const id of controls) {
      expect(html).toContain(`<label for="${id}">`);
      expect(html).toMatch(new RegExp(`id="${id}"[^>]*aria-describedby="${id}-help"`));
    }
    expect(html).toMatch(/id="status"[^>]*role="status"[^>]*aria-live="polite"/);
    expect(html).toContain('<a class="skip-link" href="#main">');
    expect(html).toContain('<html lang="en">');
    expect(html).toContain('keysentry box card');
  });
  it('is generated from packages/control-plane/ui (run scripts/build-ui.mjs after editing it)', async () => {
    const current = (await readFile(new URL('../src/ui-assets.ts', import.meta.url), 'utf8')).replace(/\r\n/g, '\n');
    expect(current).toBe(await buildControlPlaneUi());
  });
  it('type-checks the page script against the DOM library', () => {
    const configPath = new URL('../tsconfig.ui.json', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
    const config = ts.readConfigFile(configPath, ts.sys.readFile);
    const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, configPath.replace(/[\\/][^\\/]+$/, ''));
    expect(parsed.fileNames.map(name => name.replace(/^.*[\\/]/, ''))).toEqual(['app.ts']);
    const diagnostics = ts.getPreEmitDiagnostics(ts.createProgram(parsed.fileNames, parsed.options));
    expect(diagnostics.map(item => ts.flattenDiagnosticMessageText(item.messageText, '\n'))).toEqual([]);
  }, 60_000);
});

describe('account and checkout routes', () => {
  it('requires a session for the account view and shows plan, quota and boxes', async () => {
    const ctx = await start();
    expect((await call(ctx.port, '/account')).status).toBe(401);
    const user = await ctx.signUp();
    const view = await call(ctx.port, '/account', { headers: { Cookie: user.cookie } });
    expect(view.status).toBe(200);
    expect(view.json()).toEqual({ accountId: user.accountId, plan: 'free', boxes: [], boxQuota: 1 });
    expect((await call(ctx.port, '/account', { headers: { Cookie: user.cookie, Authorization: 'Bearer x' } })).status).toBe(401);
  });
  it('checkout needs a session, the page origin and the CSRF token, and takes an empty body', async () => {
    const ctx = await start();
    const user = await ctx.signUp();
    const post = (headers: Record<string, string>, body = '{}') => call(ctx.port, '/billing/checkout', { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body });
    expect((await post({ Origin: ctx.origin, 'X-CSRF-Token': user.csrf })).status).toBe(401);
    expect((await post({ Cookie: user.cookie, 'X-CSRF-Token': user.csrf })).status).toBe(403);
    expect((await post({ Cookie: user.cookie, Origin: 'https://evil.example', 'X-CSRF-Token': user.csrf })).status).toBe(403);
    expect((await post({ Cookie: user.cookie, Origin: ctx.origin })).status).toBe(403);
    expect((await post({ Cookie: user.cookie, Origin: ctx.origin, 'X-CSRF-Token': 'A'.repeat(43) })).status).toBe(403);
    expect((await post({ Cookie: user.cookie, Origin: ctx.origin, 'X-CSRF-Token': user.csrf }, '{"price":"price_cheap"}')).status).toBe(400);
    expect((await call(ctx.port, '/billing/checkout', { method: 'GET', headers: { Cookie: user.cookie } })).status).toBe(405);
    expect(ctx.stripe.calls).toEqual([]);
    const ok = await post({ Cookie: user.cookie, Origin: ctx.origin, 'X-CSRF-Token': user.csrf });
    expect(ok.status).toBe(200);
    expect(ok.json()).toEqual({ url: 'https://checkout.stripe.com/c/pay/cs_test_web' });
    const form = new URLSearchParams(ctx.stripe.calls[0]!.body);
    expect(form.get('mode')).toBe('subscription');
    expect(form.get('line_items[0][price]')).toBe('price_web');
    expect(form.get('client_reference_id')).toBe(user.accountId);
    expect(form.get('success_url')).toBe(`${ctx.origin}/?checkout=done`);
  });
  it.each([
    [400, 'Checkout could not be started.', 502], [403, 'Checkout could not be started.', 502],
    [429, 'Billing is temporarily unavailable.', 503], [500, 'Billing is temporarily unavailable.', 503],
  ])('maps a Stripe %i to fixed text', async (stripeStatus, text, status) => {
    const ctx = await start();
    const user = await ctx.signUp();
    ctx.stripe.fail(() => json(stripeStatus, { error: { message: `planted ${API_KEY}`, type: 'invalid_request_error' } }));
    const reply = await call(ctx.port, '/billing/checkout', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: user.cookie, Origin: ctx.origin, 'X-CSRF-Token': user.csrf }, body: '{}' });
    expect(reply.status).toBe(status);
    expect(reply.json()).toEqual({ error: text });
    expect(reply.text).not.toMatch(/planted|rk_test/);
  });
  it('answers 503 when billing cannot create checkouts', async () => {
    const ctx = await start({ checkout: false });
    const user = await ctx.signUp();
    const reply = await call(ctx.port, '/billing/checkout', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: user.cookie, Origin: ctx.origin, 'X-CSRF-Token': user.csrf }, body: '{}' });
    expect(reply.status).toBe(503);
  });
  it('sign up, sign in without an account id, pay, then create a box with the device key from keysentry box card', async () => {
    const ctx = await start();
    const user = await ctx.signUp();
    // Discoverable sign-in: the page sends {} and the credential names the account.
    const challenge = (await call(ctx.port, '/auth/login/challenge', { method: 'POST', headers: ctx.browser, body: '{}' })).json<{ id: string; challenge: string; credentialId?: string }>();
    expect(challenge.credentialId).toBeUndefined();
    const signedIn = await call(ctx.port, '/auth/login/finish', { method: 'POST', headers: ctx.browser, body: JSON.stringify({ challengeId: challenge.id, ...ctx.key.assertion(challenge.challenge) }) });
    expect(signedIn.status).toBe(200);
    const cookie = String(signedIn.headers['set-cookie']).split(';')[0]!;
    const csrf = signedIn.json<{ csrf: string }>().csrf;
    const page = { 'Content-Type': 'application/json', Cookie: cookie, Origin: ctx.origin, 'X-CSRF-Token': csrf };

    // Unpaid: the box is refused before any provisioning.
    expect((await call(ctx.port, '/boxes', { method: 'POST', headers: page, body: JSON.stringify({ name: 'web-box', deviceKey }) })).json()).toEqual({ error: 'A paid plan is required to create a box.' });
    expect((await call(ctx.port, '/billing/checkout', { method: 'POST', headers: page, body: '{}' })).status).toBe(200);
    const paid = await ctx.webhook({ id: 'evt_web', type: 'checkout.session.completed', created: Math.floor(Date.now() / 1000),
      data: { object: { mode: 'subscription', status: 'complete', payment_status: 'paid', client_reference_id: user.accountId, customer: 'cus_web', subscription: 'sub_web' } } });
    expect(paid.json()).toMatchObject({ applied: true });
    expect((await call(ctx.port, '/account', { headers: { Cookie: cookie } })).json()).toMatchObject({ plan: 'paid', boxes: [] });
    expect((await call(ctx.port, '/billing/checkout', { method: 'POST', headers: page, body: '{}' })).json()).toEqual({ error: 'This account already has the paid plan.' });

    expect((await call(ctx.port, '/boxes', { method: 'POST', headers: page, body: JSON.stringify({ name: 'web-box', deviceKey: deviceKey.slice(0, -4) }) })).json())
      .toEqual({ error: 'The enrollment device key is invalid.' });
    const created = await call(ctx.port, '/boxes', { method: 'POST', headers: page, body: JSON.stringify({ name: 'web-box', deviceKey }) });
    expect(created.status).toBe(201);
    expect(ctx.provisioned).toEqual([{ name: 'web-box', deviceKey }]);
    expect((await call(ctx.port, '/account', { headers: { Cookie: cookie } })).json()).toEqual({ accountId: user.accountId, plan: 'paid', boxes: [{ name: 'web-box', state: 'active' }], boxQuota: 1 });

    expect((await call(ctx.port, '/session', { method: 'DELETE', headers: page })).status).toBe(200);
    expect((await call(ctx.port, '/account', { headers: { Cookie: cookie } })).status).toBe(401);
  });
  it('says plainly when creating boxes is not available', async () => {
    const ctx = await start({ provision: false });
    const user = await ctx.signUp();
    const reply = await call(ctx.port, '/boxes', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: user.cookie, Origin: ctx.origin, 'X-CSRF-Token': user.csrf }, body: JSON.stringify({ name: 'web-box', deviceKey }) });
    expect(reply.status).toBe(503);
    expect(reply.json()).toEqual({ error: 'Creating boxes is not available yet.' });
  });
});
