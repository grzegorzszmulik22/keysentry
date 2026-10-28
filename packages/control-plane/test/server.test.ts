import { request } from 'node:http';
import { connect } from 'node:net';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { clientKey, createControlPlaneServer } from '../src/server.js';
import { createAccounts } from '../src/accounts.js';
import { startEmulator, type Emulator } from '../src/emulator/index.js';
import { createMemoryStorage } from '../src/storage.js';
import { encode } from '../../../test/approvals/webauthn/helpers.js';
import type { HttpClient } from '../../../src/types.js';

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; "
  + "frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types 'none'";
const servers: ReturnType<typeof createControlPlaneServer>[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });
const deviceKey = generateKeyPairSync('ed25519').publicKey.export({format:'der',type:'spki'}).toString('base64');

function services() {
  const ownership = new Map([['alpha','owner'], ['beta','other']]);
  const pending = new Set<string>();
  const provisioned: string[] = [];
  let plan: 'free'|'paid' = 'paid';
  const messages = new Map<string, unknown[]>();
  const session = { id: 'session', accountId: 'owner', csrf: 'C'.repeat(43) };
  return {
    accounts: {
      authenticate: (cookie: string | undefined) => cookie === 'ks_control_session=valid' ? session : null,
      clearSession: (_cookie: string | undefined) => undefined,
      registrationChallenge: () => ({ id: 'challenge', challenge: 'challenge', rpId: 'localhost' }),
      register: async (_input: unknown) => ({ account: { id: 'owner', plan: 'free' }, session, cookie: 'ks_control_session=valid; HttpOnly; SameSite=Strict; Path=/' }),
      assertionChallenge: async (_id: string) => ({ id: 'challenge', challenge: 'challenge', rpId: 'localhost', credentialId: 'credential' }),
      signIn: async (_input: unknown) => ({ account: { id: 'owner', plan: 'free' }, session, cookie: 'ks_control_session=valid; HttpOnly; SameSite=Strict; Path=/' }),
      ownsBox: async (accountId: string, boxId: string) => ownership.get(boxId) === accountId && !pending.has(boxId),
      reserveBox: async (accountId: string, boxId: string) => {
        if (plan !== 'paid') throw Object.assign(new Error('unpaid'), {status:402});
        if (ownership.has(boxId) && (ownership.get(boxId) !== accountId || !pending.has(boxId))) throw Object.assign(new Error('taken'), {status:409});
        ownership.set(boxId, accountId); pending.add(boxId);
      },
      confirmBox: async (_accountId: string, boxId: string) => { pending.delete(boxId); },
      releaseBox: async (_accountId: string, boxId: string) => { if (pending.delete(boxId)) ownership.delete(boxId); },
      boxOwner: async (boxId: string) => pending.has(boxId) ? null : ownership.get(boxId) ?? null,
    },
    relay: {
      publish: async (boxId: string, message: unknown) => { messages.set(boxId, [...(messages.get(boxId) ?? []), message]); return { id: 'message' }; },
      poll: async (boxId: string, _sessionId?: string) => messages.get(boxId) ?? [],
      putBlob: async (_boxId: string, input: {kind: string; ciphertext: string; ttlMs?: number}) => ({id:'blob',expiresAt:999}),
      getBlob: async (_boxId: string, _id: string) => null,
    },
    billing: { handle: async (_body: Buffer, _signature: string) => ({ received: true, applied: false, replayed: false }) },
    provisioner: { provision: async ({name}: {name: string; deviceKey: string}) => { provisioned.push(name); return {name, status:'PENDING'}; } },
    ownership, pending, provisioned, setPlan(value: 'free'|'paid') { plan = value; },
  };
}

async function setup(extra: Record<string, unknown> = {}) {
  const server = createControlPlaneServer({ origin: 'http://127.0.0.1:0', ...services(), ...extra });
  servers.push(server);
  const {origin} = await server.listen();
  const http: HttpClient = {
    request(input) {
      return new Promise((resolve,reject) => {
        const req = request(input.url.replace(/^https:/,'http:'), {method:input.method,headers:input.headers,path:input.url.slice(origin.length)}, res => {
          const chunks: Buffer[] = [];
          res.on('data', chunk => chunks.push(Buffer.from(chunk)));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            const headers: Record<string,string> = {};
            for (const [key,value] of Object.entries(res.headers)) if (value !== undefined) headers[key] = Array.isArray(value) ? value.join(', ') : value;
            resolve({status:res.statusCode!,headers,text,json:<T>() => JSON.parse(text) as T});
          });
        });
        req.on('error',reject);
        req.end(input.body);
      });
    },
  };
  const call = (path: string, method: 'GET'|'POST'|'DELETE' = 'GET', body?: unknown, headers?: Record<string,string>) => http.request({url:origin+path,method,body:body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),headers:{...(body === undefined ? {} : {'Content-Type':'application/json'}),...headers}});
  const browser = {Cookie:'ks_control_session=valid',Origin:origin,'X-CSRF-Token':'C'.repeat(43)};
  return {server,origin,http,call,browser};
}

describe('control plane HTTP server', () => {
  it('registers a real passkey at its random-port origin and authenticates its owner cookie', async () => {
    const storage=createMemoryStorage();
    const {call,origin}=await setup({accounts:(actualOrigin:string)=>createAccounts({storage,origin:actualOrigin})});
    const challengeResponse=await call('/auth/register/challenge','POST',{},{Origin:origin});
    expect(challengeResponse.status).toBe(200);
    const challenge=challengeResponse.json<{id:string;challenge:string;rpId:string}>();
    const publicKey=generateKeyPairSync('ed25519').publicKey;
    const credentialId=randomBytes(16);
    const cose=encode(new Map<number,unknown>([[1,1],[3,-8],[-1,6],[-2,Buffer.from(publicKey.export({format:'jwk'}).x!,'base64url')]]));
    const length=Buffer.alloc(2);length.writeUInt16BE(credentialId.length);
    const authData=Buffer.concat([createHash('sha256').update('127.0.0.1').digest(),Buffer.from([0x45]),Buffer.alloc(4),Buffer.alloc(16),length,credentialId,cose]);
    const clientDataJSON=Buffer.from(JSON.stringify({type:'webauthn.create',challenge:challenge.challenge,origin}));
    const attestationObject=encode(new Map<string,unknown>([['fmt','none'],['attStmt',new Map()],['authData',authData]]));
    const registered=await call('/auth/register/finish','POST',{
      challengeId:challenge.id,clientDataJSON:clientDataJSON.toString('base64url'),attestationObject:attestationObject.toString('base64url'),
    },{Origin:origin});
    expect(registered.status).toBe(200);
    const result=registered.json<{account:{id:string};csrf:string}>();
    const cookie=registered.headers['set-cookie']!.split(';')[0]!;
    const browser={Origin:origin,Cookie:cookie,'X-CSRF-Token':result.csrf};
    expect((await call('/session','GET',undefined,{Cookie:cookie})).json()).toEqual({accountId:result.account.id,csrf:result.csrf});
    expect((await call('/session','GET',undefined,{Cookie:`${cookie}; ${cookie}`})).status).toBe(401);
    expect((await call('/boxes','POST',{name:'real-account-box',deviceKey},browser)).status).toBe(402);
    await storage.put(`accounts/${result.account.id}`,{...await storage.get<object>(`accounts/${result.account.id}`),plan:'paid'});
    expect((await call('/boxes','POST',{name:'real-account-box',deviceKey},browser)).status).toBe(201);
    expect((await call('/boxes/real-account-box/messages','GET',undefined,{Cookie:cookie})).status).toBe(200);
    expect((await call('/boxes','POST',{name:'second-box',deviceKey},browser)).status).toBe(403);
  });

  it('returns JSON health with the approval server security headers', async () => {
    const {call} = await setup();
    const response = await call('/healthz');
    expect(response.status).toBe(200);
    expect(response.json()).toEqual({ok:true});
    expect(response.headers['content-type']).toMatch(/^application\/json/);
    expect(response.headers['content-security-policy']).toBe(CSP);
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers['referrer-policy']).toBe('no-referrer');
    expect(response.headers['permissions-policy']).toBe('publickey-credentials-get=(self), publickey-credentials-create=(self)');
    expect(response.headers['x-frame-options']).toBe('DENY');
    // Cloud Run reserves some paths ending in z; /health is the hosted spelling.
    expect((await call('/health')).json()).toEqual({ok:true});
  });

  it('requires an owner session to read boxes and enforces ownership', async () => {
    const {call,browser} = await setup();
    expect((await call('/boxes/alpha/messages')).status).toBe(401);
    expect((await call('/boxes/beta/messages','GET',undefined,browser)).status).toBe(403);
    expect((await call('/boxes/alpha/messages','GET',undefined,browser)).json()).toEqual({messages:[]});
  });

  it('adds HSTS for HTTPS and clears cookies with matching attributes', async () => {
    const {call,browser} = await setup({origin:'https://127.0.0.1:0'});
    const response = await call('/session','DELETE',undefined,browser);
    expect(response.status).toBe(200);
    expect(response.headers['strict-transport-security']).toBe('max-age=31536000');
    expect(response.headers['set-cookie']).toContain('HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Secure');
  });

  it('passes blob ciphertext without returning other boxes blobs', async () => {
    let stored:unknown=null;
    const dependencies=services();
    const {call,browser}=await setup({...dependencies,relay:{...dependencies.relay,
      putBlob:async(_boxId:string,input:unknown)=>{stored=input;return{id:'blob',expiresAt:999};},
      getBlob:async()=>stored,
    }});
    expect((await call('/boxes/alpha/blobs','POST',{kind:'sealed-state',ciphertext:'Y2lwaGVydGV4dA'},browser)).json()).toEqual({id:'blob',expiresAt:999});
    expect((await call('/boxes/alpha/blobs/blob','GET',undefined,browser)).json()).toEqual({kind:'sealed-state',ciphertext:'Y2lwaGVydGV4dA'});
    expect((await call('/boxes/beta/blobs/blob','GET',undefined,browser)).status).toBe(403);
  });

  it('requires matching Origin and CSRF for browser writes', async () => {
    const {call,browser} = await setup();
    expect((await call('/boxes/alpha/messages','POST',{opaque:true},{Cookie:browser.Cookie})).status).toBe(403);
    expect((await call('/boxes/alpha/messages','POST',{opaque:true},{...browser,Origin:'https://elsewhere.test'})).status).toBe(403);
    expect((await call('/boxes/alpha/messages','POST',{opaque:true},{...browser,'X-CSRF-Token':'bad'})).status).toBe(403);
    expect((await call('/boxes/alpha/messages','POST',{opaque:true},browser)).status).toBe(201);
    expect((await call('/boxes/alpha/messages','GET',undefined,browser)).json()).toEqual({messages:[{opaque:true}]});
  });

  it('scopes bearer capabilities to a single box and supports revocation', async () => {
    const {call,server} = await setup();
    const token = server.issueBoxToken('alpha');
    const headers = {Authorization:`Bearer ${token}`};
    expect((await call('/boxes/alpha/messages','POST',{opaque:true},headers)).status).toBe(201);
    expect((await call('/boxes/beta/messages','GET',undefined,headers)).status).toBe(403);
    server.revokeBoxToken('alpha');
    expect((await call('/boxes/alpha/messages','GET',undefined,headers)).status).toBe(401);
  });

  it('does not let a box capability provision another box', async () => {
    const {call,server} = await setup();
    expect((await call('/boxes','POST',{name:'new-box',deviceKey},{Authorization:`Bearer ${server.issueBoxToken('alpha')}`})).status).toBe(401);
  });

  it('provisions for the signed-in account and records ownership', async () => {
    const {call,browser} = await setup();
    const response = await call('/boxes','POST',{name:'new-box',deviceKey},browser);
    expect(response.status).toBe(201);
    expect(response.json()).toEqual({boxId:'new-box',operation:{name:'new-box',status:'PENDING'}});
    expect((await call('/boxes/new-box/messages','GET',undefined,browser)).status).toBe(200);
  });

  it('rejects non-JSON, malformed JSON, compression and oversized bodies', async () => {
    const {call,browser} = await setup({maxBodyBytes:128});
    expect((await call('/boxes/alpha/messages','POST','{}',{...browser,'Content-Type':'text/plain'})).status).toBe(415);
    expect((await call('/boxes/alpha/messages','POST','{',browser)).status).toBe(400);
    expect((await call('/boxes/alpha/messages','POST','{}',{...browser,'Content-Encoding':'gzip'})).status).toBe(415);
    expect((await call('/boxes/alpha/messages','POST',{x:'x'.repeat(129)},browser)).status).toBe(413);
  });

  it('rate limits the socket client even when forwarded addresses change', async () => {
    const {call} = await setup({rateLimitPerMinute:2});
    expect((await call('/healthz','GET',undefined,{'X-Forwarded-For':'1.1.1.1'})).status).toBe(200);
    expect((await call('/healthz','GET',undefined,{'X-Forwarded-For':'2.2.2.2'})).status).toBe(200);
    const response = await call('/healthz','GET',undefined,{'X-Forwarded-For':'3.3.3.3'});
    expect(response.status).toBe(429);
    expect(response.headers['retry-after']).toBeDefined();
  });

  it('never reflects input or upstream errors into logs or response errors', async () => {
    const logs: unknown[] = [];
    const secret = 'planted-plaintext-value';
    const dependencies = services();
    dependencies.relay.publish = async () => { throw new Error(secret); };
    const {call,browser} = await setup({...dependencies,log:(entry:unknown) => logs.push(entry)});
    const response = await call('/boxes/alpha/messages','POST',{secret},browser);
    expect(response.status).toBe(500);
    expect(response.text).not.toContain(secret);
    expect(JSON.stringify(logs)).not.toContain(secret);
    expect(logs).toEqual([{event:'request',status:500}]);
  });

  it('forwards the exact webhook body bytes without reserialization', async () => {
    let seen = '';
    const {call} = await setup({billing:{handle:async(raw:Buffer,signature:string) => {seen=raw.toString('utf8')+signature; return {received:true,applied:false,replayed:false};}}});
    const raw = '{ "type" : "ignored" }\n';
    expect((await call('/billing/webhook','POST',raw,{'Stripe-Signature':'t=1,v1=abc'})).status).toBe(200);
    expect(seen).toBe(raw+'t=1,v1=abc');
  });

  it('answers 503 when billing cannot confirm a payment yet, so Stripe retries, and 400 for anything else', async () => {
    let failure: unknown = Object.assign(new Error('planted-upstream-detail'),{status:503});
    const {call} = await setup({billing:{handle:async()=>{throw failure;}}});
    const retry = await call('/billing/webhook','POST','{}',{'Stripe-Signature':'t=1,v1=abc'});
    expect(retry.status).toBe(503);
    expect(retry.text).not.toContain('planted-upstream-detail');
    failure = new Error('bad signature');
    expect((await call('/billing/webhook','POST','{}',{'Stripe-Signature':'t=1,v1=abc'})).status).toBe(400);
  });

  it('requires auth ceremony Origin and never returns session bearer ids', async () => {
    const {call,origin} = await setup();
    expect((await call('/auth/register/challenge','POST',{})).status).toBe(403);
    expect((await call('/auth/register/challenge','POST',{},{Origin:origin})).status).toBe(200);
    const response = await call('/auth/register/finish','POST',{challengeId:'challenge',clientDataJSON:'e30',attestationObject:'e30'},{Origin:origin});
    expect(response.status).toBe(200);
    expect(response.headers['set-cookie']).toContain('HttpOnly');
    expect(response.json()).toEqual({account:{id:'owner',plan:'free'},csrf:'C'.repeat(43)});
  });

  it('rejects unexpected hosts, paths and methods with JSON errors', async () => {
    const {call} = await setup();
    expect((await call('/healthz','GET',undefined,{Host:'other.test'})).status).toBe(403);
    expect((await call('/healthz','POST',{})).status).toBe(405);
    expect((await call('/healthz?secret=value')).status).toBe(404);
    expect((await call('/boxes/../healthz')).status).toBe(404);
  });
});

describe('H1: provisioning needs a paid plan, quota and a free name before Compute', () => {
  it('refuses an unpaid account with 402 and never calls Compute', async () => {
    const dependencies = services(); dependencies.setPlan('free');
    const {call,browser} = await setup(dependencies);
    expect((await call('/boxes','POST',{name:'new-box',deviceKey},browser)).status).toBe(402);
    expect(dependencies.provisioned).toEqual([]);
  });
  it('refuses a name another account holds before Compute', async () => {
    const dependencies = services();
    const {call,browser} = await setup(dependencies);
    expect((await call('/boxes','POST',{name:'beta',deviceKey},browser)).status).toBe(409);
    expect(dependencies.provisioned).toEqual([]);
  });
  it.each([
    ['upper case', {name:'New-Box',deviceKey}], ['a reserved prefix', {name:'gcp-box',deviceKey}], ['a trailing hyphen', {name:'box-',deviceKey}],
    ['no device key', {name:'new-box'}], ['an X25519 device key', {name:'new-box',deviceKey:generateKeyPairSync('x25519').publicKey.export({format:'der',type:'spki'}).toString('base64')}],
    ['an extra field', {name:'new-box',deviceKey,zone:'us-east1-b'}],
  ])('answers 400 for %s', async (_name, body) => {
    const dependencies = services();
    const {call,browser} = await setup(dependencies);
    expect((await call('/boxes','POST',body,browser)).status).toBe(400);
    expect(dependencies.provisioned).toEqual([]);
  });
  it('releases the reservation when Compute fails, so the name can be tried again', async () => {
    const dependencies = services();
    let fail = true;
    const {call,browser} = await setup({...dependencies,provisioner:{provision:async({name}:{name:string})=>{if(fail)throw new Error('planted-compute-detail');return{name,status:'DONE'};}}});
    const failed = await call('/boxes','POST',{name:'new-box',deviceKey},browser);
    expect(failed.status).toBe(502);
    expect(failed.text).not.toContain('planted-compute-detail');
    expect(dependencies.ownership.has('new-box')).toBe(false);
    fail = false;
    expect((await call('/boxes','POST',{name:'new-box',deviceKey},browser)).status).toBe(201);
  });
  it('is unavailable (503) when the accounts service cannot reserve boxes', async () => {
    const dependencies = services();
    const {reserveBox:_r,...accounts} = dependencies.accounts;
    const {call,browser} = await setup({...dependencies,accounts});
    expect((await call('/boxes','POST',{name:'new-box',deviceKey},browser)).status).toBe(503);
    expect(dependencies.provisioned).toEqual([]);
  });
});

describe('H2: rate limits keyed by credential and trusted client address', () => {
  it('gives each box credential and each account its own budget, apart from anonymous traffic', async () => {
    const {call,server,browser} = await setup({rateLimitPerMinute:3,boxRateLimitPerMinute:3});
    const alpha = {Authorization:`Bearer ${server.issueBoxToken('alpha')}`};
    const beta = {Authorization:`Bearer ${server.issueBoxToken('beta')}`};
    for (let i = 0; i < 3; i++) expect((await call('/healthz')).status).toBe(200);
    expect((await call('/healthz')).status).toBe(429);
    for (let i = 0; i < 3; i++) expect((await call('/boxes/alpha/messages','GET',undefined,alpha)).status).toBe(200);
    expect((await call('/boxes/alpha/messages','GET',undefined,alpha)).status).toBe(429);
    expect((await call('/boxes/beta/messages','GET',undefined,beta)).status).toBe(200);
    expect((await call('/boxes/alpha/messages','GET',undefined,browser)).status).toBe(200);
  });
  it('charges invalid credentials to the client address', async () => {
    const {call} = await setup({rateLimitPerMinute:2});
    const forged = {Authorization:`Bearer ${'A'.repeat(43)}`};
    expect((await call('/boxes/alpha/messages','GET',undefined,forged)).status).toBe(401);
    expect((await call('/boxes/alpha/messages','GET',undefined,forged)).status).toBe(401);
    expect((await call('/boxes/alpha/messages','GET',undefined,forged)).status).toBe(429);
    expect((await call('/healthz')).status).toBe(429);
  });
  it('keys anonymous requests by the trusted front end\'s client entry and ignores spoofed earlier entries', async () => {
    const {call} = await setup({rateLimitPerMinute:1,trustedProxy:{header:'x-forwarded-for',hops:2}});
    const via = (chain: string) => call('/healthz','GET',undefined,{'X-Forwarded-For':chain});
    expect((await via('198.51.100.1, 203.0.113.10')).status).toBe(200);
    expect((await via('9.9.9.9, 198.51.100.1, 203.0.113.10')).status).toBe(429);
    expect((await via('198.51.100.2, 203.0.113.10')).status).toBe(200);
    expect((await via('2001:db8:1:2::1, 203.0.113.10')).status).toBe(200);
    expect((await via('2001:db8:1:2:ffff::9, 203.0.113.10')).status).toBe(429);
  });
  it('gives the Stripe webhook its own budget', async () => {
    const {call} = await setup({rateLimitPerMinute:1,webhookRateLimitPerMinute:2});
    expect((await call('/healthz')).status).toBe(200);
    expect((await call('/healthz')).status).toBe(429);
    for (let i = 0; i < 2; i++) expect((await call('/billing/webhook','POST','{}',{'Stripe-Signature':'t=1,v1=abc'})).status).toBe(200);
    expect((await call('/billing/webhook','POST','{}',{'Stripe-Signature':'t=1,v1=abc'})).status).toBe(429);
  });
  it('evicts the least recently used bucket instead of refusing a new client', async () => {
    let clock = 1_000_000;
    const {call,server} = await setup({rateLimitPerMinute:1,boxRateLimitPerMinute:1,maxRateBuckets:2,now:()=>clock});
    const tokens = ['alpha','beta','gamma'].map(id => ({id,headers:{Authorization:`Bearer ${server.issueBoxToken(id)}`}}));
    for (const {id,headers} of tokens) expect((await call(`/boxes/${id}/messages`,'GET',undefined,headers)).status).toBe(200);
    clock += 1;
    expect((await call('/boxes/gamma/messages','GET',undefined,tokens[2]!.headers)).status).toBe(429);
  });
  it('normalizes client addresses: IPv4-mapped to IPv4, IPv6 to its /64', () => {
    expect(clientKey('::ffff:192.0.2.7')).toBe('192.0.2.7');
    expect(clientKey('2001:db8::1')).toBe(clientKey('2001:0db8:0000:0000:ffff::2'));
    expect(clientKey('2001:db8:0:1::1')).not.toBe(clientKey('2001:db8::1'));
    expect(clientKey('[fe80::1%eth0]')).toBe('fe80:0000:0000:0000::/64');
    expect(clientKey('not-an-address')).toBe('unknown');
  });
});

describe('L5: refused and oversized requests', () => {
  it('closes the connection after refusing an oversized body instead of draining it', async () => {
    const {origin,browser} = await setup({maxBodyBytes:128});
    const {port} = new URL(origin);
    const reply = await new Promise<string>((resolve,reject) => {
      const socket = connect(Number(port),'127.0.0.1',() => {
        socket.write(`POST /boxes/alpha/messages HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nCookie: ${browser.Cookie}\r\nOrigin: ${origin}\r\nX-CSRF-Token: ${browser['X-CSRF-Token']}\r\nContent-Type: application/json\r\nContent-Length: 100000000\r\n\r\n{"x":"`);
      });
      let data = '';
      socket.on('data',chunk => { data += chunk.toString(); });
      socket.on('close',() => resolve(data));
      socket.on('error',reject);
      setTimeout(() => { socket.destroy(); reject(new Error('connection stayed open')); },5_000);
    });
    expect(reply).toMatch(/^HTTP\/1\.1 413/);
    expect(reply.toLowerCase()).toContain('connection: close');
  });
  it('limits open connections per socket address', async () => {
    const {origin} = await setup({maxConnectionsPerAddress:2});
    const {port} = new URL(origin);
    const sockets = await Promise.all([0,1,2].map(() => new Promise<{closed:Promise<boolean>}>(resolve => {
      const socket = connect(Number(port),'127.0.0.1',() => resolve({closed:new Promise(done => { socket.once('close',() => done(true)); setTimeout(() => { done(false); socket.destroy(); },500); })}));
    })));
    const closed = await Promise.all(sockets.map(entry => entry.closed));
    expect(closed.filter(Boolean).length).toBeGreaterThanOrEqual(1);
  });
});

describe('M5: boxes authenticate with an attestation token for the relay origin', () => {
  let emulator: Emulator;
  afterEach(async () => { await emulator?.close(); });
  async function attested(extra: Record<string, unknown> = {}, knownBox?: (boxId: string) => Promise<boolean>) {
    emulator = await startEmulator();
    let jwksCalls = 0;
    const policy = emulator.policy;
    const context = await setup({ boxAttestation: { jwks: async () => { jwksCalls++; return emulator.jwks; }, root: emulator.root,
      projectIds: [policy.projectId], serviceAccounts: [policy.serviceAccount], allowedDigests: policy.allowedDigests, hardwareModels: ['GCP_INTEL_TDX'],
      ...(knownBox ? { knownBox } : {}) }, ...extra });
    const token = (instanceName: string, switches = {}, audience = context.origin) => emulator.mintToken({ audience, nonces: [], instanceName, switches });
    return { ...context, token, jwksCalls: () => jwksCalls };
  }
  const bearer = (value: string) => ({Authorization:`Bearer ${value}`});
  it('accepts a production token naming the box, for that box only, and caches the verification', async () => {
    const {call,token,jwksCalls} = await attested();
    const alpha = token('alpha');
    expect((await call('/boxes/alpha/messages','POST',{opaque:true},bearer(alpha))).status).toBe(201);
    expect((await call('/boxes/alpha/messages','GET',undefined,bearer(alpha))).json()).toEqual({messages:[{opaque:true}]});
    expect((await call('/boxes/beta/messages','GET',undefined,bearer(alpha))).status).toBe(403);
    expect(jwksCalls()).toBe(1);
    expect((await call('/session','GET',undefined,bearer(alpha))).status).toBe(401);
    expect((await call('/boxes','POST',{name:'new-box',deviceKey},bearer(alpha))).status).toBe(401);
  });
  it.each([
    ['another audience', (t: (n: string, s?: object, a?: string) => string) => t('alpha', {}, 'https://sts.googleapis.com')],
    ['a debug image', (t: (n: string, s?: object) => string) => t('alpha', { debugImage: true })],
    ['another project', (t: (n: string, s?: object) => string) => t('alpha', { otherProject: true })],
    ['another service account', (t: (n: string, s?: object) => string) => t('alpha', { otherServiceAccount: true })],
    ['an image outside the allow-list', (t: (n: string, s?: object) => string) => t('alpha', { wrongDigest: true })],
    ['no STABLE support', (t: (n: string, s?: object) => string) => t('alpha', { missingStable: true })],
    ['a stale token', (t: (n: string, s?: object) => string) => t('alpha', { staleIat: true })],
    ['an instance with no owner', (t: (n: string) => string) => t('unknown-box')],
  ])('refuses a token from %s', async (_name, make) => {
    const {call,token} = await attested();
    const value = make(token as never);
    const target = value.includes('.') && JSON.parse(Buffer.from(value.split('.')[1]!,'base64url').toString()).submods.gce.instance_name;
    expect((await call(`/boxes/${target}/messages`,'GET',undefined,bearer(value))).status).toBe(401);
  });
  it('refuses a token whose signature does not verify', async () => {
    const {call,token} = await attested();
    const [head,payload,signature] = token('alpha').split('.');
    const forged = `${head}.${payload}.${signature!.slice(0,-2)}${signature!.endsWith('AA')?'BB':'AA'}`;
    expect((await call('/boxes/alpha/messages','GET',undefined,bearer(forged))).status).toBe(401);
  });
  it('honours a custom existence check, and refuses tokens when attestation is not configured', async () => {
    const {call,token} = await attested({}, async boxId => boxId === 'gamma');
    expect((await call('/boxes/alpha/messages','GET',undefined,bearer(token('alpha')))).status).toBe(401);
    expect((await call('/boxes/gamma/messages','GET',undefined,bearer(token('gamma')))).status).toBe(200);
    const plain = await setup();
    expect((await plain.call('/boxes/alpha/messages','GET',undefined,bearer(token('alpha')))).status).toBe(401);
  });
});

describe('graceful shutdown', () => {
  it('lets the deadline close a connection whose request never finishes', async () => {
    const {server,origin} = await setup();
    const url = new URL(origin);
    const socket = connect(Number(url.port), '127.0.0.1');
    await new Promise<void>(resolve => socket.once('connect', () => resolve()));
    // A body that never arrives keeps the request open.
    socket.write(`POST /billing/webhook HTTP/1.1\r\nHost: ${url.host}\r\nContent-Type: application/json\r\nStripe-Signature: t=1,v1=00\r\nContent-Length: 100\r\n\r\n{`);
    await new Promise(resolve => setTimeout(resolve, 50));
    const closed = new Promise<void>(resolve => socket.once('close', () => resolve()));
    const started = Date.now();
    await server.close({deadlineMs: 100});
    await closed;
    expect(Date.now() - started).toBeLessThan(5_000);
  });
});
