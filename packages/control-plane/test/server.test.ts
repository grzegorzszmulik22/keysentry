import { request } from 'node:http';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { createControlPlaneServer } from '../src/server.js';
import { createAccounts } from '../src/accounts.js';
import { createMemoryStorage } from '../src/storage.js';
import { encode } from '../../../test/approvals/webauthn/helpers.js';
import type { HttpClient } from '../../../src/types.js';

const servers: ReturnType<typeof createControlPlaneServer>[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map(server => server.close())); });

function services() {
  const ownership = new Map([['alpha','owner'], ['beta','other']]);
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
      ownsBox: async (accountId: string, boxId: string) => ownership.get(boxId) === accountId,
      addBox: async (accountId: string, boxId: string) => { ownership.set(boxId, accountId); },
    },
    relay: {
      publish: async (boxId: string, message: unknown) => { messages.set(boxId, [...(messages.get(boxId) ?? []), message]); return { id: 'message' }; },
      poll: async (boxId: string, _sessionId?: string) => messages.get(boxId) ?? [],
      putBlob: async (_boxId: string, input: {kind: string; ciphertext: string; ttlMs?: number}) => ({id:'blob',expiresAt:999}),
      getBlob: async (_boxId: string, _id: string) => null,
    },
    billing: { handle: async (_body: Buffer, _signature: string) => ({ received: true, applied: false, replayed: false }) },
    provisioner: { provision: async ({name}: {name: string}) => ({name, status:'PENDING'}) },
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
    expect((await call('/boxes','POST',{name:'real-account-box'},browser)).status).toBe(201);
    expect((await call('/boxes/real-account-box/messages','GET',undefined,{Cookie:cookie})).status).toBe(200);
  });

  it('returns JSON health with the approval server security headers', async () => {
    const {call} = await setup();
    const response = await call('/healthz');
    expect(response.status).toBe(200);
    expect(response.json()).toEqual({ok:true});
    expect(response.headers['content-type']).toMatch(/^application\/json/);
    expect(response.headers['content-security-policy']).toBe("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers['referrer-policy']).toBe('no-referrer');
    expect(response.headers['permissions-policy']).toBe('publickey-credentials-get=(self)');
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
    expect((await call('/boxes','POST',{name:'new-box'},{Authorization:`Bearer ${server.issueBoxToken('alpha')}`})).status).toBe(401);
  });

  it('provisions for the signed-in account and records ownership', async () => {
    const {call,browser} = await setup();
    const response = await call('/boxes','POST',{name:'new-box'},browser);
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
