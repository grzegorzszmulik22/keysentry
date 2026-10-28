import { createHash, randomBytes, timingSafeEqual, type X509Certificate } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { isIP } from 'node:net';
import { verifyAttestation, type JwksFetcher } from '../../../src/box/attestation/index.js';
import { Lru } from './lock.js';
import { isBoxName, isDeviceKey } from './provision.js';

interface Session { accountId: string; id: string; csrf: string }
interface Authentication { account: unknown; session: Session; cookie: string }
export interface AccountsService {
  registrationChallenge(client?: string): unknown;
  register(input: {challengeId:string;clientDataJSON:Buffer;attestationObject:Buffer}): Promise<Authentication>;
  assertionChallenge(accountId: string, client?: string): Promise<unknown>;
  signIn(input: {accountId:string;challengeId:string;credentialId:string;clientDataJSON:Buffer;authenticatorData:Buffer;signature:Buffer}): Promise<Authentication>;
  authenticate(cookie: string | undefined): Session | null | Promise<Session | null>;
  clearSession(cookie: string | undefined): void | Promise<void>;
  ownsBox(accountId: string, boxId: string): Promise<boolean>;
  /** H1: plan, quota and name checks plus a pending ownership record, before any Compute call. */
  reserveBox?(accountId: string, boxId: string): Promise<void>;
  confirmBox?(accountId: string, boxId: string): Promise<void>;
  releaseBox?(accountId: string, boxId: string): Promise<void>;
  /** Owner of an active box; the default existence check for attested boxes. */
  boxOwner?(boxId: string): Promise<string | null>;
  /** True when checking this cookie needs no storage read. */
  cachedSession?(cookie: string | undefined): boolean;
  clearCookie?: string;
  addBox?(accountId: string, boxId: string): Promise<void>;
}
interface RelayService {
  publish(boxId:string,message:unknown):Promise<{id:string}>;
  poll(boxId:string,sessionId?:string):Promise<unknown[]>;
  putBlob(boxId:string,input:{kind:'sealed-bundle'|'sealed-state';ciphertext:string;ttlMs?:number}):Promise<{id:string;expiresAt:number}>;
  getBlob(boxId:string,id:string):Promise<unknown|null>;
  sweep?():Promise<void>;
}
/**
 * A hosted box authenticates with a Confidential Space attestation token whose audience is this server's origin
 * (`relayCredential` in src/box/agent/main.ts). The token is checked by the shared verifier against these anchors and
 * pins, and `submods.gce.instance_name` must name the box in the route.
 */
export interface BoxAttestationOptions {
  jwks: JwksFetcher;
  /** Pinned PKI root for `x5c` tokens (Google's root by default inside the verifier). */
  root?: X509Certificate;
  projectIds: string[];
  serviceAccounts: string[];
  allowedDigests: string[];
  hardwareModels?: ('GCP_INTEL_TDX' | 'GCP_AMD_SEV')[];
  /** Whether a box with this id exists. Default: it has an active owner (`accounts.boxOwner`). */
  knownBox?(boxId: string): Promise<boolean>;
}
/** A front end (load balancer, Cloud Run) that appends the connecting client's address to `header`. */
export interface TrustedProxy {
  /** Lower-case header name, e.g. `x-forwarded-for`. */
  header: string;
  /** Entries appended by trusted front ends; the client is this many entries from the right (ALB: 2). */
  hops: number;
}
export interface ControlPlaneServerOptions {
  /** Public HTTPS origin, or loopback HTTP origin for the local emulator. */
  origin: string;
  host?: string;
  port?: number;
  /** A factory receives the finalized origin after a random port has been bound. */
  accounts: AccountsService | ((origin:string)=>AccountsService);
  billing: {handle(rawBody:Buffer,signatureHeader:string):Promise<unknown>};
  relay: RelayService;
  provisioner?: {provision(input:{name:string;deviceKey:string}):Promise<unknown>};
  boxAttestation?: BoxAttestationOptions;
  /** Without it the socket peer is the client; forwarded headers are never trusted. */
  trustedProxy?: TrustedProxy;
  /** Per client address (anonymous) and per signed-in account. Default 120. */
  rateLimitPerMinute?: number;
  /** Per box credential. Default 120 (the agent polls 12 times a minute). */
  boxRateLimitPerMinute?: number;
  /** `/billing/webhook`, per client address. Default 300. */
  webhookRateLimitPerMinute?: number;
  /** Least recently used buckets are evicted beyond this. Default 10,000. */
  maxRateBuckets?: number;
  maxConnections?: number;
  /** Open connections per socket address when no trusted proxy is configured. Default 64. */
  maxConnectionsPerAddress?: number;
  maxBodyBytes?: number;
  now?: () => number;
  log?: (entry:{event:'request'|'cleanup';status:number}) => void;
}

class HttpError extends Error {
  constructor(readonly status:number, message:string) { super(message); }
}
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const ID = /^[A-Za-z0-9_-]{1,128}$/;
const RELAYED: Record<number,string> = {
  400:'Invalid request.', 409:'Invalid request.', 413:'Invalid request.', 429:'Please wait before trying again.',
  503:'The service is temporarily unavailable.', 507:'Relay storage is full.',
};
function fail(status:number,message='Invalid request.'):never { throw new HttpError(status,message); }
function exact(value:Record<string,unknown>,keys:string[],optional:string[]=[]):void {
  if (keys.some(key => !(key in value)) || Object.keys(value).some(key => !keys.includes(key) && !optional.includes(key))) fail(400);
}
function identifier(value:unknown):string {
  if (typeof value !== 'string' || !ID.test(value)) fail(400);
  return value;
}
function bytes(value:unknown,max:number):Buffer {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > Math.ceil(max*4/3)) fail(400);
  const data = Buffer.from(value,'base64url');
  if (!data.length || data.length > max || data.toString('base64url') !== value) fail(400);
  return data;
}
function same(actual:string|undefined,expected:string):boolean {
  if (actual === undefined || Buffer.byteLength(actual) !== Buffer.byteLength(expected)) return false;
  return timingSafeEqual(Buffer.from(actual),Buffer.from(expected));
}
function publicOrigin(value:string):URL {
  try {
    const url = new URL(value);
    if (url.origin !== value || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error();
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost','127.0.0.1','[::1]'].includes(url.hostname))) throw new Error();
    return url;
  } catch { throw new TypeError('Invalid control plane origin.'); }
}
/** IPv4 as is; IPv6 by its /64, since one host commonly holds a whole /64. */
export function clientKey(address:string):string {
  let value = address.trim();
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1,-1);
  value = value.split('%')[0]!.toLowerCase();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(value);
  if (mapped) value = mapped[1]!;
  const kind = isIP(value);
  if (kind === 4) return value;
  if (kind !== 6) return 'unknown';
  const v4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (v4) {
    const [a,b,c,d] = v4.slice(1).map(Number) as [number,number,number,number];
    value = `${value.slice(0,-v4[0].length)}${((a<<8)|b).toString(16)}:${((c<<8)|d).toString(16)}`;
  }
  const [head,tail] = value.split('::') as [string,string|undefined];
  const left = head ? head.split(':') : [], right = tail ? tail.split(':') : [];
  const groups = tail === undefined ? left : [...left,...Array(8-left.length-right.length).fill('0'),...right];
  return `${groups.slice(0,4).map(group=>group.padStart(4,'0')).join(':')}::/64`;
}
function rawBody(req:IncomingMessage,max:number):Promise<Buffer> {
  if (req.headers['content-encoding'] && req.headers['content-encoding'].toLowerCase() !== 'identity') fail(415,'Unsupported media type.');
  if ((req.headers['content-type'] ?? '').split(';',1)[0]!.trim().toLowerCase() !== 'application/json') fail(415,'Unsupported media type.');
  const length=req.headers['content-length'];
  if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > max)) fail(413,'Request body is too large.');
  return new Promise((resolve,reject) => {
    let total=0, settled=false;
    const chunks:Buffer[]=[];
    const stop = (error:HttpError) => {
      if (settled) return;
      // The response closes the connection (send() sees an incomplete request); the rest is never read.
      settled=true; chunks.length=0; req.removeListener('data',data); req.pause(); reject(error);
    };
    const data=(chunk:Buffer) => {
      total+=chunk.length;
      if(total>max) {stop(new HttpError(413,'Request body is too large.'));return;}
      chunks.push(Buffer.from(chunk));
    };
    req.on('data',data);
    req.once('error',()=>stop(new HttpError(400,'Invalid request.')));
    req.once('aborted',()=>stop(new HttpError(400,'Invalid request.')));
    req.once('end',()=>{if(!settled){settled=true;resolve(Buffer.concat(chunks));}});
  });
}
function jsonRecord(body:Buffer):Record<string,unknown> {
  try {
    const parsed:unknown=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(body));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
    return parsed as Record<string,unknown>;
  } catch {fail(400);}
}
type Route =
  | {kind:'health'} | {kind:'session'} | {kind:'webhook'} | {kind:'boxes'} | {kind:'auth';path:string}
  | {kind:'messages';boxId:string;sessionId?:string} | {kind:'blobs';boxId:string} | {kind:'blob';boxId:string;blobId:string};
function route(raw:string):Route|null {
  if (raw==='/healthz') return {kind:'health'};
  if (raw==='/session') return {kind:'session'};
  if (raw==='/billing/webhook') return {kind:'webhook'};
  if (raw==='/boxes') return {kind:'boxes'};
  if (['/auth/register/challenge','/auth/register/finish','/auth/login/challenge','/auth/login/finish'].includes(raw)) return {kind:'auth',path:raw};
  const message=/^\/boxes\/([A-Za-z0-9_-]{1,128})\/messages(?:\?sessionId=([A-Za-z0-9_-]{1,128}))?$/.exec(raw);
  if (message) return {kind:'messages',boxId:message[1]!,...(message[2]===undefined?{}:{sessionId:message[2]})};
  const blobs=/^\/boxes\/([A-Za-z0-9_-]{1,128})\/blobs$/.exec(raw);
  if (blobs) return {kind:'blobs',boxId:blobs[1]!};
  const blob=/^\/boxes\/([A-Za-z0-9_-]{1,128})\/blobs\/([A-Za-z0-9_-]{1,128})$/.exec(raw);
  if (blob) return {kind:'blob',boxId:blob[1]!,blobId:blob[2]!};
  return null;
}
const METHODS:Record<Route['kind'],string[]> = {
  health:['GET'], blob:['GET'], session:['GET','DELETE'], messages:['GET','POST'],
  webhook:['POST'], boxes:['POST'], auth:['POST'], blobs:['POST'],
};
type Principal = {kind:'box';boxId:string} | {kind:'session';session:Session} | {kind:'none';presented:boolean};
const sha256 = (value:string) => createHash('sha256').update(value).digest('hex');
function budgetOf(value:number|undefined,fallback:number):number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > 1_000_000) throw new TypeError('Invalid control plane configuration.');
  return result;
}

/** JSON transport only. It does not decrypt blobs, verify device authority or run a box. */
export function createControlPlaneServer(opts:ControlPlaneServerOptions) {
  let origin=publicOrigin(opts.origin);
  let accountService=typeof opts.accounts==='function'?null:opts.accounts;
  function accounts():AccountsService {
    if(!accountService) fail(503,'Accounts are unavailable.');
    return accountService;
  }
  const host=opts.host ?? '127.0.0.1';
  const port=opts.port ?? (origin.port ? Number(origin.port) : origin.protocol==='https:' ? 443 : 80);
  const max=opts.maxBodyBytes ?? 2*1024*1024;
  const budget=budgetOf(opts.rateLimitPerMinute,120);
  const boxBudget=budgetOf(opts.boxRateLimitPerMinute,120);
  const webhookBudget=budgetOf(opts.webhookRateLimitPerMinute,300);
  const bucketLimit=budgetOf(opts.maxRateBuckets,10_000);
  const perAddress=budgetOf(opts.maxConnectionsPerAddress,64);
  const now=opts.now ?? Date.now;
  const trusted=opts.trustedProxy;
  if ((host !== 'localhost' && !isIP(host)) || !Number.isInteger(port) || port<0 || port>65535 || !Number.isSafeInteger(max) || max<1 || max>4*1024*1024
    || (trusted !== undefined && (typeof trusted.header !== 'string' || !/^[a-z0-9-]{1,64}$/.test(trusted.header) || !Number.isSafeInteger(trusted.hops) || trusted.hops<1 || trusted.hops>10))) {
    throw new TypeError('Invalid control plane configuration.');
  }
  const attestation=opts.boxAttestation;
  if (attestation && (typeof attestation.jwks!=='function' || !attestation.projectIds?.length || !attestation.serviceAccounts?.length || !attestation.allowedDigests?.length)) {
    throw new TypeError('Invalid control plane configuration.');
  }
  // Issued bearers (local emulator and tests): hash -> box, and box -> its one current hash.
  const bearers=new Map<string,string>();
  const bearerOf=new Map<string,string>();
  const verified=new Lru<string,{boxId:string;until:number}>(4096);
  const buckets=new Lru<string,{at:number;tokens:number}>(bucketLimit);
  const headers:Record<string,string>={
    'Content-Security-Policy':CSP,'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
    'Cache-Control':'no-store','Permissions-Policy':'publickey-credentials-get=(self)',
    'Content-Type':'application/json; charset=utf-8',
  };
  if(origin.protocol==='https:') headers['Strict-Transport-Security']='max-age=31536000';
  function log(event:'request'|'cleanup',status:number) {try {opts.log?.({event,status});}catch{/* Logs cannot alter request outcomes. */}}
  function send(req:IncomingMessage,res:ServerResponse,status:number,value:unknown) {
    // L5: a body that was refused or never read is not drained; the connection closes after this response.
    res.writeHead(status,{...headers,...(req.complete?{}:{Connection:'close'})});
    res.end(JSON.stringify(value));log('request',status);
  }
  function take(key:string,limit:number):boolean {
    const current=now();
    let bucket=buckets.get(key);
    if(!bucket) {bucket={at:current,tokens:limit};buckets.set(key,bucket);}
    bucket.tokens=Math.min(limit,bucket.tokens+Math.max(0,current-bucket.at)*limit/60_000);
    bucket.at=current;
    if(bucket.tokens<1) return false;
    bucket.tokens--;return true;
  }
  function limited(res:ServerResponse,limit:number):never {res.setHeader('Retry-After',String(Math.ceil(60/limit)));fail(429,'Please wait before trying again.');}
  function clientAddress(req:IncomingMessage):string {
    if(trusted) {
      const raw=req.headers[trusted.header];
      const value=Array.isArray(raw)?raw.join(','):raw;
      if(typeof value==='string'&&value.length<=4096) {
        const parts=value.split(',').map(part=>part.trim()).filter(Boolean);
        const candidate=parts.length>=trusted.hops?parts[parts.length-trusted.hops]!:'';
        const key=clientKey(candidate);
        if(key!=='unknown') return key;
      }
    }
    return clientKey(req.socket.remoteAddress??'');
  }
  // A forced JWKS refresh (unknown key id) runs at most every five minutes, so random key ids cannot amplify.
  let lastRefresh=-Infinity;
  const jwks:JwksFetcher=async force=>{
    if(force){if(now()-lastRefresh<300_000) return attestation!.jwks(false);lastRefresh=now();}
    return attestation!.jwks(force);
  };
  async function attestedBox(token:string):Promise<{boxId:string;until:number}|null> {
    if(!attestation) return null;
    try {
      const result=await verifyAttestation({token,jwks,...(attestation.root?{root:attestation.root}:{}),expectedNonces:[],now:new Date(now()),policy:{
        audience:origin.origin,projectIds:attestation.projectIds,serviceAccounts:attestation.serviceAccounts,allowedDigests:attestation.allowedDigests,
        hardwareModels:attestation.hardwareModels??['GCP_INTEL_TDX','GCP_AMD_SEV'],maxTokenAgeSeconds:3600,clockSkewSeconds:60}});
      // The relay credential carries no nonces; every other check of the shared verifier must pass.
      if(!result.claims||result.checks.some(check=>!check.ok&&!check.name.startsWith('nonce-'))) return null;
      const boxId=result.claims.submods?.gce?.instance_name;
      if(!isBoxName(boxId)) return null;
      const known=attestation.knownBox?await attestation.knownBox(boxId):accounts().boxOwner?Boolean(await accounts().boxOwner!(boxId)):false;
      if(!known) return null;
      return {boxId,until:Math.min(result.claims.exp,result.claims.iat+3600)*1000};
    } catch {return null;}
  }
  /** Resolves the credential for credentialed routes; expensive first-time checks are charged to the client first. */
  async function principal(req:IncomingMessage,res:ServerResponse,client:string,sessionOnly:boolean):Promise<{who:Principal;charged:boolean}> {
    const auth=req.headers.authorization;
    if(auth!==undefined) {
      if(sessionOnly) return {who:{kind:'none',presented:true},charged:false};
      const issued=/^Bearer ([A-Za-z0-9_-]{43})$/.exec(auth);
      if(issued) {const boxId=bearers.get(sha256(issued[1]!));return {who:boxId?{kind:'box',boxId}:{kind:'none',presented:true},charged:false};}
      const jwt=auth.length<=16*1024?/^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/.exec(auth):null;
      if(jwt&&attestation) {
        const key=sha256(jwt[1]!);
        const cached=verified.get(key);
        if(cached&&now()<cached.until) return {who:{kind:'box',boxId:cached.boxId},charged:false};
        if(cached) verified.delete(key);
        if(!take(`anon:${client}`,budget)) limited(res,budget);
        const box=await attestedBox(jwt[1]!);
        if(!box) return {who:{kind:'none',presented:true},charged:true};
        verified.set(key,box);
        return {who:{kind:'box',boxId:box.boxId},charged:true};
      }
      return {who:{kind:'none',presented:true},charged:false};
    }
    const cookie=req.headers.cookie;
    if(cookie===undefined) return {who:{kind:'none',presented:false},charged:false};
    let charged=false;
    if(accounts().cachedSession&&!accounts().cachedSession!(cookie)) {
      if(!take(`anon:${client}`,budget)) limited(res,budget);
      charged=true;
    }
    const active=await accounts().authenticate(cookie);
    return {who:active?{kind:'session',session:active}:{kind:'none',presented:true},charged};
  }
  function browserOrigin(req:IncomingMessage):void {
    if(req.headers.origin!==origin.origin) fail(403,'Request origin is not allowed.');
  }
  function csrf(req:IncomingMessage,active:Session):void {
    browserOrigin(req);
    const value=req.headers['x-csrf-token'];
    if(typeof value!=='string'||!same(value,active.csrf)) fail(403,'Request authorization is required.');
  }
  function signedIn(who:Principal):Session {
    if(who.kind!=='session') fail(401,'Sign in to continue.');
    return who.session;
  }
  const open=new Map<string,number>();
  const server=createServer({maxHeaderSize:16*1024},(req,res)=>{void handle(req,res);});
  server.requestTimeout=15_000;
  server.headersTimeout=10_000;
  server.keepAliveTimeout=5_000;
  server.maxConnections=budgetOf(opts.maxConnections,1024);
  if(!trusted) server.on('connection',socket=>{
    const key=clientKey(socket.remoteAddress??'');
    const count=(open.get(key)??0)+1;
    if(count>perAddress){socket.destroy();return;}
    open.set(key,count);
    socket.once('close',()=>{const left=(open.get(key)??1)-1;if(left<=0)open.delete(key);else open.set(key,left);});
  });
  async function handle(req:IncomingMessage,res:ServerResponse):Promise<void> {
    try {
      const hostCount=req.rawHeaders.filter((value,index)=>index%2===0&&value.toLowerCase()==='host').length;
      if(hostCount!==1||req.headers.host!==origin.host) fail(403,'Request origin is not allowed.');
      const client=clientAddress(req);
      const target=route(req.url??'');
      let who:Principal={kind:'none',presented:false};
      if(target?.kind==='webhook') {if(!take(`webhook:${client}`,webhookBudget)) limited(res,webhookBudget);}
      else if(target&&['session','boxes','messages','blobs','blob'].includes(target.kind)) {
        const resolved=await principal(req,res,client,target.kind==='session'||target.kind==='boxes');
        who=resolved.who;
        if(who.kind==='box') {if(!take(`box:${who.boxId}`,boxBudget)) limited(res,boxBudget);}
        else if(who.kind==='session') {if(!take(`account:${who.session.accountId}`,budget)) limited(res,budget);}
        else if(!resolved.charged&&!take(`anon:${client}`,budget)) limited(res,budget);
      }
      else if(!take(`anon:${client}`,budget)) limited(res,budget);
      if(!target) fail(404,'Not found.');
      const allowed=METHODS[target.kind];
      if(!allowed.includes(req.method??'')){res.setHeader('Allow',allowed.join(', '));fail(405,'Method is not allowed.');}
      if(target.kind==='health'){send(req,res,200,{ok:true});return;}
      if(target.kind==='webhook') {
        const body=await rawBody(req,Math.min(max,256*1024));
        // Validate JSON media/body while passing untouched bytes to the signature verifier.
        jsonRecord(body);
        const signature=req.headers['stripe-signature'];
        if(typeof signature!=='string') fail(400);
        let result:unknown;
        try{result=await opts.billing.handle(body,signature);}
        catch(error){
          // 503: Stripe could not confirm a payment yet; Stripe retries non-2xx deliveries.
          if((error as {status?:unknown}|null)?.status===503) fail(503,'Billing is temporarily unavailable.');
          fail(400,'Webhook could not be verified.');
        }
        send(req,res,200,result);return;
      }
      if(target.kind==='auth') {
        browserOrigin(req);
        const raw=target.path;
        const body=jsonRecord(await rawBody(req,Math.min(max,64*1024)));
        if(raw==='/auth/register/challenge'){exact(body,[]);send(req,res,200,await accounts().registrationChallenge(client));return;}
        if(raw==='/auth/login/challenge'){exact(body,['accountId']);const id=identifier(body.accountId);let challenge:unknown;try{challenge=await accounts().assertionChallenge(id,client);}catch{fail(403,'Sign in could not be verified.');}send(req,res,200,challenge);return;}
        let result:Authentication;
        if(raw==='/auth/register/finish') {
          exact(body,['challengeId','clientDataJSON','attestationObject']);
          const input={challengeId:identifier(body.challengeId),clientDataJSON:bytes(body.clientDataJSON,16*1024),attestationObject:bytes(body.attestationObject,32*1024)};
          try{result=await accounts().register(input);}catch{fail(403,'Registration could not be verified.');}
        } else {
          exact(body,['accountId','challengeId','credentialId','clientDataJSON','authenticatorData','signature']);
          if(typeof body.credentialId!=='string'||body.credentialId.length>1400) fail(400);
          const input={accountId:identifier(body.accountId),challengeId:identifier(body.challengeId),credentialId:body.credentialId,clientDataJSON:bytes(body.clientDataJSON,16*1024),authenticatorData:bytes(body.authenticatorData,16*1024),signature:bytes(body.signature,1024)};
          try{result=await accounts().signIn(input);}catch{fail(403,'Sign in could not be verified.');}
        }
        res.setHeader('Set-Cookie',result.cookie);
        send(req,res,200,{account:result.account,csrf:result.session.csrf});return;
      }
      if(target.kind==='session') {
        const active=signedIn(who);
        if(req.method==='DELETE') {
          csrf(req,active);await accounts().clearSession(req.headers.cookie);
          res.setHeader('Set-Cookie',accounts().clearCookie??`ks_control_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${origin.protocol==='https:'?'; Secure':''}`);
          send(req,res,200,{ok:true});return;
        }
        send(req,res,200,{accountId:active.accountId,csrf:active.csrf});return;
      }
      if(target.kind==='boxes') {
        const active=signedIn(who);csrf(req,active);
        const service=accounts();
        if(!opts.provisioner||!service.reserveBox||!service.confirmBox||!service.releaseBox) fail(503,'Provisioning is unavailable.');
        const body=jsonRecord(await rawBody(req,Math.min(max,4096)));exact(body,['name','deviceKey']);
        if(!isBoxName(body.name)) fail(400,'Box names use lowercase letters, digits and hyphens, and start with a letter.');
        if(!isDeviceKey(body.deviceKey)) fail(400,'The enrollment device key is invalid.');
        const name=body.name, deviceKey=body.deviceKey;
        // H1: plan, quota and a pending name reservation come before Compute; a failed provision releases it.
        try{await service.reserveBox(active.accountId,name);}
        catch(error){
          const status=(error as {status?:unknown}|null)?.status;
          if(status===402) fail(402,'A paid plan is required to create a box.');
          if(status===403) fail(403,'This account has reached its box limit.');
          if(status===409) fail(409,'That box name is taken.');
          throw error;
        }
        let operation:unknown;
        try{operation=await opts.provisioner.provision({name,deviceKey});}
        catch{await service.releaseBox(active.accountId,name).catch(()=>undefined);fail(502,'Box provisioning failed.');}
        await service.confirmBox(active.accountId,name);
        send(req,res,201,{boxId:name,operation});return;
      }
      const boxId=target.boxId;
      if(who.kind==='box') {if(who.boxId!==boxId) fail(403,'Box access is not allowed.');}
      else if(who.kind==='session') {
        if(!await accounts().ownsBox(who.session.accountId,boxId)) fail(403,'Box access is not allowed.');
        if(req.method!=='GET') csrf(req,who.session);
      }
      else fail(401,'Sign in to continue.');
      if(target.kind==='messages') {
        if(req.method==='GET'){send(req,res,200,{messages:await opts.relay.poll(boxId,target.sessionId)});return;}
        send(req,res,201,await opts.relay.publish(boxId,jsonRecord(await rawBody(req,max))));return;
      }
      if(target.kind==='blobs') {
        const body=jsonRecord(await rawBody(req,max));exact(body,['kind','ciphertext'],['ttlMs']);
        if((body.kind!=='sealed-bundle'&&body.kind!=='sealed-state')||typeof body.ciphertext!=='string'||(body.ttlMs!==undefined&&typeof body.ttlMs!=='number')) fail(400);
        send(req,res,201,await opts.relay.putBlob(boxId,{kind:body.kind,ciphertext:body.ciphertext,ttlMs:body.ttlMs as number|undefined}));return;
      }
      const stored=await opts.relay.getBlob(boxId,target.blobId);
      if(stored===null) fail(404,'Not found.');
      send(req,res,200,stored);
    }catch(error) {
      if(res.headersSent){res.end();return;}
      if(error instanceof HttpError){send(req,res,error.status,{error:error.message});return;}
      const status=(error as {status?:unknown}|null)?.status;
      if(typeof status==='number'&&RELAYED[status]){send(req,res,status,{error:RELAYED[status]});return;}
      send(req,res,500,{error:'Request could not be completed.'});
    }
  }
  let sweeping=false;
  const cleanup=setInterval(()=>{
    if(sweeping) return;
    sweeping=true;
    void (opts.relay.sweep?.()??Promise.resolve()).catch(()=>log('cleanup',500)).finally(()=>{sweeping=false;});
  },60_000);
  cleanup.unref();
  return {
    async listen():Promise<{port:number;origin:string}> {
      await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(port,host,()=>{server.removeListener('error',reject);resolve();});});
      const address=server.address();
      if(!address||typeof address==='string') throw new Error('Control plane could not start.');
      if(origin.port==='0') {origin=new URL(origin.origin);origin.port=String(address.port);}
      if(typeof opts.accounts==='function') {
        try {accountService=opts.accounts(origin.origin);}
        catch {
          await new Promise<void>(resolve=>server.close(()=>resolve()));
          throw new Error('Control plane accounts could not start.');
        }
      }
      return {port:address.port,origin:origin.origin};
    },
    async close():Promise<void> {
      clearInterval(cleanup);bearers.clear();bearerOf.clear();verified.clear();buckets.clear();
      if(!server.listening)return;
      await new Promise<void>((resolve,reject)=>{server.close(error=>error?reject(new Error('Control plane could not close.')):resolve());server.closeIdleConnections();});
    },
    /** A bearer for one box's relay routes (local emulator and tests). Replaces that box's previous bearer. */
    issueBoxToken(boxId:string):string {
      identifier(boxId);
      const token=randomBytes(32).toString('base64url');
      const previous=bearerOf.get(boxId);
      if(previous) bearers.delete(previous);
      const hash=sha256(token);
      bearers.set(hash,boxId);bearerOf.set(boxId,hash);
      return token;
    },
    revokeBoxToken(boxId:string):void {const previous=bearerOf.get(boxId);if(previous)bearers.delete(previous);bearerOf.delete(boxId);},
  };
}
