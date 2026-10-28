import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { isIP } from 'node:net';

interface Session { accountId: string; id: string; csrf: string }
interface Authentication { account: unknown; session: Session; cookie: string }
export interface AccountsService {
  registrationChallenge(): unknown;
  register(input: {challengeId:string;clientDataJSON:Buffer;attestationObject:Buffer}): Promise<Authentication>;
  assertionChallenge(accountId: string): Promise<unknown>;
  signIn(input: {accountId:string;challengeId:string;credentialId:string;clientDataJSON:Buffer;authenticatorData:Buffer;signature:Buffer}): Promise<Authentication>;
  authenticate(cookie: string | undefined): Session | null;
  clearSession(cookie: string | undefined): void;
  addBox(accountId: string, boxId: string): Promise<void>;
  ownsBox(accountId: string, boxId: string): Promise<boolean>;
}
interface RelayService {
  publish(boxId:string,message:unknown):Promise<{id:string}>;
  poll(boxId:string,sessionId?:string):Promise<unknown[]>;
  putBlob(boxId:string,input:{kind:'sealed-bundle'|'sealed-state';ciphertext:string;ttlMs?:number}):Promise<{id:string;expiresAt:number}>;
  getBlob(boxId:string,id:string):Promise<unknown|null>;
  sweep?():Promise<void>;
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
  provisioner?: {provision(input:{name:string}):Promise<unknown>};
  rateLimitPerMinute?: number;
  maxBodyBytes?: number;
  now?: () => number;
  log?: (entry:{event:'request'|'cleanup';status:number}) => void;
}

class HttpError extends Error {
  constructor(readonly status:number, message:string) { super(message); }
}
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const ID = /^[A-Za-z0-9_-]{1,128}$/;
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
function rawBody(req:IncomingMessage,max:number):Promise<Buffer> {
  if (req.headers['content-encoding'] && req.headers['content-encoding'].toLowerCase() !== 'identity') fail(415,'Unsupported media type.');
  if ((req.headers['content-type'] ?? '').split(';',1)[0]!.trim().toLowerCase() !== 'application/json') fail(415,'Unsupported media type.');
  const length=req.headers['content-length'];
  if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > max)) {req.resume(); fail(413,'Request body is too large.');}
  return new Promise((resolve,reject) => {
    let total=0, settled=false;
    const chunks:Buffer[]=[];
    const stop = (error:HttpError) => {
      if (settled) return;
      settled=true; chunks.length=0; req.removeListener('data',data); req.resume(); reject(error);
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
  const budget=opts.rateLimitPerMinute ?? 120;
  const now=opts.now ?? Date.now;
  if ((host !== 'localhost' && !isIP(host)) || !Number.isInteger(port) || port<0 || port>65535 || !Number.isSafeInteger(max) || max<1 || max>4*1024*1024 || !Number.isSafeInteger(budget) || budget<1) throw new TypeError('Invalid control plane configuration.');
  const tokens=new Map<string,Buffer>();
  const buckets=new Map<string,{at:number;tokens:number}>();
  const headers:Record<string,string>={
    'Content-Security-Policy':CSP,'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
    'Cache-Control':'no-store','Permissions-Policy':'publickey-credentials-get=(self)',
    'Content-Type':'application/json; charset=utf-8',
  };
  if(origin.protocol==='https:') headers['Strict-Transport-Security']='max-age=31536000';
  function log(event:'request'|'cleanup',status:number) {try {opts.log?.({event,status});}catch{/* Logs cannot alter request outcomes. */}}
  function send(res:ServerResponse,status:number,value:unknown) {res.writeHead(status,headers);res.end(JSON.stringify(value));log('request',status);}
  function take(client:string):boolean {
    const current=now();
    let bucket=buckets.get(client);
    if(!bucket) {
      for(const [key,value] of buckets) if(current-value.at>=60_000) buckets.delete(key);
      if(buckets.size>=10_000) return false;
      bucket={at:current,tokens:budget};buckets.set(client,bucket);
    }
    bucket.tokens=Math.min(budget,bucket.tokens+Math.max(0,current-bucket.at)*budget/60_000);
    bucket.at=current;
    if(bucket.tokens<1) return false;
    bucket.tokens--;return true;
  }
  function session(req:IncomingMessage):Session {
    const active=accounts().authenticate(req.headers.cookie);
    if(!active) fail(401,'Sign in to continue.');
    return active;
  }
  function browserOrigin(req:IncomingMessage):void {
    if(req.headers.origin!==origin.origin) fail(403,'Request origin is not allowed.');
  }
  function csrf(req:IncomingMessage,active:Session):void {
    browserOrigin(req);
    const value=req.headers['x-csrf-token'];
    if(typeof value!=='string'||!same(value,active.csrf)) fail(403,'Request authorization is required.');
  }
  async function boxAccess(req:IncomingMessage,boxId:string):Promise<void> {
    const auth=req.headers.authorization;
    if(auth!==undefined) {
      if(!/^Bearer [A-Za-z0-9_-]{43}$/.test(auth)) fail(401,'Sign in to continue.');
      const hash=createHash('sha256').update(auth.slice(7)).digest();
      const expected=tokens.get(boxId);
      if(expected&&timingSafeEqual(hash,expected)) return;
      for(const other of tokens.values()) if(timingSafeEqual(hash,other)) fail(403,'Box access is not allowed.');
      fail(401,'Sign in to continue.');
    }
    const active=session(req);
    if(!await accounts().ownsBox(active.accountId,boxId)) fail(403,'Box access is not allowed.');
    if(req.method!=='GET') csrf(req,active);
  }
  const server=createServer({maxHeaderSize:16*1024},(req,res)=>{void handle(req,res);});
  server.requestTimeout=15_000;
  server.headersTimeout=10_000;
  server.keepAliveTimeout=5_000;
  async function handle(req:IncomingMessage,res:ServerResponse):Promise<void> {
    try {
      const hostCount=req.rawHeaders.filter((value,index)=>index%2===0&&value.toLowerCase()==='host').length;
      if(hostCount!==1||req.headers.host!==origin.host) fail(403,'Request origin is not allowed.');
      if(!take(req.socket.remoteAddress??'unknown')) {res.setHeader('Retry-After',String(Math.ceil(60/budget)));fail(429,'Please wait before trying again.');}
      const raw=req.url??'';
      const message=/^\/boxes\/([A-Za-z0-9_-]{1,128})\/messages(?:\?sessionId=([A-Za-z0-9_-]{1,128}))?$/.exec(raw);
      const blobs=/^\/boxes\/([A-Za-z0-9_-]{1,128})\/blobs$/.exec(raw);
      const blob=/^\/boxes\/([A-Za-z0-9_-]{1,128})\/blobs\/([A-Za-z0-9_-]{1,128})$/.exec(raw);
      const authRoute=['/auth/register/challenge','/auth/register/finish','/auth/login/challenge','/auth/login/finish'].includes(raw);
      const known=raw==='/healthz'||raw==='/session'||raw==='/billing/webhook'||raw==='/boxes'||authRoute||message||blobs||blob;
      if(!known) fail(404,'Not found.');
      const allowed=raw==='/healthz'||blob ? ['GET'] : raw==='/session' ? ['GET','DELETE'] : message ? ['GET','POST'] : ['POST'];
      if(!allowed.includes(req.method??'')){res.setHeader('Allow',allowed.join(', '));fail(405,'Method is not allowed.');}
      if(raw==='/healthz'){send(res,200,{ok:true});return;}
      if(raw==='/billing/webhook') {
        const body=await rawBody(req,Math.min(max,256*1024));
        // Validate JSON media/body while passing untouched bytes to the signature verifier.
        jsonRecord(body);
        const signature=req.headers['stripe-signature'];
        if(typeof signature!=='string') fail(400);
        try{send(res,200,await opts.billing.handle(body,signature));}catch{fail(400,'Webhook could not be verified.');}
        return;
      }
      if(authRoute) {
        browserOrigin(req);
        const body=jsonRecord(await rawBody(req,Math.min(max,64*1024)));
        if(raw==='/auth/register/challenge'){exact(body,[]);send(res,200,await accounts().registrationChallenge());return;}
        if(raw==='/auth/login/challenge'){exact(body,['accountId']);const id=identifier(body.accountId);try{send(res,200,await accounts().assertionChallenge(id));}catch{fail(403,'Sign in could not be verified.');}return;}
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
        send(res,200,{account:result.account,csrf:result.session.csrf});return;
      }
      if(raw==='/session') {
        const active=session(req);
        if(req.method==='DELETE') {
          csrf(req,active);accounts().clearSession(req.headers.cookie);
          res.setHeader('Set-Cookie',`ks_control_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${origin.protocol==='https:'?'; Secure':''}`);
          send(res,200,{ok:true});return;
        }
        send(res,200,{accountId:active.accountId,csrf:active.csrf});return;
      }
      if(raw==='/boxes') {
        const active=session(req);csrf(req,active);
        if(!opts.provisioner) fail(503,'Provisioning is unavailable.');
        const body=jsonRecord(await rawBody(req,Math.min(max,4096)));exact(body,['name']);
        const name=identifier(body.name);
        const operation=await opts.provisioner.provision({name});
        await accounts().addBox(active.accountId,name);
        send(res,201,{boxId:name,operation});return;
      }
      const boxId=(message??blobs??blob)![1]!;
      await boxAccess(req,boxId);
      if(message) {
        if(req.method==='GET'){send(res,200,{messages:await opts.relay.poll(boxId,message[2])});return;}
        send(res,201,await opts.relay.publish(boxId,jsonRecord(await rawBody(req,max))));return;
      }
      if(blobs) {
        const body=jsonRecord(await rawBody(req,max));exact(body,['kind','ciphertext'],['ttlMs']);
        if((body.kind!=='sealed-bundle'&&body.kind!=='sealed-state')||typeof body.ciphertext!=='string'||(body.ttlMs!==undefined&&typeof body.ttlMs!=='number')) fail(400);
        send(res,201,await opts.relay.putBlob(boxId,{kind:body.kind,ciphertext:body.ciphertext,ttlMs:body.ttlMs as number|undefined}));return;
      }
      const stored=await opts.relay.getBlob(boxId,blob![2]!);
      if(stored===null) fail(404,'Not found.');
      send(res,200,stored);
    }catch(error) {
      if(res.headersSent){res.end();return;}
      if(error instanceof HttpError){send(res,error.status,{error:error.message});return;}
      const status=(error as {status?:unknown}|null)?.status;
      if(typeof status==='number'&&[400,409,413,429].includes(status)){send(res,status,{error:'Invalid request.'});return;}
      send(res,500,{error:'Request could not be completed.'});
    }finally{if(!req.readableEnded)req.resume();}
  }
  const cleanup=setInterval(()=>{void opts.relay.sweep?.().catch(()=>log('cleanup',500));},60_000);
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
      clearInterval(cleanup);tokens.clear();buckets.clear();
      if(!server.listening)return;
      await new Promise<void>((resolve,reject)=>server.close(error=>error?reject(new Error('Control plane could not close.')):resolve()));
    },
    issueBoxToken(boxId:string):string {
      identifier(boxId);
      const token=randomBytes(32).toString('base64url');
      tokens.set(boxId,createHash('sha256').update(token).digest());
      return token;
    },
    revokeBoxToken(boxId:string):void {tokens.delete(boxId);},
  };
}
