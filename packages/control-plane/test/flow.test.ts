import { afterEach, describe, expect, it } from 'vitest';
import { verifyAttestation } from '../../../src/box/attestation/index.js';
import { boxKeyBindingNonce, createHandshake, generateBoxKeyPair, handshakeAttestationNonces } from '../../../src/box/handshake/index.js';
import { generateDeviceKey } from '../../../src/security/index.js';
import { createRelayStore } from '../src/relay.js';
import { createMemoryStorage } from '../src/storage.js';
import { startEmulator, type Emulator } from '../src/emulator/index.js';

const emulators:Emulator[]=[];
afterEach(async()=>{await Promise.all(emulators.splice(0).map(emulator=>emulator.close()));});
const now=new Date('2026-10-27T12:00:00.000Z');

async function setup(tamper=false) {
  const emulator=await startEmulator({now:()=>now.getTime()});emulators.push(emulator);
  const storage=createMemoryStorage();
  const relay=createRelayStore({storage,now:()=>now.getTime()});
  const boxKey=generateBoxKeyPair(),signingKey=generateDeviceKey(),deviceKey=generateDeviceKey();
  const signingRaw=signingKey.publicKeyDer.subarray(-32);
  const binding=boxKeyBindingNonce(boxKey.publicKeyRaw,signingRaw);
  const helloToken=emulator.mintToken({audience:'keysentry-box',nonces:[binding]});
  let box=createHandshake('box',{boxKey,signingKey,devicePublicKeyDer:deviceKey.publicKeyDer});
  let cli=createHandshake('cli',{deviceKey});
  const hello=box.next({now,attestationToken:helloToken});box=hello.handshake;
  await relay.publish('cloud-box',hello.message);
  const challenge=cli.next({now,message:(await relay.poll('cloud-box'))[0]});cli=challenge.handshake;
  await relay.publish('cloud-box',challenge.message);
  const attestedToken=emulator.mintToken({audience:'keysentry-box',nonces:[binding,(challenge.message as {challenge:string}).challenge],switches:tamper?{replay:true}:{}});
  const attest=box.next({now,message:(await relay.poll('cloud-box'))[1],attestationToken:attestedToken});box=attest.handshake;
  await relay.publish('cloud-box',attest.message);
  const policy={audience:'keysentry-box',projectIds:[emulator.policy.projectId],serviceAccounts:[emulator.policy.serviceAccount],allowedDigests:emulator.policy.allowedDigests,hardwareModels:['GCP_INTEL_TDX'] as ['GCP_INTEL_TDX'],maxTokenAgeSeconds:300,clockSkewSeconds:60};
  const verified=await verifyAttestation({token:attestedToken,jwks:async()=>emulator.jwks,policy,expectedNonces:handshakeAttestationNonces(attest.message as Parameters<typeof handshakeAttestationNonces>[0]),now});
  return {emulator,storage,relay,box,cli,attest,verified};
}

describe('local control plane with the real handshake',()=>{
  it('relays the five-message exchange and never stores the planted token',async()=>{
    const {storage,relay,box,cli,attest,verified}=await setup();
    expect(verified.ok).toBe(true);
    const planted='sk-or-v1-planted-plaintext-token-01234567890123456789';
    const plaintext=Buffer.from(JSON.stringify({providerToken:planted}));
    const bundle=cli.next({now,message:attest.message,verifiedAttestation:verified,plaintext});
    await relay.publish('cloud-box',bundle.message);
    const opened=box.next({now,message:(await relay.poll('cloud-box'))[3]});
    expect(opened.plaintext?.toString()).toBe(plaintext.toString());
    await relay.publish('cloud-box',opened.message);
    expect(bundle.handshake.next({now,message:(await relay.poll('cloud-box'))[4]}).handshake.state).toBe('complete');
    for(const key of await storage.list(''))expect(JSON.stringify(await storage.get(key))).not.toContain(planted);
    opened.plaintext?.fill(0);plaintext.fill(0);
  });
  it('a replayed provisional attestation cannot authorize a token bundle through the relay',async()=>{
    const {cli,attest,verified,relay}=await setup(true);
    expect(verified.ok).toBe(false);
    expect(()=>cli.next({now,message:attest.message,verifiedAttestation:verified,plaintext:Buffer.from('planted-token')})).toThrow();
    expect((await relay.poll('cloud-box')).some(message=>(message as {type:string}).type==='token-bundle')).toBe(false);
  });
});
