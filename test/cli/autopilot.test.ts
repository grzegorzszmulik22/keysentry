import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { createStateCipher, createStateStore, buildInventory } from '../../src/core/index.js';
import { generateDeviceKey, verifyDetached, canonicalJson } from '../../src/security/index.js';
import { verifyArmedPlan } from '../../src/autopilot/index.js';
import { DISARM_PREFIX } from '../../src/approvals/index.js';
import { createAutopilotManager, recordDrill } from '../../src/cli/autopilot.js';
import { svc } from '../helpers/fakes.js';
import type { Inventory, RotationReport } from '../../src/types.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
const at = new Date('2026-10-27T12:00:00Z');
async function fixture() {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-arm-')); dirs.push(cwd);
  const store = createStateStore({ cwd, cipher: createStateCipher(Buffer.alloc(32, 4)) });
  const key = generateDeviceKey();
  let inv = buildInventory([{ host: 'railway', services: [{ service: svc('railway', 'api'), vars: [
    { name: 'OPENROUTER_API_KEY', value: 'sk-or-v1-old-secret-value-00000000000000', sealed: false },
    { name: 'STRIPE_SECRET_KEY', value: 'sk_live_old-secret-value-00000000000000', sealed: false },
  ] }] }], Buffer.alloc(32, 8), at);
  const events: {kind: string}[] = []; const rows: unknown[] = []; const questions: string[] = [];
  let mutations = 0; let rotations = 0;
  let result: RotationReport = { planId: 'p', dryRun: false, startedAt: at.toISOString(), finishedAt: at.toISOString(),
    status: 'complete', steps: [], deployments: [], diff: [] };
  const manager = createAutopilotManager({ store, projectId: 'project', deviceKey: async () => key,
    audit: { append: async e => { events.push(e); }, checkpoint: async () => {}, verify: async () => ({ok:true,entries:0,checkpoints:0}) },
    scan: async () => inv, rotateCluster: async () => { rotations++; return result; }, now: () => at,
    assertHuman: () => { mutations++; }, confirmAdoption: async q => { questions.push(q); return true; },
    emitEligibility: r => { rows.push(...r); },
  });
  return { cwd, store, key, manager, events, rows, questions, setInventory: (value: Inventory) => {inv=value;},
    get inventory() { return inv; }, get mutations() {return mutations;}, get rotations(){return rotations;},
    setReport: (value: RotationReport) => {result=value;} };
}

it('arm refuses without a recent drill and lists ineligible keys with reasons', async () => {
  const f=await fixture();
  await expect(f.manager.arm()).rejects.toThrow(/drill.*24 hours/i);
  expect(f.rows).toEqual(expect.arrayContaining([expect.objectContaining({eligible:false,reason:expect.stringContaining('Stripe')})]));
  expect(await f.manager.loadPlan()).toBeNull(); expect(f.rotations).toBe(0); expect(f.mutations).toBe(1);
});

it('a passing recent drill arms only eligible keys and persists a device-signed encrypted plan', async () => {
  const f=await fixture(); await recordDrill(f.store,{passed:true,at});
  const result=await f.manager.arm();
  expect(result.plan.clusters).toHaveLength(1); expect(result.refused).toHaveLength(1);
  expect(verifyArmedPlan(result.plan,{now:at,trustedKeyIds:[f.key.keyId]}).ok).toBe(true);
  expect((await readFile(join(f.store.paths.dir,'armed-plan.json'),'utf8')).startsWith('keysentry-encrypted:v1\n')).toBe(true);
  expect(await f.manager.loadState()).toMatchObject({disarmed:false,armedPlanId:result.plan.id});
  expect(f.events.some(e=>e.kind==='autopilot:arm')).toBe(true);
});

it.each([['expired',new Date(at.getTime()-86_400_001),true],['future',new Date(at.getTime()+1),true],['failed',at,false]] as const)
  ('a %s drill cannot authorize arming',async (_name,date,passed)=>{
    const f=await fixture(); await recordDrill(f.store,{passed,at:date});
    await expect(f.manager.arm()).rejects.toThrow(/drill.*24 hours/i);
  });

it('policy-widening arm refuses relay and remote forms before reading inventory',async()=>{
  const f=await fixture(); await recordDrill(f.store,{passed:true,at});
  await expect(f.manager.arm({relay:true})).rejects.toThrow(/local/i);
  await expect(f.manager.arm({remote:true})).rejects.toThrow(/local/i);
  expect(f.rows).toHaveLength(0); expect(await f.manager.loadPlan()).toBeNull();
});

it('rearming replaces and audits the armed plan',async()=>{
  const f=await fixture(); await recordDrill(f.store,{passed:true,at});
  const a=await f.manager.arm(); const b=await f.manager.arm({graceMinutes:2,maxServices:3});
  expect(a.plan.id).not.toBe(b.plan.id); expect(b.plan.graceSeconds).toBe(120); expect(b.plan.maxServicesPerWave).toBe(3);
  expect(f.events.some(e=>e.kind==='autopilot:rearm')).toBe(true);
});

it('disarming never needs a passkey and preserves active waves and old-key recovery metadata',async()=>{
  const f=await fixture(); await f.manager.saveState({armedPlanId:'arm',disarmed:false,waves:[{id:'wave',incidentId:'i',planId:'p',startedAt:at.toISOString(),status:'grace',deadline:new Date(at.getTime()+900_000).toISOString()}]});
  const result=await f.manager.disarm();
  expect(result.disarmed).toBe(true); expect((await f.manager.loadState()).waves[0]?.status).toBe('grace');
  expect(f.rotations).toBe(0); expect(f.mutations).toBe(1);
});

it('relay disarm is signed with the local device key and local disarm survives delivery failure',async()=>{
  const f=await fixture(); let message: unknown;
  const manager=createAutopilotManager({store:f.store,projectId:'project',deviceKey:async()=>f.key,assertHuman:()=>{},scan:async()=>f.inventory,
    rotateCluster:async()=>{throw new Error('unexpected');}, audit:{append:async()=>{},checkpoint:async()=>{},verify:async()=>({ok:true,entries:0,checkpoints:0})},now:()=>at,
    relayDisarm:async signed=>{ message=signed; throw new Error('channel unavailable'); }});
  await expect(manager.disarm({relay:true})).rejects.toThrow(/relay/i);
  expect((await manager.loadState()).disarmed).toBe(true);
  const {sig,...body}=message as {sig:string;keyId:string;at:string};
  expect(verifyDetached(f.key.publicKeyDer,Buffer.from(DISARM_PREFIX+canonicalJson(body)),Buffer.from(sig,'base64'))).toBe(true);
});

it('adoption asks for a real rotation and records its new provider ref and fingerprint',async()=>{
  const f=await fixture(); await recordDrill(f.store,{passed:true,at});
  const inv=buildInventory([{host:'fly',services:[{service:svc('fly','api'),vars:[{name:'OPENROUTER_API_KEY',sealed:true}]}]}],Buffer.alloc(32,8),at);
  f.setInventory(inv); const id=inv.clusters[0]!.id;
  f.setReport({planId:'p',dryRun:false,startedAt:at.toISOString(),finishedAt:at.toISOString(),status:'complete',
    steps:[{clusterId:id,status:'deployed',newKeyRef:'replacement-ref',newFingerprint:'replacement-fingerprint',warnings:[]}],
    deployments:[{serviceKey:'fly:proj1/production/api',deploymentId:'d',state:'success'}],diff:[]});
  const result=await f.manager.arm();
  expect(f.questions).toEqual(['This will rotate OPENROUTER_API_KEY now so keysentry knows the new value. Rotate now? [y/N]']);
  expect(f.rotations).toBe(1); expect(result.plan.clusters[0]?.adopted).toEqual({keyRef:'replacement-ref',fingerprint:'replacement-fingerprint',at:at.toISOString()});
});

it('failed or grace-pending adoption cannot silently become armed',async()=>{
  const f=await fixture(); await recordDrill(f.store,{passed:true,at});
  const inv=buildInventory([{host:'fly',services:[{service:svc('fly','api'),vars:[{name:'OPENROUTER_API_KEY',sealed:true}]}]}],Buffer.alloc(32,8),at); f.setInventory(inv);
  f.setReport({planId:'p',dryRun:false,startedAt:at.toISOString(),finishedAt:at.toISOString(),status:'grace-pending',steps:[{clusterId:inv.clusters[0]!.id,status:'deployed',newKeyRef:'ref',newFingerprint:'fingerprint',warnings:[]}],deployments:[],diff:[]});
  await expect(f.manager.arm()).rejects.toThrow(/finish|complete/i); expect(await f.manager.loadPlan()).toBeNull();
});

it('status exposes deadlines and a pending-adoption refresh notice without values',async()=>{
  const f=await fixture(); await recordDrill(f.store,{passed:true,at}); const armed=await f.manager.arm();
  await f.manager.saveState({armedPlanId:armed.plan.id,disarmed:false,waves:[{id:'w',incidentId:'incident',planId:'p',startedAt:at.toISOString(),status:'grace',deadline:'2026-10-27T12:15:00Z'}],
    adoptionUpdatesPlanId:armed.plan.id,adoptionUpdates:{cluster:{fingerprint:'fp',keyRef:'key',at:at.toISOString()}}});
  const result=await f.manager.status();
  expect(result.nextSettleTime).toBe('2026-10-27T12:15:00Z'); expect(result.adoptionNotice).toBe('re-arm to refresh adopted keys');
  expect(result.waves[0]).toMatchObject({incident:'incident',status:'grace'});
});

it('refresh resigns known adopted replacements but refuses unfinished waves',async()=>{
  const f=await fixture(); await recordDrill(f.store,{passed:true,at});
  const inv=buildInventory([{host:'fly',services:[{service:svc('fly','api'),vars:[{name:'OPENROUTER_API_KEY',sealed:true}]}]}],Buffer.alloc(32,8),at);f.setInventory(inv);
  const id=inv.clusters[0]!.id; f.setReport({planId:'p',dryRun:false,startedAt:at.toISOString(),finishedAt:at.toISOString(),status:'complete',steps:[{clusterId:id,status:'deployed',newKeyRef:'old-ref',newFingerprint:'old-fp',warnings:[]}],deployments:[{serviceKey:'fly:proj1/production/api',deploymentId:'d',state:'success'}],diff:[]});
  const a=await f.manager.arm(); const state=await f.manager.loadState();
  state.adoptionUpdatesPlanId=a.plan.id; state.adoptionUpdates={[id]:{keyRef:'next-ref',fingerprint:'next-fp',at:at.toISOString()}};
  state.waves=[{id:'w',incidentId:'i',planId:'p',startedAt:at.toISOString(),status:'grace'}]; await f.manager.saveState(state);
  await expect(f.manager.arm({refresh:true})).rejects.toThrow(/finish/i);
  state.waves[0]!.status='done'; await f.manager.saveState(state);
  const refreshed=await f.manager.arm({refresh:true});
  expect(refreshed.plan.id).not.toBe(a.plan.id); expect(refreshed.plan.clusters[0]?.adopted?.keyRef).toBe('next-ref');
  expect(verifyArmedPlan(refreshed.plan,{now:at,trustedKeyIds:[f.key.keyId]}).ok).toBe(true);
  expect((await f.manager.loadState()).adoptionUpdates).toBeUndefined();
});

it('refreshing adopted metadata preserves a local disarm',async()=>{
  const f=await fixture(); await recordDrill(f.store,{passed:true,at});
  const inv=buildInventory([{host:'fly',services:[{service:svc('fly','api'),vars:[{name:'OPENROUTER_API_KEY',sealed:true}]}]}],Buffer.alloc(32,8),at);f.setInventory(inv);
  const id=inv.clusters[0]!.id; f.setReport({planId:'p',dryRun:false,startedAt:at.toISOString(),finishedAt:at.toISOString(),status:'complete',steps:[{clusterId:id,status:'deployed',newKeyRef:'old-ref',newFingerprint:'old-fp',warnings:[]}],deployments:[{serviceKey:'fly:proj1/production/api',deploymentId:'d',state:'success'}],diff:[]});
  await f.manager.arm(); await f.manager.disarm();
  await f.manager.applyAdoptionUpdates({[id]:{keyRef:'next-ref',fingerprint:'next-fp',at:at.toISOString()}});
  expect((await f.manager.loadState()).disarmed).toBe(true);
});

it('an explicit local arm --refresh may reactivate a disarmed plan after recovery finishes',async()=>{
  const f=await fixture();await recordDrill(f.store,{passed:true,at});
  const inv=buildInventory([{host:'fly',services:[{service:svc('fly','api'),vars:[{name:'OPENROUTER_API_KEY',sealed:true}]}]}],Buffer.alloc(32,8),at);f.setInventory(inv);
  const id=inv.clusters[0]!.id;f.setReport({planId:'p',dryRun:false,startedAt:at.toISOString(),finishedAt:at.toISOString(),status:'complete',steps:[{clusterId:id,status:'deployed',newKeyRef:'old-ref',newFingerprint:'old-fp',warnings:[]}],deployments:[{serviceKey:'fly:proj1/production/api',deploymentId:'d',state:'success'}],diff:[]});
  const armed=await f.manager.arm();await f.manager.disarm();
  const state=await f.manager.loadState();state.adoptionUpdatesPlanId=armed.plan.id;state.adoptionUpdates={[id]:{keyRef:'next-ref',fingerprint:'next-fp',at:at.toISOString()}};await f.manager.saveState(state);
  await f.manager.arm({refresh:true});expect((await f.manager.loadState()).disarmed).toBe(false);
});

it('rearming an unchanged adopted key reuses its signed reference without another rotation',async()=>{
  const f=await fixture(); await recordDrill(f.store,{passed:true,at});
  const inv=buildInventory([{host:'fly',services:[{service:svc('fly','api'),vars:[{name:'OPENROUTER_API_KEY',sealed:true}]}]}],Buffer.alloc(32,8),at);f.setInventory(inv);
  const id=inv.clusters[0]!.id; f.setReport({planId:'p',dryRun:false,startedAt:at.toISOString(),finishedAt:at.toISOString(),status:'complete',steps:[{clusterId:id,status:'deployed',newKeyRef:'old-ref',newFingerprint:'old-fp',warnings:[]}],deployments:[{serviceKey:'fly:proj1/production/api',deploymentId:'d',state:'success'}],diff:[]});
  await f.manager.arm(); const result=await f.manager.arm({maxServices:2});
  expect(f.rotations).toBe(1); expect(result.plan.clusters[0]?.adopted?.keyRef).toBe('old-ref');
});

it('invalid plan options are refused before offering any real adoption rotation',async()=>{
  const f=await fixture(); await recordDrill(f.store,{passed:true,at});
  const inv=buildInventory([{host:'fly',services:[{service:svc('fly','api'),vars:[{name:'OPENROUTER_API_KEY',sealed:true}]}]}],Buffer.alloc(32,8),at);f.setInventory(inv);
  await expect(f.manager.arm({validDays:366})).rejects.toThrow();
  expect(f.questions).toHaveLength(0); expect(f.rotations).toBe(0);
});

it('adopting an extra key retains earlier signed adoptions after the rescan',async()=>{
  const f=await fixture(); await recordDrill(f.store,{passed:true,at});
  const key = (id:string) => ({service:svc('fly',id),vars:[{name:'OPENROUTER_API_KEY',sealed:true}]});
  const initial=buildInventory([{host:'fly',services:[key('existing')]}],Buffer.alloc(32,8),at); f.setInventory(initial);
  const oldId=initial.clusters[0]!.id;
  const report=(id:string):RotationReport=>({planId:'p',dryRun:false,startedAt:at.toISOString(),finishedAt:at.toISOString(),status:'complete',steps:[{clusterId:id,status:'deployed',newKeyRef:'old-ref',newFingerprint:'old-fp',warnings:[]}],deployments:[{serviceKey:id===oldId?'fly:proj1/production/existing':'fly:proj1/production/new',deploymentId:'d',state:'success'}],diff:[]});
  f.setReport(report(oldId)); await f.manager.arm();
  const fresh=buildInventory([{host:'fly',services:[key('existing'),key('new')]}],Buffer.alloc(32,8),at); f.setInventory(fresh);
  const newId=fresh.clusters.find(c=>c.id!==oldId)!.id; f.setReport(report(newId));
  const result=await f.manager.arm({clusterIds:[newId,oldId]});
  expect(f.rotations).toBe(2); expect(result.plan.clusters).toHaveLength(2);
});

it('applying one completed adoption update retains other saved replacements in the signed refresh',async()=>{
  const f=await fixture(); await recordDrill(f.store,{passed:true,at});
  const inv=buildInventory([{host:'fly',services:[{service:svc('fly','one'),vars:[{name:'OPENROUTER_API_KEY',sealed:true}]}]}],Buffer.alloc(32,8),at); f.setInventory(inv);
  const id=inv.clusters[0]!.id; f.setReport({planId:'p',dryRun:false,startedAt:at.toISOString(),finishedAt:at.toISOString(),status:'complete',steps:[{clusterId:id,status:'deployed',newKeyRef:'old-ref',newFingerprint:'old-fp',warnings:[]}],deployments:[{serviceKey:'fly:proj1/production/one',deploymentId:'d',state:'success'}],diff:[]});
  const armed=await f.manager.arm();
  const state=await f.manager.loadState(); state.adoptionUpdatesPlanId=armed.plan.id;
  state.adoptionUpdates={[id]:{keyRef:'saved-ref',fingerprint:'saved-fp',at:at.toISOString()}};await f.manager.saveState(state);
  // A callback can return no new update while durable state still has a completed replacement.
  const refreshed=await f.manager.applyAdoptionUpdates({});
  expect(refreshed?.clusters[0]?.adopted?.keyRef).toBe('saved-ref');
});

it('unresolved manual adoption recovery blocks plan replacement even without an autopilot wave',async()=>{
  const f=await fixture();await recordDrill(f.store,{passed:true,at});const a=await f.manager.arm();
  const state=await f.manager.loadState();Object.assign(state,{manualAdoptionPending:{cluster:'manual-plan'}});await f.manager.saveState(state);
  await expect(f.manager.arm()).rejects.toThrow(/finish/i);
  await expect(f.manager.applyAdoptionUpdates({cluster:{keyRef:'ref',fingerprint:'fp',at:at.toISOString()}})).rejects.toThrow(/finish/i);
  expect((await f.manager.loadPlan())?.id).toBe(a.plan.id);
});
