import { expect, it } from 'vitest';
import { buildArmedPlan, signArmedPlan, type AutopilotState } from '../../src/autopilot/index.js';
import { buildInventory } from '../../src/core/index.js';
import { generateDeviceKey } from '../../src/security/index.js';
import { persistManualAdoption, reconcileAutopilotRecovery } from '../../src/cli/adoption-recovery.js';
import { svc } from '../helpers/fakes.js';
import type { RotationReport } from '../../src/types.js';

const at=new Date('2026-10-27T12:00:00Z');
function fixture(){
  const key=generateDeviceKey();
  const inventory=buildInventory([{host:'fly',services:[{service:svc('fly','api'),vars:[{name:'OPENROUTER_API_KEY',sealed:true}]}]}],Buffer.alloc(32,8),at);
  const cluster=inventory.clusters[0]!;
  Object.assign(cluster,{adopted:{keyRef:'old-ref',fingerprint:'old-fingerprint',at:at.toISOString()}});
  const armed=signArmedPlan(buildArmedPlan({projectId:'project',inventory,clusterIds:[cluster.id],hosts:['fly'],options:{},now:at}).plan,key);
  const state:AutopilotState={armedPlanId:armed.id,disarmed:false,waves:[]};
  const report:RotationReport={planId:'rotation',dryRun:false,startedAt:at.toISOString(),finishedAt:at.toISOString(),status:'complete',steps:[{clusterId:cluster.id,status:'deployed',newKeyRef:'new-ref',newFingerprint:'new-fingerprint',warnings:[]}],deployments:[{serviceKey:'fly:proj1/production/api',deploymentId:'deploy',state:'success'}],diff:[]};
  const saved:AutopilotState[]=[]; const updates:unknown[]=[];
  const input={report,armed,state,inventory,trustedKeyIds:[key.keyId],now:at,saveState:async(s:AutopilotState)=>{saved.push(structuredClone(s));},applyUpdates:async(u:unknown)=>{updates.push(u);}};
  return {key,inventory,cluster,armed,state,report,saved,updates,input};
}

it('manual completed adopted rotations persist refs then refresh through the local manager',async()=>{
  const f=fixture();
  expect(await persistManualAdoption(f.input)).toEqual({recorded:1,refreshed:true});
  expect(f.saved[0]?.adoptionUpdates?.[f.cluster.id]?.keyRef).toBe('new-ref');
  expect(f.updates).toEqual([{[f.cluster.id]:{keyRef:'new-ref',fingerprint:'new-fingerprint',at:at.toISOString()}}]);
});
it('pending grace and partial delivery save observations without resigning',async()=>{
  const f=fixture(); f.report.status='grace-pending'; f.report.pendingRevocations=[{clusterId:f.cluster.id,deadline:'2026-10-27T12:15:00Z',undoAvailable:false}];
  expect(await persistManualAdoption(f.input)).toEqual({recorded:1,refreshed:false});expect(f.updates).toHaveLength(0);
  f.report.status='partial';f.report.steps[0]!.status='failed';
  expect(await persistManualAdoption(f.input)).toEqual({recorded:1,refreshed:false});expect(f.updates).toHaveLength(0);
});
it('completed finish reconciles a matching wave before refreshing adopted keys',async()=>{
  const f=fixture();f.state.waves=[{id:'wave',incidentId:'i',planId:f.report.planId,startedAt:at.toISOString(),status:'grace'}];
  expect(await persistManualAdoption(f.input)).toEqual({recorded:1,refreshed:false});
  expect(reconcileAutopilotRecovery(f.state,{planId:f.report.planId,report:f.report})).toBe(true);
  expect(f.state.waves[0]?.status).toBe('done');
  expect(await persistManualAdoption(f.input)).toEqual({recorded:1,refreshed:true});
});
it('another unfinished wave prevents automatic refresh and earlier saved updates are preserved',async()=>{
  const f=fixture();f.state.waves=[{id:'other',incidentId:'i',planId:'other',startedAt:at.toISOString(),status:'running'}];
  f.state.adoptionUpdatesPlanId=f.armed.id;f.state.adoptionUpdates={earlier:{keyRef:'earlier-ref',fingerprint:'earlier-fp',at:at.toISOString()}};
  expect(await persistManualAdoption(f.input)).toEqual({recorded:1,refreshed:false});
  expect(f.saved.at(-1)?.adoptionUpdates?.earlier?.keyRef).toBe('earlier-ref'); expect(f.updates).toHaveLength(0);
});
it('an unrelated unfinished manual adoption prevents an otherwise completed rotation refreshing the plan',async()=>{
  const f=fixture();Object.assign(f.state,{manualAdoptionPending:{earlier:'earlier-plan'}});
  expect(await persistManualAdoption(f.input)).toEqual({recorded:1,refreshed:false});expect(f.updates).toHaveLength(0);
});
it('completed manual finish clears only its own pending recovery marker',async()=>{
  const f=fixture();Object.assign(f.state,{manualAdoptionPending:{[f.cluster.id]:f.report.planId,other:'other-plan'}});
  expect(reconcileAutopilotRecovery(f.state,{planId:f.report.planId,report:f.report})).toBe(true);
  expect((f.state as typeof f.state & {manualAdoptionPending:Record<string,string>}).manualAdoptionPending).toEqual({other:'other-plan'});
});
it('dry runs and tampered armed plans cannot record adopted authorization metadata',async()=>{
  const f=fixture();f.report.dryRun=true;
  expect(await persistManualAdoption(f.input)).toEqual({recorded:0,refreshed:false});
  f.report.dryRun=false;f.armed.graceSeconds++;
  expect(await persistManualAdoption(f.input)).toEqual({recorded:0,refreshed:false});expect(f.saved).toHaveLength(0);
});
it('partial recovery cannot mark a wave completed',()=>{
  const f=fixture();f.state.waves=[{id:'wave',incidentId:'i',planId:f.report.planId,startedAt:at.toISOString(),status:'stopped'}];f.report.status='partial';
  expect(reconcileAutopilotRecovery(f.state,{planId:f.report.planId,report:f.report})).toBe(false);expect(f.state.waves[0]?.status).toBe('stopped');
});
it('full human undo clears replacement refs and marks the matching wave complete using the journal marker',()=>{
  const f=fixture();f.state.waves=[{id:'wave',incidentId:'i',planId:f.report.planId,startedAt:at.toISOString(),status:'grace'}];f.state.adoptionUpdatesPlanId=f.armed.id;f.state.adoptionUpdates={[f.cluster.id]:{keyRef:'new-ref',fingerprint:'new-fp',at:at.toISOString()}};
  const undo={restored:[{clusterId:f.cluster.id,services:['fly:proj1/production/api']}],unavailable:[],newKeysRevoked:['new-ref']};
  expect(reconcileAutopilotRecovery(f.state,{planId:f.report.planId,undo,entries:[]})).toBe(true);
  expect(f.state.waves[0]?.status).toBe('grace');expect(f.state.adoptionUpdates).toBeUndefined();
  expect(reconcileAutopilotRecovery(f.state,{planId:f.report.planId,undo,entries:[{at:at.toISOString(),planId:f.report.planId,event:'plan-end',data:{status:'complete',undone:true}}]})).toBe(true);
  expect(f.state.waves[0]?.status).toBe('done');
});
