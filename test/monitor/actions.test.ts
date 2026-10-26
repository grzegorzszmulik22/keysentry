import { describe, expect, it } from 'vitest';
import { buildInventory } from '../../src/core/inventory.js';
import { executeDecisions, approve } from '../../src/monitor/actions.js';
import { defaultPolicy, decide } from '../../src/monitor/policy.js';
import { createMonitorState } from '../../src/monitor/state.js';
import { detectRevoked } from '../../src/monitor/detectors/revoked.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import type { RotationPlan, RotationReport, Signal } from '../../src/types.js';

const clock = () => new Date('2026-01-01T12:00:00.000Z');
async function setup(count = 1) {
  const host = new FakeHost('railway');
  const provider = new FakeProvider('openrouter','auto','sk-or-v1-0123456789abcdef0123456789abcdef-');
  const issued = Array.from({length:count},()=>provider.issue());
  const service = host.addService('api',Object.fromEntries(issued.map((key,i)=>[`OPENROUTER_API_KEY_${i}`,key.value])));
  const fingerprintKey = Buffer.alloc(32,3);
  const inventory = buildInventory([{host:host.id,services:[{service,vars:await host.readVariables(service)}]}],fingerprintKey);
  const plans:RotationPlan[]=[];
  const notifications:string[]=[];
  return {inventory,hosts:[host],providers:[provider],providerCtx:{http:new FakeHttp(),credentials:{},log:silentLogger},
    state:createMonitorState(),fingerprintKey,log:silentLogger,clock,policy:defaultPolicy(),
    notifier:{async notify(title:string,body:string){notifications.push(`${title}\n${body}`);}},
    async rotate(plan:RotationPlan):Promise<RotationReport> { plans.push(plan);return {planId:plan.id,dryRun:false,startedAt:clock().toISOString(),finishedAt:clock().toISOString(),steps:plan.steps.map(step=>({clusterId:step.clusterId,status:'revoked',warnings:[]})),deployments:[],diff:[]}; },
    plans,notifications,host,provider,issued};
}
function signal(clusterIds:string[],kind:Signal['kind']='leak_detected'):Signal {
  return {id:`signal-${clusterIds.join('-')}`,kind,at:clock().toISOString(),confidence:'high',clusterIds,summary:'Detected suspicious activity.',evidence:{}};
}

describe('monitor actions',()=>{
  it('requires approval by default and executes the pending plan once',async()=>{
    const ctx=await setup(); const s=signal([ctx.inventory.clusters[0]!.id]);
    await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    expect(ctx.plans).toHaveLength(0);expect(ctx.state.pendingActions[0]!.status).toBe('pending');
    expect(ctx.notifications).toHaveLength(1);
    const id=ctx.state.pendingActions[0]!.id;
    await approve(id,ctx);
    expect(ctx.plans).toHaveLength(1); expect(ctx.state.pendingActions[0]!.status).toBe('executed');
    await expect(approve(id,ctx)).rejects.toThrow();expect(ctx.plans).toHaveLength(1);
  });

  it('resolves containment to the provider key reference',async()=>{
    const ctx=await setup();const s=signal([ctx.inventory.clusters[0]!.id],'usage_anomaly');
    await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    expect(ctx.provider.capped).toEqual([ctx.issued[0]!.ref]);expect(ctx.plans).toHaveLength(0);
    expect(JSON.stringify(ctx.state)).not.toContain(ctx.issued[0]!.value);
  });

  it('enforces cooldown and the daily cap across executions',async()=>{
    const ctx=await setup(11);ctx.policy.autoExecute=true;
    for(const cluster of ctx.inventory.clusters){
      const s=signal([cluster.id]);await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    }
    expect(ctx.plans).toHaveLength(10);expect(ctx.state.autoRotations['2026-01-01']).toBe(10);
    expect(ctx.state.pendingActions.filter(action=>action.status==='pending')).toHaveLength(1);
    const s=signal([ctx.inventory.clusters[0]!.id]);
    await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    expect(ctx.plans).toHaveLength(10);
  });

  it('rechecks policy rather than trusting an automatic decision',async()=>{
    const ctx=await setup();ctx.policy.autoExecute=true;
    const s=signal([ctx.inventory.clusters[0]!.id]);const decisions=decide(s,ctx.inventory,ctx.policy,ctx.state);
    ctx.policy.autoExecute=false;
    await executeDecisions(decisions,ctx);
    expect(ctx.plans).toHaveLength(0);expect(ctx.state.pendingActions[0]!.status).toBe('pending');
  });

  it('reserves limits before calling an executor and keeps them on failure',async()=>{
    const ctx=await setup();ctx.policy.autoExecute=true;
    ctx.rotate=async()=>{expect(ctx.state.autoRotations['2026-01-01']).toBe(1);throw new Error(ctx.issued[0]!.value);};
    const s=signal([ctx.inventory.clusters[0]!.id]);
    await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    expect(ctx.state.autoRotations['2026-01-01']).toBe(1);
    expect(JSON.stringify(ctx.state)).not.toContain(ctx.issued[0]!.value);
    expect(ctx.notifications.join('')).not.toContain(ctx.issued[0]!.value);
  });

  it('does not mistake its own containment for upstream revocation',async()=>{
    const ctx=await setup();await detectRevoked(ctx);
    const s=signal([ctx.inventory.clusters[0]!.id],'usage_anomaly');
    await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    ctx.clock=()=>new Date('2026-01-01T13:01:00.000Z');
    expect(await detectRevoked(ctx)).toEqual([]);
  });

  it('preserves the previous verification result when containment fails',async()=>{
    const ctx=await setup();await detectRevoked(ctx);
    const id=ctx.inventory.clusters[0]!.id;
    const previous={...ctx.state.lastVerify[id]!};
    ctx.provider.cap=async()=>{throw new Error(ctx.issued[0]!.value);};
    const s=signal([id],'usage_anomaly');
    await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    expect(ctx.state.lastVerify[id]).toEqual(previous);
  });

  it('does not call the executor if a reservation cannot be saved',async()=>{
    const ctx=await setup();ctx.policy.autoExecute=true;
    const s=signal([ctx.inventory.clusters[0]!.id]);
    await expect(executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),{
      ...ctx,saveState:async()=>{throw new Error(ctx.issued[0]!.value);},
    })).rejects.toThrow('Unable to save monitor actions.');
    expect(ctx.plans).toHaveLength(0);
  });

  it('prevents simultaneous decisions from rotating a cluster twice',async()=>{
    const ctx=await setup();ctx.policy.autoExecute=true;
    const s=signal([ctx.inventory.clusters[0]!.id]);const decisions=decide(s,ctx.inventory,ctx.policy,ctx.state);
    await Promise.all([executeDecisions(decisions,ctx),executeDecisions(decisions,ctx)]);
    expect(ctx.plans).toHaveLength(1);expect(ctx.state.autoRotations['2026-01-01']).toBe(1);
  });

  it.each(['skipped','missing'])('keeps %s work pending for human remediation',async mode=>{
    const ctx=await setup();ctx.policy.autoExecute=true;
    ctx.rotate=async plan=>({planId:plan.id,dryRun:false,startedAt:clock().toISOString(),finishedAt:clock().toISOString(),
      steps:mode==='missing' ? []:plan.steps.map(step=>({clusterId:step.clusterId,status:'skipped',warnings:[]})),deployments:[],diff:[]});
    const s=signal([ctx.inventory.clusters[0]!.id]);
    await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    expect(ctx.state.pendingActions[0]!.status).toBe('pending');
  });

  it('keeps a rotated sealed key mapping under its stable cluster id',async()=>{
    const ctx=await setup();ctx.policy.autoExecute=true;
    const cluster=ctx.inventory.clusters[0]!;
    cluster.id='sealed:railway:project/production/api:OPENROUTER_API_KEY';cluster.fingerprint=null;
    ctx.state.keyRefs[cluster.id]=ctx.issued[0]!.ref;
    ctx.rotate=async plan=>({planId:plan.id,dryRun:false,startedAt:clock().toISOString(),finishedAt:clock().toISOString(),
      steps:plan.steps.map(step=>({clusterId:step.clusterId,status:'revoked',newFingerprint:'a'.repeat(32),newKeyRef:'key_new',warnings:[]})),deployments:[],diff:[]});
    const s=signal([cluster.id]);
    await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    expect(ctx.state.keyRefs[cluster.id]).toBe('key_new');
  });
});
