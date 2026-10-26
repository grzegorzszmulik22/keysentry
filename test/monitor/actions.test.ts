import { describe, expect, it } from 'vitest';
import { buildInventory } from '../../src/core/inventory.js';
import { executeDecisions, approve, type RotateExecutor } from '../../src/monitor/actions.js';
import { defaultPolicy, decide } from '../../src/monitor/policy.js';
import { createMonitorState, createMemoryMonitorStateStore } from '../../src/monitor/state.js';
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
  const options:Parameters<RotateExecutor>[1][]=[];
  const notifications:string[]=[];
  return {inventory,hosts:[host],providers:[provider],providerCtx:{http:new FakeHttp(),credentials:{},log:silentLogger},
    state:createMonitorState(),fingerprintKey,log:silentLogger,clock,policy:defaultPolicy(),
    notifier:{async notify(title:string,body:string){notifications.push(`${title}\n${body}`);}},
    async rotate(plan:RotationPlan, opts:Parameters<RotateExecutor>[1]):Promise<RotationReport> { plans.push(plan);options.push(opts);return {planId:plan.id,dryRun:false,startedAt:clock().toISOString(),finishedAt:clock().toISOString(),steps:plan.steps.map(step=>({clusterId:step.clusterId,status:'revoked',warnings:[]})),deployments:[],diff:[]}; },
    plans,options,notifications,host,provider,issued};
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
    ctx.policy.autoContain=true;
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
    ctx.policy.autoContain=true;
    const s=signal([ctx.inventory.clusters[0]!.id],'usage_anomaly');
    await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    ctx.clock=()=>new Date('2026-01-01T13:01:00.000Z');
    expect(await detectRevoked(ctx)).toEqual([]);
  });

  it('preserves the previous verification result when containment fails',async()=>{
    const ctx=await setup();await detectRevoked(ctx);
    ctx.policy.autoContain=true;
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

  it('keeps containment pending by default, then executes explicit approval once',async()=>{
    const ctx=await setup();const s=signal([ctx.inventory.clusters[0]!.id],'usage_anomaly');
    await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    expect(ctx.provider.capped).toEqual([]);
    expect(ctx.state.pendingActions[0]).toMatchObject({action:'cap',status:'pending'});
    expect(ctx.notifications.join('')).toContain('action pending');
    const id=ctx.state.pendingActions[0]!.id;
    await approve(id,ctx);
    expect(ctx.provider.capped).toEqual([ctx.issued[0]!.ref]);
    expect(ctx.state.pendingActions[0]!.status).toBe('executed');
    expect(ctx.state.autoContainments).toEqual({});
    await expect(approve(id,ctx)).rejects.toThrow();
  });

  it('reserves containment cooldown and its separate daily cap before provider writes',async()=>{
    const ctx=await setup(11);ctx.policy.autoContain=true;
    ctx.provider.cap=async ref=>{
      expect(ctx.state.autoContainments['2026-01-01']).toBe(ctx.provider.capped.length+1);
      ctx.provider.capped.push(ref);
    };
    const decisions=ctx.inventory.clusters.map(cluster=>decide(signal([cluster.id],'usage_anomaly'),ctx.inventory,ctx.policy,ctx.state)).flat();
    await executeDecisions(decisions,ctx);
    expect(ctx.provider.capped).toHaveLength(10);
    expect(ctx.state.autoContainments['2026-01-01']).toBe(10);
    expect(ctx.state.autoRotations).toEqual({});
    expect(ctx.state.pendingActions.some(action=>action.action==='cap' && action.status==='pending')).toBe(true);
    await executeDecisions(decide(signal([ctx.inventory.clusters[0]!.id],'usage_anomaly'),ctx.inventory,ctx.policy,ctx.state),ctx);
    expect(ctx.provider.capped).toHaveLength(10);
  });

  it('rechecks containment opt-in and stops if its reservation cannot persist',async()=>{
    const ctx=await setup();ctx.policy.autoContain=true;
    const s=signal([ctx.inventory.clusters[0]!.id],'usage_anomaly');
    const decisions=decide(s,ctx.inventory,ctx.policy,ctx.state);
    ctx.policy.autoContain=false;
    await executeDecisions(decisions,ctx);
    expect(ctx.provider.capped).toEqual([]);
    ctx.policy.autoContain=true;
    await expect(executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),{...ctx,saveState:async()=>{throw new Error('Storage unavailable.');}})).rejects.toThrow('Unable to save monitor actions.');
    expect(ctx.provider.capped).toEqual([]);
  });

  it('shares containment cooldowns across clusters that resolve to the same provider key',async()=>{
    const ctx=await setup();ctx.policy.autoContain=true;
    const original=ctx.inventory.clusters[0]!;
    ctx.inventory.clusters.push({...original,id:'sealed:second-consumer',fingerprint:null});
    const s=signal([original.id,'sealed:second-consumer'],'usage_anomaly');
    await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    expect(ctx.provider.capped).toEqual([ctx.issued[0]!.ref]);
    expect(ctx.state.autoContainments['2026-01-01']).toBe(1);
    expect(ctx.state.pendingActions.some(action=>action.status==='pending' && action.clusterIds.includes('sealed:second-consumer'))).toBe(true);
  });

  it('prevents simultaneous automatic containment of the same key',async()=>{
    const ctx=await setup();ctx.policy.autoContain=true;
    const s=signal([ctx.inventory.clusters[0]!.id],'usage_anomaly');
    const decisions=decide(s,ctx.inventory,ctx.policy,ctx.state);
    await Promise.all([executeDecisions(decisions,ctx),executeDecisions(decisions,ctx)]);
    expect(ctx.provider.capped).toEqual([ctx.issued[0]!.ref]);
    expect(ctx.state.autoContainments['2026-01-01']).toBe(1);
  });

  it.each(['cap','rotate'] as const)('rechecks failed-host exclusions before a stale automatic %s decision',async action=>{
    const ctx=await setup();ctx.policy.autoExecute=ctx.policy.autoContain=true;
    ctx.policy.rules.leak_detected.action=action;
    const s=signal([ctx.inventory.clusters[0]!.id]);
    const decisions=decide(s,ctx.inventory,ctx.policy,ctx.state);
    ctx.inventory.errors.push({host:'railway',message:'Scan unavailable.'});
    await executeDecisions(decisions,ctx);
    expect(ctx.provider.capped).toEqual([]);expect(ctx.plans).toEqual([]);
    expect(ctx.notifications.join('')).toContain('failed to scan');
  });

  it.each([
    ['canary_triggered','high',true],['leak_detected','high',true],['revoked_upstream','high',true],
    ['canary_triggered','medium',false],['usage_anomaly','high',false],['host_breach_advisory','high',false],
  ] as const)('passes safe executor options for %s/%s',async(kind,confidence,revokeUnconfirmed)=>{
    const ctx=await setup();ctx.policy.autoExecute=true;
    ctx.policy.rules[kind].action='rotate';ctx.policy.rules[kind].scope='cluster';
    const s={...signal([ctx.inventory.clusters[0]!.id],kind),confidence};
    await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    expect(ctx.options).toEqual([{revokeUnconfirmed,allowGenerate:false}]);
  });

  it('retains high-confidence provenance through durable approval and honors the current revocation policy',async()=>{
    const ctx=await setup();const s=signal([ctx.inventory.clusters[0]!.id]);
    await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    ctx.state=await createMemoryMonitorStateStore(ctx.state).load();
    await approve(ctx.state.pendingActions[0]!.id,ctx);
    expect(ctx.options).toEqual([{revokeUnconfirmed:true,allowGenerate:false}]);
    const next=await setup();next.policy.autoExecute=true;next.policy.revokeUnconfirmedOnHighConfidence=false;
    await executeDecisions(decide(signal([next.inventory.clusters[0]!.id]),next.inventory,next.policy,next.state),next);
    expect(next.options).toEqual([{revokeUnconfirmed:false,allowGenerate:false}]);
  });

  it('alerts without rotating generated secrets in a mixed canary scope',async()=>{
    const ctx=await setup(2);ctx.policy.autoExecute=true;
    ctx.inventory.clusters[0]!.method='generate';
    const s=signal([ctx.inventory.clusters[0]!.id],'canary_triggered');
    await executeDecisions(decide(s,ctx.inventory,ctx.policy,ctx.state),ctx);
    expect(ctx.plans).toHaveLength(1);
    expect(ctx.plans[0]!.steps.map(step=>step.clusterId)).toEqual([ctx.inventory.clusters[1]!.id]);
    expect(ctx.notifications.join('')).toContain('generat');
  });
});
