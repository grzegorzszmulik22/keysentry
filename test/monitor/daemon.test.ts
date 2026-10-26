import { describe, expect, it } from 'vitest';
import { buildInventory } from '../../src/core/inventory.js';
import { fingerprint } from '../../src/core/fingerprint.js';
import { serviceKey } from '../../src/core/service-key.js';
import { runMonitorOnce, runMonitor } from '../../src/monitor/daemon.js';
import { defaultPolicy } from '../../src/monitor/policy.js';
import { createMonitorState, createMemoryMonitorStateStore } from '../../src/monitor/state.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, silentLogger, text } from '../helpers/fake-http.js';
import type { RotationPlan } from '../../src/types.js';

describe('monitor daemon',()=>{
  it('turns a canary hit into a plan for exactly the implicated service clusters',async()=>{
    const host=new FakeHost('railway');const provider=new FakeProvider('openrouter','auto','sk-or-v1-0123456789abcdef0123456789abcdef-');
    const a=provider.issue(),b=provider.issue(),c=provider.issue(),decoy=provider.issue('decoy',0.01);
    const service=host.addService('api',{OPENROUTER_API_KEY:a.value,OPENROUTER_SECOND:b.value});
    const other=host.addService('worker',{OPENROUTER_API_KEY:c.value});
    const fingerprintKey=Buffer.alloc(32,5);
    const inventory=buildInventory([{host:host.id,services:await Promise.all([service,other].map(async service=>({service,vars:await host.readVariables(service)})))}],fingerprintKey);
    const state=createMonitorState();state.canaries.push({id:'canary',provider:'openrouter',keyRef:decoy.ref,service,varName:'OPENROUTER_API_KEY_FALLBACK',createdAt:'2026-01-01T00:00:00.000Z'});
    const store=createMemoryMonitorStateStore(state);provider.spend(decoy.ref,0.001);
    const plans:RotationPlan[]=[];const policy=defaultPolicy();policy.autoExecute=true;
    const ctx={inventory,hosts:[host],providers:[provider],providerCtx:{http:new FakeHttp(),credentials:{},log:silentLogger},policy,state:store,
      notifier:{async notify(){}},fingerprintKey,log:silentLogger,clock:()=>new Date('2026-01-01T12:00:00.000Z'),feeds:[],
      rotate:async(plan:RotationPlan)=>{plans.push(plan);return {planId:plan.id,dryRun:false,startedAt:'2026-01-01T12:00:00.000Z',finishedAt:'2026-01-01T12:00:00.000Z',steps:plan.steps.map(step=>({clusterId:step.clusterId,status:'revoked' as const,warnings:[]})),deployments:[],diff:[]};}};
    const result=await runMonitorOnce(ctx);
    expect(result.signals.some(s=>s.kind==='canary_triggered')).toBe(true);expect(plans).toHaveLength(1);
    const expected=inventory.clusters.filter(cluster=>cluster.consumers.some(c=>serviceKey(c.service)===serviceKey(service))).map(c=>c.id).sort();
    expect(plans[0]!.steps.map(step=>step.clusterId).sort()).toEqual(expected);
    expect((await store.load()).canaries[0]!.triggeredAt).toBeDefined();
    await runMonitorOnce(ctx);expect(plans).toHaveLength(1);
  });

  it('does not poll when already aborted',async()=>{
    const controller=new AbortController();controller.abort();
    await runMonitor({} as never,{intervalMs:10,signal:controller.signal});
  });

  it('uses configured feed age limits after a persisted baseline',async()=>{
    const host=new FakeHost('railway');
    const service=host.addService('api',{});
    const fingerprintKey=Buffer.alloc(32,5);
    const inventory=buildInventory([{host:host.id,services:[{service,vars:[]}]}],fingerprintKey);
    let xml='<rss><channel/></rss>';
    const http=new FakeHttp().on('GET',/^https:\/\/example.invalid\/feed$/,()=>text(200,xml));
    const store=createMemoryMonitorStateStore();
    const ctx={inventory,hosts:[],providers:[],providerCtx:{http,credentials:{},log:silentLogger},
      policy:defaultPolicy(),state:store,notifier:{async notify(){}},fingerprintKey,log:silentLogger,
      clock:()=>new Date('2026-10-26T12:00:00.000Z'),feeds:[{url:'https://example.invalid/feed',host:host.id}],
      breachFeedOptions:{maxAgeDays:10},rotate:async()=>{throw new Error('Not authorized.');}};
    expect((await runMonitorOnce(ctx)).signals).toEqual([]);
    xml='<rss><channel><item><title>Railway security incident</title><pubDate>2026-10-18T12:00:00.000Z</pubDate><link>https://example.invalid/incident</link></item></channel></rss>';
    expect((await runMonitorOnce(ctx)).signals).toHaveLength(1);
  });

  it('does not lose later canary hits when the first action save fails',async()=>{
    const host=new FakeHost('railway');const provider=new FakeProvider('openrouter','auto','sk-or-v1-aB3cD7eF9gH2iJ4kL6mN8pQ0');
    const a=provider.issue(),b=provider.issue(),decoyA=provider.issue('decoy-a',0.01),decoyB=provider.issue('decoy-b',0.01);
    const services=[host.addService('a',{OPENROUTER_API_KEY:a.value}),host.addService('b',{OPENROUTER_API_KEY:b.value})];
    const fingerprintKey=Buffer.alloc(32,5);
    const inventory=buildInventory([{host:host.id,services:await Promise.all(services.map(async service=>({service,vars:await host.readVariables(service)})))}],fingerprintKey);
    const initial=createMonitorState();
    initial.canaries=services.map((service,i)=>({id:`canary-${i}`,provider:'openrouter',keyRef:[decoyA,decoyB][i]!.ref,service,varName:'FALLBACK',createdAt:'2026-01-01T00:00:00.000Z'}));
    provider.spend(decoyA.ref,0.001);provider.spend(decoyB.ref,0.001);
    const inner=createMemoryMonitorStateStore(initial);let saves=0;
    const store={load:()=>inner.load(),async save(state:typeof initial){if(++saves===1)throw new Error('Temporary save failure.');await inner.save(state);}};
    const ctx={inventory,hosts:[host],providers:[provider],providerCtx:{http:new FakeHttp(),credentials:{},log:silentLogger},
      policy:defaultPolicy(),state:store,notifier:{async notify(){}},fingerprintKey,log:silentLogger,
      clock:()=>new Date('2026-01-01T12:00:00.000Z'),feeds:[],rotate:async()=>{throw new Error('Not authorized.');}};
    await runMonitorOnce(ctx);
    const saved=await store.load();
    expect(saved.pendingActions).toHaveLength(2);
    expect(saved.canaries[0]!.triggeredAt).toBeUndefined();
    expect(saved.canaries[1]!.triggeredAt).toBeDefined();
    await runMonitorOnce(ctx);
    expect((await store.load()).canaries.every(canary=>!!canary.triggeredAt)).toBe(true);
  });

  it('acknowledges multi-host feed items only after every host action is handled',async()=>{
    const railway=new FakeHost('railway'),vercel=new FakeHost('vercel');
    const provider=new FakeProvider('openrouter','auto','sk-or-v1-aB3cD7eF9gH2iJ4kL6mN8pQ0');
    railway.addService('a',{OPENROUTER_API_KEY:provider.issue().value});vercel.addService('b',{OPENROUTER_API_KEY:provider.issue().value});
    const hosts=[railway,vercel];const fingerprintKey=Buffer.alloc(32,6);
    const inventory=buildInventory(await Promise.all(hosts.map(async host=>({host:host.id,services:await Promise.all((await host.listServices()).map(async service=>({service,vars:await host.readVariables(service)})))}))),fingerprintKey);
    const inner=createMemoryMonitorStateStore();let saves=0;
    const store={load:()=>inner.load(),async save(state:Awaited<ReturnType<typeof inner.load>>){if(++saves===2)throw new Error('Temporary save failure.');await inner.save(state);}};
    let xml='<rss><channel/></rss>';
    const http=new FakeHttp().on('GET',/^https:\/\/example.invalid\/feed$/,()=>text(200,xml));
    const policy=defaultPolicy();policy.rules.host_breach_advisory.action='rotate';
    const ctx={inventory,hosts,providers:[provider],providerCtx:{http,credentials:{},log:silentLogger},policy,state:store,
      notifier:{async notify(){}},fingerprintKey,log:silentLogger,clock:()=>new Date('2026-01-01T12:00:00.000Z'),
      feeds:[{url:'https://example.invalid/feed'}],rotate:async()=>{throw new Error('Not authorized.');}};
    expect((await runMonitorOnce(ctx)).signals).toEqual([]);
    expect((await store.load()).feedBaselines).toBeDefined();
    expect(Object.keys((await store.load()).feedBaselines)).toHaveLength(1);
    xml='<rss><channel><item><title>Railway and Vercel security incident</title><link>https://example.invalid/incident</link></item></channel></rss>';
    await runMonitorOnce(ctx);
    expect((await store.load()).seenFeedItems).toEqual({});
    await runMonitorOnce(ctx);
    expect(Object.keys((await store.load()).seenFeedItems)).toHaveLength(1);
  });

  it.each(['railway','vercel'] as const)('keeps overlapping aggregated items retryable when the %s action save fails',async failedHost=>{
    const railway=new FakeHost('railway'),vercel=new FakeHost('vercel');
    const provider=new FakeProvider('openrouter','auto','sk-or-v1-aB3cD7eF9gH2iJ4kL6mN8pQ0');
    railway.addService('a',{OPENROUTER_API_KEY:provider.issue().value});vercel.addService('b',{OPENROUTER_API_KEY:provider.issue().value});
    const hosts=[railway,vercel];const fingerprintKey=Buffer.alloc(32,6);
    const inventory=buildInventory(await Promise.all(hosts.map(async host=>({host:host.id,services:await Promise.all((await host.listServices()).map(async service=>({service,vars:await host.readVariables(service)})))}))),fingerprintKey);
    const failingClusters=new Set(inventory.clusters.filter(cluster=>cluster.consumers.some(consumer=>consumer.service.host===failedHost)).map(cluster=>cluster.id));
    const inner=createMemoryMonitorStateStore();let failed=false;
    const store={load:()=>inner.load(),async save(state:Awaited<ReturnType<typeof inner.load>>){
      if(!failed && state.pendingActions.some(action=>action.clusterIds.some(id=>failingClusters.has(id)))) {
        failed=true;throw new Error('Temporary save failure.');
      }
      await inner.save(state);
    }};
    let xml='<rss><channel/></rss>';
    const http=new FakeHttp().on('GET',/^https:\/\/example.invalid\/feed$/,()=>text(200,xml));
    const policy=defaultPolicy();policy.rules.host_breach_advisory.action='rotate';
    const at='2026-01-01T12:00:00.000Z';
    const ctx={inventory,hosts,providers:[provider],providerCtx:{http,credentials:{},log:silentLogger},policy,state:store,
      notifier:{async notify(){}},fingerprintKey,log:silentLogger,clock:()=>new Date(at),
      feeds:[{url:'https://example.invalid/feed'}],rotate:async()=>{throw new Error('Not authorized.');}};
    await runMonitorOnce(ctx);
    xml='<rss><channel><item><title>Railway security incident</title><link>https://example.invalid/railway</link></item><item><title>Railway and Vercel security incident</title><link>https://example.invalid/shared</link></item></channel></rss>';
    const railwayItem=fingerprint('https://example.invalid/railway',fingerprintKey);
    const sharedItem=fingerprint('https://example.invalid/shared',fingerprintKey);
    const first=await runMonitorOnce(ctx);
    expect((await store.load()).seenFeedItems).toEqual(failedHost==='railway' ? {}:{[railwayItem]:at});
    expect(first.signals.map(signal=>signal.host).sort()).toEqual(['railway','vercel']);
    expect((await store.load()).pendingActions).toHaveLength(2);
    const retry=await runMonitorOnce(ctx);
    expect(retry.signals.map(signal=>signal.host).sort()).toEqual(['railway','vercel']);
    expect((await store.load()).seenFeedItems).toEqual({[railwayItem]:at,[sharedItem]:at});
    expect((await store.load()).pendingActions).toHaveLength(2);
    expect((await runMonitorOnce(ctx)).signals).toEqual([]);
  });
});
