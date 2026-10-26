import { describe, expect, it } from 'vitest';
import { buildInventory } from '../../src/core/inventory.js';
import { fingerprint } from '../../src/core/fingerprint.js';
import { serviceKey } from '../../src/core/service-key.js';
import { runMonitorOnce, runMonitor } from '../../src/monitor/daemon.js';
import { defaultPolicy } from '../../src/monitor/policy.js';
import { createMonitorState, createMemoryMonitorStateStore, usageKey } from '../../src/monitor/state.js';
import { anthropicProvider } from '../../src/providers/anthropic.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';
import { FakeHttp, json, silentLogger, text } from '../helpers/fake-http.js';
import type { RotationPlan } from '../../src/types.js';

describe('monitor daemon',()=>{
  it('keeps every detector running after a partial scan and acts only on clusters without failed-host consumers',async()=>{
    const railway=new FakeHost('railway'),vercel=new FakeHost('vercel');
    const provider=new FakeProvider('openrouter','auto','sk-or-v1-aB3cD7eF9gH2iJ4kL6mN8pQ0');
    const safeRotate=provider.issue(),blockedRotate=provider.issue(),safeCap=provider.issue(),blockedCap=provider.issue();
    const safeLeak=provider.issue(),blockedLeak=provider.issue(),safeRevoked=provider.issue(),blockedRevoked=provider.issue();
    const decoy=provider.issue('decoy',0.01);
    const compromised=railway.addService('api',{OPENROUTER_API_KEY:safeRotate.value,OPENROUTER_SHARED_KEY:blockedRotate.value});
    railway.addService('billing',{OPENROUTER_API_KEY:safeCap.value,OPENROUTER_SHARED_KEY:blockedCap.value});
    railway.addService('leaked',{OPENROUTER_API_KEY:safeLeak.value,OPENROUTER_SHARED_KEY:blockedLeak.value});
    railway.addService('revoked',{OPENROUTER_API_KEY:safeRevoked.value,OPENROUTER_SHARED_KEY:blockedRevoked.value});
    vercel.addService('partially-scanned',{
      OPENROUTER_API_KEY:blockedRotate.value,OPENROUTER_USAGE_KEY:blockedCap.value,
      OPENROUTER_LEAKED_KEY:blockedLeak.value,OPENROUTER_REVOKED_KEY:blockedRevoked.value,
    });
    const fingerprintKey=Buffer.alloc(32,8),at='2026-10-26T12:30:00.000Z';
    const scans=await Promise.all([railway,vercel].map(async host=>({host:host.id,
      services:await Promise.all((await host.listServices()).map(async service=>({service,vars:await host.readVariables(service)})))})));
    // The failed host returned one service before its remaining inventory request failed.
    const inventory=buildInventory(scans.map(scan=>scan.host==='vercel' ? {...scan,error:'Remaining services could not be scanned.'}:scan),fingerprintKey);
    const state=createMonitorState();
    state.canaries.push({id:'partial-scan-canary',provider:'openrouter',keyRef:decoy.ref,service:compromised,
      varName:'OPENROUTER_API_KEY_FALLBACK',createdAt:'2026-10-25T00:00:00.000Z'});
    provider.spend(decoy.ref,0.001);
    for(const key of [safeCap,blockedCap]) {
      const usage=usageKey('openrouter',key.ref);
      state.usageHistory[usage]=Array.from({length:24},(_,i)=>({
        hour:new Date(Date.parse('2026-10-25T12:00:00.000Z')+i*3_600_000).toISOString(),costUsd:0.1,
        byModel:{[fingerprint('normal-model',fingerprintKey)]:0.1},
      }));
      state.cumulativeTotals[usage]={costUsd:2.4,at:'2026-10-26T11:30:00.000Z',
        byModel:{[fingerprint('normal-model',fingerprintKey)]:2.4}};
      provider.spend(key.ref,8.4,84,'normal-model');
    }
    for(const key of [safeRevoked,blockedRevoked]) {
      const id=fingerprint(key.value,fingerprintKey);
      state.lastVerify[id]={at:'2026-10-26T10:30:00.000Z',ok:true,status:200,fingerprint:id};
      provider.revokeUpstream(key.ref);
    }
    const feedUrl='https://example.invalid/partial-scan-feed';
    state.feedBaselines[fingerprint(feedUrl,fingerprintKey)]='2026-10-25T12:30:00.000Z';
    const http=new FakeHttp()
      .on('GET',/^https:\/\/example.invalid\/partial-scan-feed$/,()=>text(200,
        '<rss><channel><item><title>Vercel security incident</title><pubDate>2026-10-26T12:00:00Z</pubDate><link>https://example.invalid/incident</link></item></channel></rss>'))
      .on('GET',/^https:\/\/api\.github\.com\/repos\/acme\/app\/secret-scanning\/alerts\?state=open&per_page=100$/,()=>json(200,[
        {number:1,state:'open',secret_type:'openrouter_api_key',secret:safeLeak.value},
        {number:2,state:'open',secret_type:'openrouter_api_key',secret:blockedLeak.value},
      ]));
    const policy=defaultPolicy();policy.autoExecute=true;policy.autoContain=true;
    const plans:RotationPlan[]=[],notifications:{title:string;body:string}[]=[];
    const result=await runMonitorOnce({inventory,hosts:[railway,vercel],providers:[provider],
      providerCtx:{http,credentials:{GITHUB_TOKEN:'github-monitor-fixture-token'},log:silentLogger},
      state:createMemoryMonitorStateStore(state),policy,fingerprintKey,log:silentLogger,clock:()=>new Date(at),
      feeds:[{url:feedUrl,host:'vercel'}],github:{repos:['acme/app']},
      notifier:{async notify(title,body){notifications.push({title,body});}},
      rotate:async plan=>{plans.push(plan);return {planId:plan.id,dryRun:false,startedAt:at,finishedAt:at,
        steps:plan.steps.map(step=>({clusterId:step.clusterId,status:'revoked' as const,warnings:[]})),deployments:[],diff:[]};},
    });
    expect([...new Set(result.signals.map(signal=>signal.kind))].sort()).toEqual([
      'canary_triggered','host_breach_advisory','leak_detected','revoked_upstream','usage_anomaly',
    ]);
    const blocked=[blockedRotate,blockedCap,blockedLeak,blockedRevoked].map(key=>fingerprint(key.value,fingerprintKey)).sort();
    const destructive=result.decisions.filter(decision=>decision.action!=='alert');
    expect(destructive.flatMap(decision=>decision.clusterIds).some(id=>blocked.includes(id))).toBe(false);
    const downgraded=result.decisions.filter(decision=>decision.action==='alert' && decision.signal.kind!=='host_breach_advisory');
    expect([...new Set(downgraded.flatMap(decision=>decision.clusterIds))].sort()).toEqual(blocked);
    expect(plans.flatMap(plan=>plan.steps.map(step=>step.clusterId)).sort()).toEqual(
      [safeRotate,safeLeak,safeRevoked].map(key=>fingerprint(key.value,fingerprintKey)).sort());
    expect(provider.capped).toEqual([safeCap.ref]);
    expect(notifications.some(notification=>notification.title.includes('alert')
      && /(?:incomplete|failed)[\s\S]*scan|scan[\s\S]*(?:incomplete|failed)/i.test(notification.body))).toBe(true);
  });

  it('learns a first Anthropic poll with $1.50 on an unseen model without signaling or disabling the key',async()=>{
    const host=new FakeHost('railway');
    const key=new FakeProvider('anthropic','guided','sk-ant-api03-aB3cD7eF9gH2iJ4kL6mN8pQ0').issue();
    const service=host.addService('api',{ANTHROPIC_API_KEY:key.value});
    const fingerprintKey=Buffer.alloc(32,9);
    const inventory=buildInventory([{host:host.id,services:[{service,vars:await host.readVariables(service)}]}],fingerprintKey);
    const http=new FakeHttp()
      .on('GET',/^https:\/\/api\.anthropic\.com\/v1\/organizations\/api_keys\?/,()=>json(200,{
        data:[{id:'apikey_probe',name:'production',status:'active',created_at:'2026-10-01T00:00:00Z',
          partial_key_hint:`${key.value.slice(0,20)}...${key.value.slice(-4)}`}],
        has_more:false,first_id:'apikey_probe',last_id:'apikey_probe',
      }))
      .on('GET',/^https:\/\/api\.anthropic\.com\/v1\/organizations\/usage_report\/messages\?/,()=>json(200,{
        data:[{starting_at:'2026-10-26T12:00:00Z',ending_at:'2026-10-26T13:00:00Z',results:[{
          model:'claude-sonnet-4-20250514',uncached_input_tokens:500000,output_tokens:0,
          cache_read_input_tokens:0,cache_creation_input_tokens:0,
        }]}],has_more:false,next_page:null,
      }))
      .on('GET',/^https:\/\/api\.anthropic\.com\/v1\/models$/,()=>json(200,{data:[],has_more:false,first_id:null,last_id:null}))
      .on('POST',/^https:\/\/api\.anthropic\.com\/v1\/organizations\/api_keys\/apikey_probe$/,()=>json(200,{id:'apikey_probe',status:'inactive'}));
    const store=createMemoryMonitorStateStore();
    const result=await runMonitorOnce({inventory,hosts:[host],providers:[anthropicProvider],
      providerCtx:{http,credentials:{ANTHROPIC_ADMIN_KEY:'anthropic-admin-fixture-credential'},log:silentLogger},
      policy:defaultPolicy(),state:store,notifier:{async notify(){}},fingerprintKey,log:silentLogger,
      clock:()=>new Date('2026-10-26T12:30:00.000Z'),feeds:[],rotate:async()=>{throw new Error('Not authorized.');},
    });
    const saved=await store.load();
    expect(saved.usageHistory[usageKey('anthropic','apikey_probe')]?.[0]?.costUsd).toBe(1.5);
    expect(result.signals.filter(signal=>signal.kind==='usage_anomaly')).toEqual([]);
    expect(result.decisions).toEqual([]);
    expect(saved.pendingActions).toEqual([]);
    expect(http.calls.filter(call=>call.method==='POST')).toEqual([]);
  });

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
