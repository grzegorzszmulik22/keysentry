import type { Inventory, Notifier, Policy, Signal } from '../types.js';
import { executeDecisions, type ActionContext, type RotateExecutor } from './actions.js';
import { now, type DetectorContext } from './context.js';
import { detectBreachFeeds, type BreachFeed, type BreachFeedOptions } from './detectors/breach-feed.js';
import { detectCanaries } from './detectors/canary.js';
import { detectGithubLeaks, type GithubOptions } from './detectors/github-leaks.js';
import { detectRevoked } from './detectors/revoked.js';
import { detectUsage, type UsageOptions } from './detectors/usage.js';
import { decide, type Decision } from './policy.js';
import type { MonitorState, MonitorStateStore } from './state.js';
import { pruneUsageHistory } from './state.js';

export interface MonitorContext extends Omit<DetectorContext,'state'> {
  inventory: Inventory;
  policy: Policy;
  state: MonitorState | MonitorStateStore;
  notifier: Notifier;
  rotate: RotateExecutor;
  feeds?: readonly BreachFeed[];
  breachFeedOptions?: BreachFeedOptions;
  github?: GithubOptions;
  usageOptions?: UsageOptions;
  /** Team policy limits for automatic actions (hosts, providers, tiers); clusters outside them wait for approval. */
  automaticAllowed?: (clusterId: string) => boolean;
}

function isStore(state: MonitorState|MonitorStateStore): state is MonitorStateStore { return 'load' in state; }
const runs = new WeakMap<object,Promise<unknown>>();

async function poll(ctx: MonitorContext): Promise<{signals:Signal[];decisions:Decision[]}> {
  const store=isStore(ctx.state) ? ctx.state:undefined;
  const state=store ? await store.load():ctx.state as MonitorState;
  pruneUsageHistory(state,now(ctx));
  const detector:DetectorContext={...ctx,state};
  const before={
    canaries:new Map(state.canaries.map(canary=>[canary.id,canary.triggeredAt])),
    feeds:{...state.seenFeedItems},github:{...state.seenGithubAlerts},verify:{...state.lastVerify},
  };
  const actions:ActionContext={...detector,policy:ctx.policy,notifier:ctx.notifier,rotate:ctx.rotate,automaticAllowed:ctx.automaticAllowed,
    ...(store ? {saveState:()=>store.save(state)}:{})};
  const signals:Signal[]=[];
  const decisions:Decision[]=[];
  const detectors: Array<() => Promise<Signal[]>> = [
    ()=>detectCanaries(detector), ()=>detectUsage(detector,ctx.usageOptions),
    ()=>detectBreachFeeds(detector,ctx.feeds,ctx.breachFeedOptions),
    ()=>ctx.github ? detectGithubLeaks(detector,ctx.github):Promise.resolve([]),
    ()=>detectRevoked(detector),
  ];
  try {
    for(const detect of detectors) {
      try { signals.push(...await detect()); }
      catch { ctx.log.warn('Unable to run a monitor detector.'); }
    }
    // Defer acknowledgments until each signal has a durable action. In particular,
    // saving the first action must not consume later canary hits after a crash.
    const acknowledgments=new Map<Signal,()=>void>();
    const sourceGroups=new Map<string,{remaining:number;ack:()=>void}>();
    for(const signal of signals) {
      if(signal.kind==='canary_triggered') {
        const canary=state.canaries.find(canary=>canary.id===signal.evidence.canaryId);
        if(canary) {
          const triggered=canary.triggeredAt;
          if(before.canaries.get(canary.id)) canary.triggeredAt=before.canaries.get(canary.id); else delete canary.triggeredAt;
          acknowledgments.set(signal,()=>{canary.triggeredAt=triggered;});
        }
      } else if(signal.kind==='host_breach_advisory' || signal.kind==='leak_detected') {
        const feed=signal.kind==='host_breach_advisory';
        const ids=feed ? signal.evidence.itemIds:[signal.evidence.alertId];
        const keys=Array.isArray(ids) ? [...new Set(ids.filter((id):id is string=>typeof id==='string'))]:[];
        const target=feed ? state.seenFeedItems:state.seenGithubAlerts;
        const original=feed ? before.feeds:before.github;
        const sources:Array<{remaining:number;ack:()=>void}>=[];
        for(const key of keys) {
          if(original[key]) target[key]=original[key]; else delete target[key];
          const groupKey=`${signal.kind}:${key}`;
          let group=sourceGroups.get(groupKey);
          if(!group) {
            group={remaining:0,ack:()=>{target[key]=signal.at;}};
            sourceGroups.set(groupKey,group);
          }
          group.remaining++;
          sources.push(group);
        }
        acknowledgments.set(signal,()=>{for(const source of sources) if(--source.remaining===0) source.ack();});
      } else if(signal.kind==='revoked_upstream') {
        const observed=signal.clusterIds.map(id=>[id,state.lastVerify[id]] as const);
        for(const id of signal.clusterIds) {
          if(before.verify[id]) state.lastVerify[id]=before.verify[id]!; else delete state.lastVerify[id];
        }
        acknowledgments.set(signal,()=>{for(const [id,result] of observed) if(result) state.lastVerify[id]=result;});
      }
    }
    for(const signal of signals) {
      try {
        const selected=decide(signal,ctx.inventory,ctx.policy,state,ctx.automaticAllowed);
        decisions.push(...selected);
        await executeDecisions(selected,actions);
        acknowledgments.get(signal)?.();
        if(store) await store.save(state);
      } catch { ctx.log.warn('Unable to complete a monitor action; the signal remains available for retry.'); }
    }
    return {signals,decisions};
  } finally { if(store) await store.save(state); }
}

/** Calls sharing the same state/store are serialized to avoid lost reservations and duplicated canary actions. */
export function runMonitorOnce(ctx: MonitorContext): Promise<{signals:Signal[];decisions:Decision[]}> {
  const previous=runs.get(ctx.state) ?? Promise.resolve();
  const result=previous.catch(()=>undefined).then(()=>poll(ctx));
  runs.set(ctx.state,result);
  return result.finally(()=>{if(runs.get(ctx.state)===result) runs.delete(ctx.state);});
}

function wait(intervalMs:number, signal?:AbortSignal):Promise<void> {
  return new Promise(resolve=>{
    if(signal?.aborted) {resolve();return;}
    const done=()=>{clearTimeout(timer);signal?.removeEventListener('abort',done);resolve();};
    const timer=setTimeout(done,intervalMs);
    signal?.addEventListener('abort',done,{once:true});
  });
}

export async function runMonitor(ctx: MonitorContext, options:{intervalMs:number;signal?:AbortSignal}):Promise<void> {
  if(!Number.isFinite(options.intervalMs) || options.intervalMs<=0) throw new Error('Monitor interval must be positive.');
  while(!options.signal?.aborted) {
    try { await runMonitorOnce(ctx); }
    catch { ctx.log.error('Monitor poll failed.'); }
    if(options.signal?.aborted) break;
    await wait(options.intervalMs,options.signal);
  }
}
