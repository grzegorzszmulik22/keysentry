import { z } from 'zod';
import { createRedactor } from '../core/redact.js';
import { readJson, statePaths, writeJsonAtomic, type StateStore } from '../core/store.js';
import type { PendingAction, ProviderId, ServiceRef } from '../types.js';

export interface UsageBucket { hour: string; costUsd: number; requests?: number; byModel?: Record<string, number> }
export interface CumulativeTotal { costUsd: number; requests?: number; byModel?: Record<string, number>; at: string }
export interface Canary {
  id: string; provider: 'openrouter'; keyRef: string; service: ServiceRef; varName: string;
  createdAt: string; triggeredAt?: string;
}
export interface LastVerify { at: string; ok: boolean; status?: number; fingerprint: string }
/** Only the safety options and minimum signal provenance needed by a later human approval are persisted. */
export interface MonitorPendingAction extends PendingAction {
  highConfidence?: boolean;
  /** Atomic rolls invalidate the old key immediately and require an interactive approval executor. */
  requiresInteractive?: boolean;
  /** Recorded revocation choice; absent on legacy actions means false. */
  revokeUnconfirmed?: boolean;
}
export interface MonitorState {
  version: 1;
  usageHistory: Record<string, UsageBucket[]>;
  cumulativeTotals: Record<string, CumulativeTotal>;
  keyRefs: Record<string, string>;
  canaries: Canary[];
  /** Keyed feed URL fingerprints mapped to the first successful poll time. */
  feedBaselines: Record<string, string>;
  seenFeedItems: Record<string, string>;
  seenGithubAlerts: Record<string, string>;
  lastVerify: Record<string, LastVerify>;
  cooldowns: Record<string, string>;
  containCooldowns: Record<string, string>;
  pendingActions: MonitorPendingAction[];
  autoRotations: Record<string, number>;
  autoContainments: Record<string, number>;
}
export interface MonitorStateStore {
  load(): Promise<MonitorState>;
  save(state: MonitorState): Promise<void>;
}

export function createMonitorState(): MonitorState {
  return { version: 1, usageHistory: {}, cumulativeTotals: {}, keyRefs: {}, canaries: [],
    feedBaselines: {}, seenFeedItems: {}, seenGithubAlerts: {}, lastVerify: {}, cooldowns: {}, containCooldowns: {},
    pendingActions: [], autoRotations: {}, autoContainments: {} };
}

/** Provider namespace prevents unrelated providers' key references from colliding. */
export function usageKey(provider: ProviderId, keyRef: string): string { return `${provider}:${keyRef}`; }

/** Expire history for retired keys as well as keys still present in inventory. */
export function pruneUsageHistory(state: MonitorState, at: Date): void {
  const cutoff=at.getTime()-30*24*60*60*1000;
  for(const [key,buckets] of Object.entries(state.usageHistory)) {
    const recent=buckets.filter(bucket=>Date.parse(bucket.hour)>=cutoff);
    if(recent.length) state.usageHistory[key]=recent; else delete state.usageHistory[key];
  }
}

const redactor = createRedactor();
const safeText = z.string().max(4096).refine(value => redactor.redact(value) === value);
const date = z.string().datetime();
const amount = z.number().finite().nonnegative();
const amounts = z.record(safeText, amount);
const service = z.object({
  host: z.enum(['railway','vercel','render','fly','github-actions','dotenv']),
  projectId: safeText, projectName: safeText, serviceId: safeText, serviceName: safeText,
  environmentId: safeText, environmentName: safeText,
});
// Projection deliberately strips unknown fields; neither provider payloads nor Signal.evidence are persisted.
const schema = z.object({
  version: z.literal(1),
  usageHistory: z.record(safeText, z.array(z.object({hour:date,costUsd:amount,requests:amount.optional(),byModel:amounts.optional()}))),
  cumulativeTotals: z.record(safeText,z.object({costUsd:amount,requests:amount.optional(),byModel:amounts.optional(),at:date})),
  keyRefs: z.record(safeText,safeText),
  canaries: z.array(z.object({id:safeText,provider:z.literal('openrouter'),keyRef:safeText,service,varName:safeText,createdAt:date,triggeredAt:date.optional()})),
  feedBaselines: z.record(safeText,date).default({}),
  seenFeedItems: z.record(safeText,date), seenGithubAlerts:z.record(safeText,date),
  lastVerify: z.record(safeText,z.object({at:date,ok:z.boolean(),status:z.number().int().optional(),fingerprint:safeText})),
  cooldowns:z.record(safeText,date),
  containCooldowns:z.record(safeText,date).default({}),
  pendingActions:z.array(z.object({id:safeText,createdAt:date,signalId:safeText,
    action:z.enum(['alert','cap','rotate','breach-mode']),clusterIds:z.array(safeText),
    status:z.enum(['pending','approved','executed','dismissed','failed']),note:safeText.optional(),highConfidence:z.boolean().optional(),
    requiresInteractive:z.boolean().optional(),revokeUnconfirmed:z.boolean().optional()})),
  autoRotations:z.record(z.string().regex(/^\d{4}-\d{2}-\d{2}$/),z.number().int().nonnegative()),
  autoContainments:z.record(z.string().regex(/^\d{4}-\d{2}-\d{2}$/),z.number().int().nonnegative()).default({}),
});

function snapshot(state: unknown): MonitorState {
  const result = schema.safeParse(state);
  if (!result.success) throw new Error('Invalid monitor state.');
  return result.data;
}

export function createMemoryMonitorStateStore(initial = createMonitorState()): MonitorStateStore {
  let current = snapshot(initial);
  return { async load() { return snapshot(current); }, async save(state) { current = snapshot(state); } };
}

/** cwd is the project directory, matching core.statePaths(). */
export function createFileMonitorStateStore(cwd = process.cwd(), store?: StateStore): MonitorStateStore {
  const path = statePaths(cwd).monitor;
  return {
    async load() { const state = await (store ? store.readJson<unknown>('monitor', path) : readJson<unknown>(path)); return state === null ? createMonitorState() : snapshot(state); },
    async save(state) { if (store) await store.writeJson('monitor', path, snapshot(state)); else await writeJsonAtomic(path, snapshot(state)); },
  };
}
