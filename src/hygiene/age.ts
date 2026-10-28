import { join } from 'node:path';
import { z } from 'zod';
import { createRedactor } from '../core/redact.js';
import { PROVIDER_IDS } from '../core/provider-ids.js';
import type { StateStore } from '../core/store.js';
import { usageKey, type MonitorState } from '../monitor/state.js';
import type { Inventory, JournalEntry, KeyHygiene, ProviderId, ProviderKeyInfo } from '../types.js';
import { unusedDays, type UsageCoverage } from './unused.js';

const DAY = 86_400_000;
const fingerprint = z.string().regex(/^[a-f0-9]{32}$/);
const redactor = createRedactor();
const safeId = z.string().min(1).max(4096).refine(value => redactor.redact(value) === value
  && !['__proto__', 'constructor', 'prototype'].includes(value));
const date = z.string().datetime();
const amount = z.number().finite().nonnegative();
const providerId = z.enum(PROVIDER_IDS);

export interface HygieneState {
  version: 1;
  /** Keyed cluster fingerprints only; unreadable values cannot establish key age. */
  firstSeen: Record<string, string>;
  lastRotation: Record<string, string>;
  settings: { rotateEveryDays: number; spendCapsUsd: Partial<Record<ProviderId, number>> };
}

const schema = z.object({
  version: z.literal(1),
  firstSeen: z.record(fingerprint, date),
  lastRotation: z.record(safeId, date),
  settings: z.object({ rotateEveryDays: z.number().int().positive().max(36500),
    spendCapsUsd: z.partialRecord(providerId, amount) }),
});

function snapshot(state: unknown): HygieneState {
  const result = schema.safeParse(state);
  if (!result.success) throw new Error('Invalid hygiene state.');
  return result.data;
}

function hygieneDate(now: string | Date): string {
  const at = now instanceof Date ? now.getTime() : Date.parse(now);
  if (!Number.isFinite(at)) throw new Error('Invalid hygiene date.');
  return new Date(at).toISOString();
}

export function createHygieneState(): HygieneState {
  return { version: 1, firstSeen: {}, lastRotation: {}, settings: { rotateEveryDays: 90, spendCapsUsd: {} } };
}

/** Requires the encrypted StateStore; there is deliberately no plaintext fallback. */
export function createHygieneStateStore(store: StateStore): {
  load(): Promise<HygieneState>; save(state: HygieneState): Promise<void>;
} {
  const path = join(store.paths.dir, 'hygiene.json');
  return {
    async load() {
      const state = await store.readJson<unknown>('monitor', path);
      return state === null ? createHygieneState() : snapshot(state);
    },
    async save(state) { await store.writeJson('monitor', path, snapshot(state)); },
  };
}

/** Mutates and returns state so callers can persist the same snapshot after each scan. */
export function updateFirstSeen(state: HygieneState, inventory: Inventory, now: string | Date): HygieneState {
  const at = hygieneDate(now);
  for (const cluster of inventory.clusters) {
    if (cluster.fingerprint !== null && fingerprint.safeParse(cluster.fingerprint).success
        && !Object.hasOwn(state.firstSeen, cluster.fingerprint)) state.firstSeen[cluster.fingerprint] = at;
  }
  return state;
}

/** Cleanup and undo revocations do not mean that an active key was successfully rotated. */
export function updateLastRotation(state: HygieneState, entries: readonly JournalEntry[]): HygieneState {
  for (const entry of entries) {
    if (entry.event !== 'revoked' || !entry.clusterId || entry.data?.cleanup || entry.data?.undo
        || !date.safeParse(entry.at).success || !safeId.safeParse(entry.clusterId).success) continue;
    const replacement = entry.data?.newFingerprint;
    const ids = [entry.clusterId];
    if (typeof replacement === 'string' && fingerprint.safeParse(replacement).success) ids.push(replacement);
    for (const id of ids) {
      if (!Object.hasOwn(state.lastRotation, id) || Date.parse(state.lastRotation[id]!) < Date.parse(entry.at)) {
        state.lastRotation[id] = entry.at;
      }
    }
  }
  return state;
}

export interface HygieneReportInput {
  inventory: Inventory;
  state: HygieneState;
  now: string | Date;
  monitor?: MonitorState;
  /** Continuous counter coverage, keyed by usageKey(provider, keyRef). Legacy monitor data has none. */
  usageCoverage?: Readonly<Record<string, UsageCoverage>>;
  providerKeys?: Partial<Record<ProviderId, readonly ProviderKeyInfo[]>>;
}

/** Age is time since observation, rather than a claim about the provider's creation date. */
export function hygieneReport(input: HygieneReportInput): KeyHygiene[] {
  const at = hygieneDate(input.now);
  const state = snapshot(input.state);
  return input.inventory.clusters.map(cluster => {
    const firstSeen = cluster.fingerprint === null ? at : state.firstSeen[cluster.fingerprint] ?? at;
    const lastRotation = state.lastRotation[cluster.id] ?? (cluster.fingerprint === null ? undefined : state.lastRotation[cluster.fingerprint]);
    const rotationBase = Date.parse(lastRotation ?? firstSeen);
    const result: KeyHygiene = { clusterId: cluster.id, firstSeen,
      ageDays: Math.max(0, Math.floor((Date.parse(at) - Date.parse(firstSeen)) / DAY)),
      copies: cluster.consumers.length, rotateBy: new Date(rotationBase + state.settings.rotateEveryDays * DAY).toISOString() };
    const ref = input.monitor?.keyRefs[cluster.id];
    if (ref) {
      const key = usageKey(cluster.provider, ref);
      const unused = unusedDays(input.monitor?.usageHistory[key] ?? [], at, input.usageCoverage?.[key]);
      if (unused !== undefined) result.unusedDays = unused;
      const providerKey = input.providerKeys?.[cluster.provider]?.find(key => key.keyRef === ref);
      if (providerKey?.limitUsd === null || (typeof providerKey?.limitUsd === 'number' && Number.isFinite(providerKey.limitUsd) && providerKey.limitUsd >= 0)) {
        result.spendLimitUsd = providerKey.limitUsd;
      }
    }
    return result;
  });
}
