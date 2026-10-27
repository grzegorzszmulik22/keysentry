import { resolve } from 'node:path';
import { z } from 'zod';
import type { StateStore } from '../core/store.js';
import type { ApprovalGrant, ApprovalRequest, AuditEvent } from '../types.js';

export type ApprovalStatus = 'pending' | 'approved' | 'expired' | 'rejected';
export interface StoredApproval extends ApprovalRequest {
  kind: string;
  keyCount: number;
  status: ApprovalStatus;
  attempts: number;
  grant?: ApprovalGrant;
}
export interface ApprovalState {
  v: 1;
  requests: StoredApproval[];
  usedChallenges: string[];
  usedDeviceApprovals: string[];
  counters: { credentialId: string; publicKeyCose: string; signCount: number }[];
  auditPending: AuditEvent[];
}

const date = z.string().datetime();
const grant = z.object({ actionId: z.string(), digest: z.string().regex(/^[a-f0-9]{64}$/), at: date,
  by: z.discriminatedUnion('kind', [z.object({ kind: z.literal('passkey'), credentialId: z.string() }).strict(), z.object({ kind: z.literal('device'), keyId: z.string() }).strict()]) }).strict();
const stateSchema = z.object({
  v: z.literal(1),
  requests: z.array(z.object({
    actionId: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/), digest: z.string().regex(/^[a-f0-9]{64}$/), createdAt: date, expiresAt: date,
    challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/), widening: z.boolean(), kind: z.string().min(1).max(80),
    keyCount: z.number().int().min(0).max(10000), status: z.enum(['pending', 'approved', 'expired', 'rejected']),
    attempts: z.number().int().min(0).max(5), grant: grant.optional(),
  }).strict()),
  usedChallenges: z.array(z.string().regex(/^[A-Za-z0-9_-]{43}$/)),
  usedDeviceApprovals: z.array(z.string().regex(/^[a-f0-9]{64}$/)),
  counters: z.array(z.object({ credentialId: z.string(), publicKeyCose: z.string(), signCount: z.number().int().min(0).max(0xffffffff) }).strict()),
  auditPending: z.array(z.object({ kind: z.string(), summary: z.string(), data: z.record(z.string(), z.unknown()).optional() }).strict()).default([]),
}).strict();

// Serialize complete read/modify/write transactions, including different service instances.
const queues = new Map<string, Promise<unknown>>();
export function transactApprovals<T>(store: StateStore, operation: (state: ApprovalState, commit: () => Promise<void>) => Promise<T>): Promise<T> {
  const path = resolve(store.paths.dir, 'approvals.json');
  const previous = queues.get(path) ?? Promise.resolve();
  const current = previous.catch(() => undefined).then(async () => {
    const raw = await store.readJson('pending', path);
    let state: ApprovalState;
    if (raw === null) state = { v: 1, requests: [], usedChallenges: [], usedDeviceApprovals: [], counters: [], auditPending: [] };
    else {
      const parsed = stateSchema.safeParse(raw);
      if (!parsed.success) throw new Error('Saved approval state could not be read.');
      state = parsed.data;
      if (new Set(state.requests.map((r) => r.actionId)).size !== state.requests.length || new Set(state.requests.map((r) => r.challenge)).size !== state.requests.length) {
        throw new Error('Saved approval state could not be read.');
      }
    }
    return operation(state, () => store.writeJson('pending', path, state));
  });
  queues.set(path, current);
  return current.finally(() => { if (queues.get(path) === current) queues.delete(path); });
}
