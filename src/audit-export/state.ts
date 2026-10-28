import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { StateStore } from '../core/store.js';
import { canonicalJson } from '../security/index.js';
import type { AuditExportTarget } from './types.js';

/** Per-target delivery progress. `seq` is the last audit entry the receiver is known to have accepted. */
export interface TargetCursor {
  /** Digest of the target's non-secret destination settings; a different destination starts from the beginning. */
  destination: string;
  seq: number;
  /** Chain hash of entry `seq` when it was sent; a different hash means the audit log was replaced. */
  anchor?: string;
  failures: number;
  lastAttemptAt?: string;
  lastSuccessAt?: string;
  lastError?: string;
  warning?: string;
}

export interface AuditExportState { v: 1; targets: Record<string, TargetCursor> }

/** Encrypted project state in production (`createStoreExportState`); tests use an in-memory object. */
export interface AuditExportStateStore {
  load(): Promise<unknown>;
  save(state: AuditExportState): Promise<void>;
}

const text = z.string().max(500);
const cursorSchema = z.object({
  destination: z.string().regex(/^[0-9a-f]{64}$/),
  seq: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  anchor: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  failures: z.number().int().nonnegative().max(1_000_000),
  lastAttemptAt: z.iso.datetime().optional(),
  lastSuccessAt: z.iso.datetime().optional(),
  lastError: text.optional(),
  warning: text.optional(),
}).strict();
const stateSchema = z.object({
  v: z.literal(1),
  targets: z.record(z.string().regex(/^[A-Za-z0-9_-]{1,64}$/), cursorSchema),
}).strict();

export function emptyExportState(): AuditExportState {
  return { v: 1, targets: {} };
}

/** Unreadable progress restarts from the beginning: receivers deduplicate by seq, and a gap is never acceptable. */
export function parseExportState(raw: unknown): { state: AuditExportState; reset: boolean } {
  if (raw === null || raw === undefined) return { state: emptyExportState(), reset: false };
  const parsed = stateSchema.safeParse(raw);
  if (!parsed.success) return { state: emptyExportState(), reset: true };
  const targets: Record<string, TargetCursor> = Object.create(null);
  for (const [id, cursor] of Object.entries(parsed.data.targets)) targets[id] = { ...cursor } as TargetCursor;
  return { state: { v: 1, targets }, reset: false };
}

/** What the receiver is: changing any of these fields means a new destination that needs the whole log. */
export function destinationDigest(target: AuditExportTarget): string {
  const fields = target.kind === 'syslog' ? { kind: target.kind, host: target.host, port: target.port }
    : target.kind === 's3' ? { kind: target.kind, endpoint: target.endpoint, bucket: target.bucket, region: target.region, prefix: target.prefix }
    : { kind: target.kind, url: target.url };
  return createHash('sha256').update(`keysentry-audit-export:v1\n${canonicalJson(fields)}`).digest('hex');
}

export function createStoreExportState(store: Pick<StateStore, 'readJson' | 'writeJson'>, path: string): AuditExportStateStore {
  return {
    load: () => store.readJson('plan', path),
    save: state => store.writeJson('plan', path, state),
  };
}
