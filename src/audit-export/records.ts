import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRedactor } from '../core/redact.js';
import { canonicalJson } from '../security/index.js';
import type { AuditExportRecord, Redactor } from '../types.js';
import { AuditExportRefusedError } from './types.js';

const ZERO_HASH = '0'.repeat(64);
const HASH = /^[0-9a-f]{64}$/;
const CHANGED = 'The audit log changed while it was being read for export, so nothing was exported. Run keysentry audit verify.';

/** The verified prefix of the audit log, as value-free export records (index i holds seq i + 1). */
export interface AuditSnapshot {
  readonly entries: number;
  readonly records: readonly AuditExportRecord[];
  /** Chain hash of the entry with this sequence number; lets the exporter notice a replaced log. */
  hashAt(seq: number): string | undefined;
  /**
   * The entry's MAC as read (HMAC-SHA256 of its chain hash under the vault's audit key). The exporter checks it, so the
   * records it sends are the bytes it read, authenticated, and not only the bytes an earlier verify() saw (review L2).
   */
  macAt?(seq: number): string | undefined;
}

export interface AuditRecordReader {
  /** Reads exactly the first `entries` entries, re-checking their hash chain; throws AuditExportRefusedError otherwise. */
  load(entries: number): Promise<AuditSnapshot>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function cleanValue(value: unknown, redactor: Redactor, depth: number): unknown {
  if (depth > 32) return null;
  if (typeof value === 'string') return redactor.redact(value);
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (Array.isArray(value)) return value.map(item => cleanValue(item, redactor, depth + 1));
  if (isRecord(value)) {
    // fromEntries defines own data properties, so a "__proto__" key stays an ordinary field.
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [redactor.redact(key), cleanValue(item, redactor, depth + 1)]));
  }
  return null;
}

/** The person or device an entry names, when its data carries one (team mode records `memberId`). */
function actorOf(data: Record<string, unknown> | undefined): string | undefined {
  if (!data) return undefined;
  if (typeof data.actor === 'string' && /^[A-Za-z0-9._@:-]{1,128}$/.test(data.actor)) return data.actor;
  if (typeof data.memberId === 'string' && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(data.memberId)) return data.memberId;
  return undefined;
}

/**
 * Projects one audit entry onto the export contract. The audit log is value-free by construction; strings pass
 * through the redactor again so a value registered in this process can never leave in an export.
 */
export function toExportRecord(entry: { seq: number; at: string; kind: string; summary: string; data?: Record<string, unknown> },
  redactor: Redactor = createRedactor()): AuditExportRecord {
  const data = entry.data === undefined ? undefined : cleanValue(entry.data, redactor, 0) as Record<string, unknown>;
  const actor = actorOf(data);
  return {
    seq: entry.seq, at: entry.at, kind: redactor.redact(entry.kind), summary: redactor.redact(entry.summary),
    ...(data === undefined ? {} : { data }), ...(actor === undefined ? {} : { actor }),
  };
}

function chainHash(line: Record<string, unknown>): string {
  const { seq, at, kind, summary, data, prev } = line;
  return createHash('sha256').update(canonicalJson({ seq, at, kind, summary, data, prev })).digest('hex');
}

/** Parses the audit file written by src/security/audit.ts. MACs and signatures are checked by `audit.verify()`. */
export function parseAuditLines(text: string, entries: number, redactor?: Redactor): AuditSnapshot {
  if (!Number.isSafeInteger(entries) || entries < 0) throw new AuditExportRefusedError(CHANGED);
  const lines = text === '' ? [] : text.split('\n');
  if (lines.at(-1) === '') lines.pop();
  if (lines.length < entries) throw new AuditExportRefusedError(CHANGED);
  const clean = redactor ?? createRedactor();
  const records: AuditExportRecord[] = [];
  const hashes: string[] = [];
  const macs: (string | undefined)[] = [];
  let previous = ZERO_HASH;
  for (let index = 0; index < entries; index++) {
    let line: unknown;
    try { line = JSON.parse(lines[index]!.replace(/\r$/, '')); } catch { throw new AuditExportRefusedError(CHANGED); }
    if (!isRecord(line) || line.seq !== index + 1 || line.prev !== previous || typeof line.hash !== 'string' || !HASH.test(line.hash)
      || typeof line.at !== 'string' || typeof line.kind !== 'string' || typeof line.summary !== 'string'
      || (line.data !== undefined && !isRecord(line.data))) throw new AuditExportRefusedError(CHANGED);
    let hash: string;
    try { hash = chainHash(line); } catch { throw new AuditExportRefusedError(CHANGED); }
    if (hash !== line.hash) throw new AuditExportRefusedError(CHANGED);
    records.push(toExportRecord({ seq: index + 1, at: line.at, kind: line.kind, summary: line.summary,
      ...(line.data === undefined ? {} : { data: line.data as Record<string, unknown> }) }, clean));
    hashes.push(hash);
    macs.push(typeof line.mac === 'string' && HASH.test(line.mac) ? line.mac : undefined);
    previous = hash;
  }
  return { entries, records, hashAt: seq => hashes[seq - 1], macAt: seq => macs[seq - 1] };
}

export function createAuditFileReader(path: string, opts: { redactor?: Redactor } = {}): AuditRecordReader {
  return {
    async load(entries) {
      let text: string;
      try { text = await readFile(path, 'utf8'); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new AuditExportRefusedError('The audit log could not be read for export.');
        text = '';
      }
      return parseAuditLines(text, entries, opts.redactor);
    },
  };
}
