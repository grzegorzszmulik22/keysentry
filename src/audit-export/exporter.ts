import { createHash, createHmac, createPublicKey, timingSafeEqual } from 'node:crypto';
import { canonicalJson } from '../security/index.js';
import type { DeviceKey } from '../security/index.js';
import type { AuditExportKind, AuditExportRecord, AuditLog, HttpClient, Vault } from '../types.js';
import { createOtlpSink } from './otlp.js';
import type { AuditRecordReader, AuditSnapshot } from './records.js';
import { createS3Sink } from './s3.js';
import { destinationDigest, parseExportState, type AuditExportState, type AuditExportStateStore, type TargetCursor } from './state.js';
import { createSyslogSink, type SyslogConnector } from './syslog.js';
import { AuditExportError, AuditExportRefusedError, EXPORT_SECRET_FIELDS, exportSecretName, type AuditExportTarget, type ExportSecretField,
  type ExportSink } from './types.js';
import { createWebhookSink, webhookPublicKey } from './webhook.js';

export interface AuditExportLimits {
  /** Records per batch (one object, one request, one syslog connection). */
  maxRecords: number;
  /** Approximate encoded bytes per batch; a single larger record still goes alone. */
  maxBytes: number;
  /** Batches per target per run; the rest waits for the next run, in order. */
  maxBatchesPerRun: number;
  /** Attempts per batch within one run, including the first. */
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  /** A longer Retry-After ends this run's attempts for the target instead of waiting. */
  maxRetryAfterMs: number;
  /** After repeated failures, unforced runs (the watcher) wait this long at most before trying the target again. */
  maxCooldownMs: number;
}

export const DEFAULT_EXPORT_LIMITS: AuditExportLimits = {
  maxRecords: 200, maxBytes: 512 * 1024, maxBatchesPerRun: 50, maxAttempts: 3,
  baseDelayMs: 1_000, maxDelayMs: 10_000, maxRetryAfterMs: 30_000, maxCooldownMs: 60 * 60_000,
};

export interface AuditExporterOptions {
  targets: readonly AuditExportTarget[];
  /** The tamper-evident log; `verify()` must pass before anything is read or sent. */
  audit: Pick<AuditLog, 'verify'>;
  reader: AuditRecordReader;
  /** The runtime's egress-guarded client, with rules for the export URLs (see auditExportEgressRules). */
  http: HttpClient;
  /**
   * Optional per-target clients that reach only that target's host (the runtime's single-host guarded clients). When
   * given, an OTLP custom header may use any name, because no redirect can carry it to another configured host.
   */
  httpFor?: (target: AuditExportTarget) => HttpClient;
  /** The only path to a syslog server (createTlsSyslogConnector). */
  tls: SyslogConnector;
  vault: Vault;
  /** The watcher/device Ed25519 key that signs webhook batches; the caller's buffer is cleared after each use. */
  signingKey: () => Promise<DeviceKey>;
  /**
   * The audit log's MAC key (vault entry `audit/mac`), read through the same vault view the audit log uses. Every entry
   * read for export is checked against it (review L2). Defaults to `vault.get('audit/mac')`.
   */
  macKey?: () => Promise<Buffer | null>;
  /**
   * Further public keys that sign this project's webhook batches (a deployed watcher's or cloud box's key), listed by
   * `status()` next to this device's key so receivers can trust exactly those (review M3).
   */
  otherSigningKeys?: () => Promise<{ signer: string; publicKeyDer: Buffer }[]>;
  state: AuditExportStateStore;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
  /** Stable, non-secret label for this log in webhook ids and OTLP resources ([A-Za-z0-9_-], at most 64). */
  sourceId?: string;
  /** RFC 5424 HOSTNAME; defaults to this machine's name. */
  hostname?: string;
  limits?: Partial<AuditExportLimits>;
}

export type TargetOutcome = 'sent' | 'up-to-date' | 'failed' | 'refused' | 'waiting';

export interface TargetRunResult {
  id: string;
  kind: AuditExportKind;
  destination: string;
  status: TargetOutcome;
  /** Records the receiver accepted in this run, and their range. */
  sent: number;
  batches: number;
  firstSeq?: number;
  lastSeq?: number;
  /** Last entry the receiver is known to hold, and how many verified entries still wait. */
  cursor: number;
  pending: number;
  error?: string;
  warnings: string[];
}

export interface AuditExportRunResult { entries: number; targets: TargetRunResult[] }

export interface DryRunBatch { firstSeq: number; lastSeq: number; records: number; bytes: number; location: string }
export interface TargetDryRun {
  id: string; kind: AuditExportKind; destination: string; cursor: number; pending: number;
  credentials: 'present' | 'missing' | 'not needed' | 'device key';
  batches: DryRunBatch[];
  /** The first records that would be sent, value-free. */
  preview: Pick<AuditExportRecord, 'seq' | 'at' | 'kind' | 'summary'>[];
  notes: string[];
}
export interface AuditExportDryRun { entries: number; targets: TargetDryRun[] }

export interface TargetStatus {
  id: string; kind: AuditExportKind; destination: string; cursor: number; pending: number;
  failures: number; lastAttemptAt?: string; lastSuccessAt?: string; lastError?: string; warning?: string; nextAttemptAt?: string;
  /** Ed25519 webhook targets: the key receivers check signatures with. */
  publicKey?: { keyId: string; whpk: string; spkiDerBase64: string };
  /**
   * Ed25519 webhook targets: every key that may sign this project's batches (this device, and each deployed watcher
   * and cloud box this computer knows). Receivers trust exactly these and pick one by the keysentry-key-id header.
   */
  publicKeys?: { signer: string; keyId: string; whpk: string; spkiDerBase64: string }[];
}
export interface AuditExportStatus { entries: number; verified: boolean; problem?: string; targets: TargetStatus[] }

export interface AuditExporter {
  /** Sends every verified entry each target has not acknowledged, in order. `force` ignores failure cooldowns. */
  run(options?: { force?: boolean; only?: readonly string[] }): Promise<AuditExportRunResult>;
  /** What `run` would send: verifies and reads, but contacts nothing, reads no credential values and saves nothing. */
  dryRun(options?: { only?: readonly string[] }): Promise<AuditExportDryRun>;
  status(): Promise<AuditExportStatus>;
}

const RESET_WARNING = 'Saved export progress was unreadable, so every target starts from the first entry again; receivers deduplicate by seq.';
const DESTINATION_WARNING = 'The destination changed, so the whole log is sent to it from the first entry.';
const SAVE_FAILED = 'Export progress could not be saved; the last batch will be sent again next time (receivers deduplicate by seq).';

function replacedLog(id: string): string {
  return `The audit log no longer matches what was already exported to ${id}, so nothing was sent there. If this log was replaced on purpose, give the target a new id in keysentry.yaml to export it from the start.`;
}

function freshCursor(target: AuditExportTarget): TargetCursor {
  return { destination: destinationDigest(target), seq: 0, failures: 0 };
}

export function createAuditExporter(options: AuditExporterOptions): AuditExporter {
  const limits = { ...DEFAULT_EXPORT_LIMITS, ...options.limits };
  if (Object.values(limits).some(value => !Number.isSafeInteger(value) || value < 0) || limits.maxRecords < 1 || limits.maxBytes < 1
    || limits.maxBatchesPerRun < 1 || limits.maxAttempts < 1) throw new TypeError('Audit export limits must be positive whole numbers.');
  const now = options.now ?? (() => new Date());
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms)));
  const sourceId = options.sourceId ?? 'keysentry';
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(sourceId)) throw new TypeError('The audit export source id must use letters, digits, "_" or "-".');
  const ids = new Set<string>();
  for (const target of options.targets) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(target.id) || ids.has(target.id)) throw new TypeError('Audit export target ids must be unique and use letters, digits, "_" or "-".');
    ids.add(target.id);
  }

  /** `logId` names this log instance (its first entry's hash), so a recreated log is never mistaken for its predecessor. */
  function sinkFor(target: AuditExportTarget, snapshot?: AuditSnapshot): ExportSink {
    const first = snapshot?.hashAt(1);
    const log = first ? { logId: first.slice(0, 16) } : {};
    switch (target.kind) {
      case 'syslog': return createSyslogSink(target, { connector: options.tls, ...(options.hostname ? { hostname: options.hostname } : {}), ...log });
      case 'otlp': return createOtlpSink(target, { http: options.httpFor?.(target) ?? options.http, vault: options.vault, now, sourceId,
        singleHost: options.httpFor !== undefined, ...log });
      case 's3': return createS3Sink(target, { http: options.httpFor?.(target) ?? options.http, vault: options.vault, now, sourceId, ...log });
      case 'webhook': return createWebhookSink(target, { http: options.httpFor?.(target) ?? options.http, vault: options.vault, now, sourceId,
        signingKey: options.signingKey, ...log });
    }
  }

  const macKey = options.macKey ?? (() => options.vault.get('audit/mac'));
  const CHANGED = 'The audit log changed while it was being read for export, so nothing was exported. Run keysentry audit verify.';

  /**
   * Whether every entry read carries a valid MAC under the audit key. verify() and the read are two reads of the file,
   * and the reader's unkeyed hash chain can be recomputed by anyone, so the bytes about to be sent are authenticated
   * themselves (review L2). Same MAC as src/security/audit.ts: HMAC-SHA256(key, chain hash as hex text).
   */
  async function authenticated(snapshot: AuditSnapshot): Promise<boolean> {
    if (snapshot.entries === 0) return true;
    if (!snapshot.macAt) return false;
    const key = await macKey();
    if (!key || key.length !== 32) {
      key?.fill(0);
      throw new AuditExportRefusedError('The audit log key is not available here, so the entries read for export could not be checked and nothing was exported. Run keysentry audit verify.');
    }
    try {
      for (let seq = 1; seq <= snapshot.entries; seq++) {
        const hash = snapshot.hashAt(seq), mac = snapshot.macAt(seq);
        if (!hash || !mac || !/^[0-9a-f]{64}$/.test(mac)) return false;
        if (!timingSafeEqual(Buffer.from(mac, 'hex'), createHmac('sha256', key).update(hash, 'utf8').digest())) return false;
      }
      return true;
    } finally { key.fill(0); }
  }

  /**
   * Verify, read the verified prefix (re-checking its chain and every entry's MAC), then verify again: nothing
   * unverified is ever sent. Entries that fail their MAC mean the file changed between the reads: try again a few
   * times, then refuse.
   */
  async function verifiedSnapshot(): Promise<AuditSnapshot> {
    for (let attempt = 1; ; attempt++) {
      const first = await options.audit.verify();
      if (!first.ok) {
        throw new AuditExportRefusedError(`The audit log did not verify, so nothing was exported${first.problem ? `: ${first.problem}` : '.'} Run keysentry audit verify.`);
      }
      const snapshot = await options.reader.load(first.entries);
      const second = await options.audit.verify();
      if (!second.ok || second.entries < first.entries) throw new AuditExportRefusedError(CHANGED);
      if (await authenticated(snapshot)) return snapshot;
      if (attempt >= 3) throw new AuditExportRefusedError(CHANGED);
    }
  }

  function batches(records: readonly AuditExportRecord[], from: number, maxBatches: number): AuditExportRecord[][] {
    const result: AuditExportRecord[][] = [];
    let index = from;
    while (index < records.length && result.length < maxBatches) {
      const batch: AuditExportRecord[] = [];
      let bytes = 0;
      while (index < records.length && batch.length < limits.maxRecords) {
        const size = Buffer.byteLength(canonicalJson(records[index])) + 1;
        if (batch.length && bytes + size > limits.maxBytes) break;
        batch.push(records[index]!);
        bytes += size;
        index++;
      }
      result.push(batch);
    }
    return result;
  }

  function selected(only?: readonly string[]): AuditExportTarget[] {
    if (!only?.length) return [...options.targets];
    const unknown = only.filter(id => !ids.has(id));
    if (unknown.length) throw new TypeError('Choose audit export target ids from keysentry.yaml.');
    return options.targets.filter(target => only.includes(target.id));
  }

  /** Where a target stands against this snapshot; null cursor means it must not be sent to. */
  function position(target: AuditExportTarget, state: AuditExportState, snapshot: AuditSnapshot):
    { cursor: TargetCursor; warning?: string; refusal?: string } {
    const saved = state.targets[target.id];
    if (!saved) return { cursor: freshCursor(target) };
    if (saved.destination !== destinationDigest(target)) return { cursor: freshCursor(target), warning: DESTINATION_WARNING };
    if (saved.seq > snapshot.entries || (saved.seq > 0 && saved.anchor !== undefined && snapshot.hashAt(saved.seq) !== saved.anchor)) {
      return { cursor: { ...saved }, refusal: replacedLog(target.id) };
    }
    return { cursor: { ...saved } };
  }

  function cooldownUntil(cursor: TargetCursor): number | undefined {
    if (!cursor.failures || !cursor.lastAttemptAt) return undefined;
    const wait = Math.min(limits.maxCooldownMs, 60_000 * 2 ** Math.min(cursor.failures - 1, 20));
    return Date.parse(cursor.lastAttemptAt) + wait;
  }

  function delayFor(error: AuditExportError, attempt: number): number | null {
    if (error.retryAfterMs !== undefined) return error.retryAfterMs > limits.maxRetryAfterMs ? null : error.retryAfterMs;
    return Math.min(limits.maxDelayMs, limits.baseDelayMs * 2 ** (attempt - 1));
  }

  return {
    async run(runOptions = {}) {
      const targets = selected(runOptions.only);
      const snapshot = await verifiedSnapshot();
      const loaded = parseExportState(await options.state.load());
      const state = loaded.state;
      // One writer at a time; each save merges with what is stored so a concurrent run can only cause duplicates.
      let saving = Promise.resolve();
      const save = (id: string, cursor: TargetCursor) => {
        const run = saving.then(async () => {
          const current = parseExportState(await options.state.load()).state;
          const stored = current.targets[id];
          const storedHash = stored ? snapshot.hashAt(stored.seq) : undefined;
          // Another run got further with the same log and destination: keep its position (never move backwards).
          const keepStored = stored !== undefined && storedHash !== undefined && stored.destination === cursor.destination
            && stored.seq > cursor.seq && (stored.anchor === undefined || stored.anchor === storedHash);
          current.targets[id] = keepStored ? { ...cursor, seq: stored.seq, anchor: storedHash } : { ...cursor };
          await options.state.save(current);
          state.targets[id] = current.targets[id]!;
        });
        saving = run.catch(() => {});
        return run;
      };

      const results = await Promise.all(targets.map(async (target): Promise<TargetRunResult> => {
        const sink = sinkFor(target, snapshot);
        const base = { id: target.id, kind: target.kind, destination: sink.destination };
        const place = position(target, state, snapshot);
        const cursor = place.cursor;
        const warnings = [...(loaded.reset ? [RESET_WARNING] : []), ...(place.warning ? [place.warning] : [])];
        const pending = () => Math.max(0, snapshot.entries - cursor.seq);
        if (place.refusal) return { ...base, status: 'refused', sent: 0, batches: 0, cursor: cursor.seq, pending: 0, error: place.refusal, warnings };
        const until = cooldownUntil(cursor);
        if (!runOptions.force && until !== undefined && until > now().getTime() && pending() > 0) {
          return { ...base, status: 'waiting', sent: 0, batches: 0, cursor: cursor.seq, pending: pending(),
            error: `Waiting until ${new Date(until).toISOString()} after ${cursor.failures} failed attempts: ${cursor.lastError ?? 'delivery failed'}`, warnings };
        }
        if (pending() === 0) {
          if (place.warning) { delete cursor.warning; await save(target.id, cursor).catch(() => {}); }
          return { ...base, status: 'up-to-date', sent: 0, batches: 0, cursor: cursor.seq, pending: 0, warnings };
        }
        cursor.lastAttemptAt = now().toISOString();
        let sent = 0, count = 0, firstSeq: number | undefined, lastSeq: number | undefined;
        try {
          for (const batch of batches(snapshot.records, cursor.seq, limits.maxBatchesPerRun)) {
            let attempt = 0;
            for (;;) {
              attempt++;
              try {
                const outcome = await sink.deliver(batch);
                if (outcome.warnings?.length) warnings.push(...outcome.warnings);
                break;
              } catch (error) {
                const failure = error instanceof AuditExportError ? error : new AuditExportError('Delivery failed unexpectedly.', true);
                const delay = failure.retryable && attempt < limits.maxAttempts ? delayFor(failure, attempt) : null;
                if (delay === null) throw failure;
                await sleep(delay);
              }
            }
            const last = batch.at(-1)!;
            cursor.seq = last.seq;
            cursor.anchor = snapshot.hashAt(last.seq)!;
            cursor.failures = 0;
            cursor.lastSuccessAt = now().toISOString();
            delete cursor.lastError;
            if (warnings.length) cursor.warning = warnings.at(-1)!.slice(0, 500); else delete cursor.warning;
            sent += batch.length; count++;
            firstSeq ??= batch[0]!.seq; lastSeq = last.seq;
            try { await save(target.id, cursor); }
            catch { return { ...base, status: 'failed', sent, batches: count, firstSeq, lastSeq, cursor: cursor.seq, pending: pending(), error: SAVE_FAILED, warnings }; }
          }
          return { ...base, status: 'sent', sent, batches: count, ...(firstSeq === undefined ? {} : { firstSeq, lastSeq }),
            cursor: cursor.seq, pending: pending(), warnings };
        } catch (error) {
          const message = error instanceof AuditExportError ? error.message : 'Delivery failed unexpectedly.';
          cursor.failures++;
          cursor.lastError = message.slice(0, 500);
          await save(target.id, cursor).catch(() => {});
          return { ...base, status: 'failed', sent, batches: count, ...(firstSeq === undefined ? {} : { firstSeq, lastSeq }),
            cursor: cursor.seq, pending: pending(), error: message, warnings };
        } finally { sink.dispose(); }
      }));
      await saving;
      return { entries: snapshot.entries, targets: results };
    },

    async dryRun(runOptions = {}) {
      const targets = selected(runOptions.only);
      const snapshot = await verifiedSnapshot();
      const loaded = parseExportState(await options.state.load());
      const result: TargetDryRun[] = [];
      for (const target of targets) {
        const sink = sinkFor(target, snapshot);
        try {
          const place = position(target, loaded.state, snapshot);
          const notes = [...(loaded.reset ? [RESET_WARNING] : []), ...(place.warning ? [place.warning] : []), ...(place.refusal ? [place.refusal] : [])];
          const fields = EXPORT_SECRET_FIELDS[target.kind];
          let credentials: TargetDryRun['credentials'] = 'not needed';
          if (target.kind === 'webhook' && target.signing === 'ed25519') credentials = 'device key';
          else if (fields.length) {
            // Presence only, from names: no credential value is read for a dry run.
            const names = new Set(await options.vault.list(`audit-export/${target.id}/`));
            const required: ExportSecretField[] = target.kind === 's3' ? ['access-key-id', 'secret-access-key'] : target.kind === 'webhook' ? ['hmac-secret'] : [];
            credentials = required.every(field => names.has(exportSecretName(target.id, field))) ? 'present' : 'missing';
          }
          const planned = place.refusal ? [] : batches(snapshot.records, place.cursor.seq, limits.maxBatchesPerRun);
          const described: DryRunBatch[] = [];
          for (const batch of planned) {
            try {
              const preview = sink.preview(batch);
              described.push({ firstSeq: batch[0]!.seq, lastSeq: batch.at(-1)!.seq, records: batch.length, ...preview });
            } catch (error) {
              notes.push(error instanceof AuditExportError ? error.message : 'This batch could not be prepared.');
              break;
            }
          }
          const remaining = snapshot.records.slice(place.cursor.seq);
          if (planned.length && planned.flat().length < remaining.length) notes.push('Further entries wait for the next run, in order.');
          result.push({ id: target.id, kind: target.kind, destination: sink.destination, cursor: place.cursor.seq,
            pending: place.refusal ? 0 : Math.max(0, snapshot.entries - place.cursor.seq), credentials, batches: described,
            preview: (planned[0] ?? []).slice(0, 20).map(({ seq, at, kind, summary }) => ({ seq, at, kind, summary })), notes });
        } finally { sink.dispose(); }
      }
      return { entries: snapshot.entries, targets: result };
    },

    async status() {
      const verification = await options.audit.verify();
      const loaded = parseExportState(await options.state.load());
      const targets: TargetStatus[] = [];
      for (const target of options.targets) {
        const sink = sinkFor(target);
        sink.dispose();
        const saved = loaded.state.targets[target.id];
        const cursor = saved && saved.destination === destinationDigest(target) ? saved : freshCursor(target);
        const until = cooldownUntil(cursor);
        const entry: TargetStatus = { id: target.id, kind: target.kind, destination: sink.destination, cursor: cursor.seq,
          pending: Math.max(0, verification.entries - cursor.seq), failures: cursor.failures,
          ...(cursor.lastAttemptAt ? { lastAttemptAt: cursor.lastAttemptAt } : {}),
          ...(cursor.lastSuccessAt ? { lastSuccessAt: cursor.lastSuccessAt } : {}),
          ...(cursor.lastError ? { lastError: cursor.lastError } : {}),
          ...(cursor.warning ? { warning: cursor.warning } : {}),
          ...(until !== undefined && until > now().getTime() ? { nextAttemptAt: new Date(until).toISOString() } : {}) };
        if (target.kind === 'webhook' && target.signing === 'ed25519') {
          // Every key that may sign this project's batches (review M3): this device's, then each deployed watcher's
          // and cloud box's that this computer knows. A deployed watcher signs with its own key, never this one.
          const keys: NonNullable<TargetStatus['publicKeys']> = [];
          const add = (signer: string, publicKeyDer: Buffer) => {
            let whpk: string;
            try {
              if (createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' }).asymmetricKeyType !== 'ed25519') return;
              whpk = webhookPublicKey(publicKeyDer);
            } catch { return; }
            const keyId = createHash('sha256').update(publicKeyDer).digest('hex').slice(0, 16);
            if (!keys.some(key => key.keyId === keyId)) keys.push({ signer, keyId, whpk, spkiDerBase64: publicKeyDer.toString('base64') });
          };
          try {
            const key = await options.signingKey();
            try {
              entry.publicKey = { keyId: key.keyId, whpk: webhookPublicKey(key.publicKeyDer), spkiDerBase64: key.publicKeyDer.toString('base64') };
              add('this computer', key.publicKeyDer);
            } finally { key.privateKeyDer.fill(0); }
          } catch { entry.warning ??= 'The device signing key is unavailable, so its public key cannot be shown.'; }
          try { for (const other of await options.otherSigningKeys?.() ?? []) add(other.signer, other.publicKeyDer); }
          catch { entry.warning ??= 'The public keys of deployed watchers could not be read, so only this computer\'s key is shown.'; }
          if (keys.length) entry.publicKeys = keys;
        }
        targets.push(entry);
      }
      return { entries: verification.entries, verified: verification.ok, ...(verification.problem ? { problem: verification.problem } : {}), targets };
    },
  };
}
