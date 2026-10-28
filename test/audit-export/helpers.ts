import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAuditFileReader } from '../../src/audit-export/index.js';
import type { AuditExportState, AuditExportStateStore, SyslogConnection, SyslogConnector } from '../../src/audit-export/index.js';
import { AuditExportError } from '../../src/audit-export/index.js';
import { createAuditLog, generateDeviceKey } from '../../src/security/index.js';
import type { AuditExportRecord } from '../../src/types.js';
import { createFakeVault } from '../helpers/fake-vault.js';

const dirs: string[] = [];
export async function cleanupDirs(): Promise<void> {
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
}

/** A real tamper-evident audit log with `count` entries, an injected clock and an in-memory vault. */
export async function auditFixture(count: number, opts: { checkpointEvery?: number; start?: string } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-audit-export-'));
  dirs.push(dir);
  const vault = createFakeVault();
  const key = generateDeviceKey();
  const path = join(dir, 'audit.jsonl');
  let clock = Date.parse(opts.start ?? '2026-10-28T10:00:00.000Z');
  const now = () => new Date(clock += 1000);
  const audit = createAuditLog({ path, vault, now, checkpointEvery: opts.checkpointEvery ?? 1000,
    deviceKey: async () => ({ ...key, privateKeyDer: Buffer.from(key.privateKeyDer) }) });
  const append = async (n: number, kind = 'scan') => {
    for (let index = 0; index < n; index++) await audit.append({ kind, summary: `Event ${index + 1}`, data: { n: index + 1 } });
  };
  await append(count);
  return {
    dir, vault, key, path, audit, append, reader: createAuditFileReader(path),
    signingKey: async () => ({ ...key, privateKeyDer: Buffer.from(key.privateKeyDer) }),
  };
}

/** In-memory export progress; `failSaves` makes the next N saves throw, like a crash before the cursor is stored. */
export function memoryState(initial: unknown = null) {
  let saved: unknown = initial === null ? null : structuredClone(initial);
  const control = { failSaves: 0, saves: 0 };
  const store: AuditExportStateStore = {
    load: async () => saved === null ? null : structuredClone(saved),
    save: async (state: AuditExportState) => {
      if (control.failSaves > 0) { control.failSaves--; throw new Error('disk full'); }
      control.saves++;
      saved = structuredClone(state);
    },
  };
  return { store, control, get: () => saved as AuditExportState | null, set: (value: unknown) => { saved = structuredClone(value); } };
}

/** Syslog connector fake: records each delivered batch as the records it carried (parsed back from the frames). */
export function fakeSyslog() {
  const deliveries: number[][] = [];
  const control = { failures: 0, retryable: true };
  const connector: SyslogConnector = {
    async connect() {
      if (control.failures > 0) { control.failures--; throw new AuditExportError('Could not connect to the syslog server over TLS.', control.retryable); }
      let data = Buffer.alloc(0);
      const connection: SyslogConnection = {
        async write(bytes) { data = Buffer.concat([data, bytes]); },
        async close() { deliveries.push(parseFrames(data).map(message => Number(/ seq="(\d+)"/.exec(message)![1]))); },
        destroy() {},
      };
      return connection;
    },
  };
  return { connector, deliveries, control };
}

/** Splits RFC 5425 octet-counted frames: MSG-LEN SP SYSLOG-MSG, repeated. */
export function parseFrames(data: Buffer): string[] {
  const messages: string[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const length = Number(data.subarray(offset, space).toString('ascii'));
    if (!Number.isSafeInteger(length) || length <= 0) throw new Error('bad frame');
    messages.push(data.subarray(space + 1, space + 1 + length).toString('utf8'));
    offset = space + 1 + length;
  }
  return messages;
}

export const sampleRecord = (seq: number, extra: Partial<AuditExportRecord> = {}): AuditExportRecord =>
  ({ seq, at: `2026-10-28T10:00:${String(seq % 60).padStart(2, '0')}.000Z`, kind: 'scan', summary: `Event ${seq}`, data: { n: seq }, ...extra });

/** For `.then(unexpected, error => error)`: a promise that should have rejected but resolved fails the test. */
export const unexpected = (): never => { throw new Error('Expected a rejection.'); };
