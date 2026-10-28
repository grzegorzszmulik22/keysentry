import { readFile, writeFile } from 'node:fs/promises';
import { afterEach, describe, expect, it } from 'vitest';
import {
  AuditExportRefusedError, createAuditExporter, destinationDigest, type AuditExporterOptions, type AuditExportTarget,
} from '../../src/audit-export/index.js';
import { FakeHttp, text } from '../helpers/fake-http.js';
import { auditFixture, cleanupDirs, fakeSyslog, memoryState } from './helpers.js';

afterEach(cleanupDirs);

const syslog: AuditExportTarget = { kind: 'syslog', id: 'siem', host: 'syslog.example.com', port: 6514, appName: 'keysentry' };
const hook: AuditExportTarget = { kind: 'webhook', id: 'hook', url: 'https://hooks.example.com/audit', signing: 'ed25519' };
const lake: AuditExportTarget = { kind: 's3', id: 'lake', endpoint: 'https://s3.eu-west-1.amazonaws.com', bucket: 'audit-bucket', region: 'eu-west-1', prefix: 'k/' };
const S3_SECRET = 'lake-secret-access-key-Vb93Lq';

/** Webhook receiver fake: records the seqs of each accepted batch; `statuses` scripts responses before 200s. */
function webhookReceiver(statuses: number[] = []) {
  const deliveries: number[][] = [];
  const http = new FakeHttp().on('POST', /hooks\.example\.com/, request => {
    const status = statuses.shift() ?? 200;
    if (status === 200) deliveries.push((JSON.parse(request.body!) as { data: { records: { seq: number }[] } }).data.records.map(record => record.seq));
    return text(status, '', status === 429 ? { 'retry-after': '2' } : {});
  });
  return { http, deliveries };
}

async function setup(count: number, targets: AuditExportTarget[], extra: Partial<AuditExporterOptions> = {}, start?: string) {
  const f = await auditFixture(count, start ? { start } : {});
  const state = memoryState();
  const tls = fakeSyslog();
  const receiver = webhookReceiver();
  const sleeps: number[] = [];
  let clock = Date.parse('2026-10-28T12:00:00.000Z');
  const options: AuditExporterOptions = {
    targets, audit: f.audit, reader: f.reader, http: receiver.http, tls: tls.connector, vault: f.vault, signingKey: f.signingKey,
    state: state.store, now: () => new Date(clock), sleep: async ms => { sleeps.push(ms); }, sourceId: 'src', hostname: 'h', ...extra,
  };
  return { f, state, tls, receiver, sleeps, options, exporter: createAuditExporter(options), advance: (ms: number) => { clock += ms; } };
}

/** Every seq 1..n delivered at least once, and the first delivery of each seq happens in order. */
function expectNoGaps(deliveries: number[][], n: number) {
  const flat = deliveries.flat();
  expect([...new Set(flat)].sort((a, b) => a - b)).toEqual(Array.from({ length: n }, (_, index) => index + 1));
  const firstSeen = [...new Set(flat)];
  expect(firstSeen).toEqual([...firstSeen].sort((a, b) => a - b));
}

describe('audit exporter', () => {
  it('sends every verified entry in order, in batches, and saves a cursor per target', async () => {
    const s = await setup(5, [syslog, hook], { limits: { maxRecords: 2 } });
    const result = await s.exporter.run();
    expect(result.entries).toBe(5);
    expect(result.targets.map(target => [target.id, target.status, target.sent, target.batches, target.cursor, target.pending]))
      .toEqual([['siem', 'sent', 5, 3, 5, 0], ['hook', 'sent', 5, 3, 5, 0]]);
    expect(s.tls.deliveries).toEqual([[1, 2], [3, 4], [5]]);
    expect(s.receiver.deliveries).toEqual([[1, 2], [3, 4], [5]]);
    const saved = s.state.get()!;
    expect(saved.targets.siem).toMatchObject({ seq: 5, failures: 0, destination: destinationDigest(syslog) });
    expect(saved.targets.siem!.anchor).toMatch(/^[0-9a-f]{64}$/);

    const again = await s.exporter.run();
    expect(again.targets.map(target => target.status)).toEqual(['up-to-date', 'up-to-date']);
    await s.f.append(2, 'approval');
    const more = await s.exporter.run();
    expect(more.targets.map(target => [target.sent, target.firstSeq, target.lastSeq])).toEqual([[2, 6, 7], [2, 6, 7]]);
    expect(s.tls.deliveries.at(-1)).toEqual([6, 7]);
  });

  it('refuses a log that does not verify, sends nothing and keeps the saved progress', async () => {
    const s = await setup(4, [syslog, hook]);
    await s.exporter.run();
    const before = JSON.stringify(s.state.get());
    await s.f.append(1);
    const text = await readFile(s.f.path, 'utf8');
    await writeFile(s.f.path, text.replace('"summary":"Event 2"', '"summary":"Event two"'));
    const error = await s.exporter.run().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(AuditExportRefusedError);
    expect((error as Error).message).toMatch(/^The audit log did not verify, so nothing was exported: .+ Run keysentry audit verify\.$/);
    expect(s.tls.deliveries).toHaveLength(1);
    expect(s.receiver.deliveries).toHaveLength(1);
    expect(JSON.stringify(s.state.get())).toBe(before);
    await expect(s.exporter.dryRun()).rejects.toBeInstanceOf(AuditExportRefusedError);
  });

  it('refuses when the log changes between verification and reading', async () => {
    const s = await setup(3, [syslog]);
    let calls = 0;
    const audit = { verify: async () => { calls++; const result = await s.f.audit.verify(); return calls === 2 ? { ...result, ok: false } : result; } };
    await expect(createAuditExporter({ ...s.options, audit }).run()).rejects.toThrow('changed while it was being read');
    expect(s.tls.deliveries).toEqual([]);
  });

  it('resumes after a crash between send and cursor save: duplicates are allowed, gaps never', async () => {
    const s = await setup(6, [syslog, hook], { limits: { maxRecords: 2 } });
    s.state.control.failSaves = 1;
    const crashed = await s.exporter.run();
    // The first save failed: one target stops after its first batch; the cursor stays where it was stored.
    expect(crashed.targets.some(target => target.status === 'failed' && target.error?.includes('could not be saved'))).toBe(true);
    const resumed = await s.exporter.run();
    expect(resumed.targets.every(target => target.cursor === 6 && target.pending === 0)).toBe(true);
    expectNoGaps(s.tls.deliveries, 6);
    expectNoGaps(s.receiver.deliveries, 6);
    const all = [...s.tls.deliveries.flat(), ...s.receiver.deliveries.flat()];
    expect(all.length).toBeGreaterThan(12);
  });

  it('resumes from the stored cursor when a run dies after sending (simulated by discarding the run\'s saves)', async () => {
    const s = await setup(4, [syslog], { limits: { maxRecords: 1 } });
    await s.exporter.run();
    s.state.set(null);
    s.tls.deliveries.length = 0;
    await s.f.append(1);
    await s.exporter.run();
    expect(s.tls.deliveries).toEqual([[1], [2], [3], [4], [5]]);
  });

  it('isolates a failing target: others deliver everything, the failing one keeps its cursor and retries with backoff', async () => {
    const s = await setup(3, [syslog, hook]);
    const failing = webhookReceiver([500, 500, 500]);
    const exporter = createAuditExporter({ ...s.options, http: failing.http });
    const result = await exporter.run();
    const [siem, webhook] = result.targets;
    expect(siem).toMatchObject({ status: 'sent', sent: 3, cursor: 3 });
    expect(webhook).toMatchObject({ status: 'failed', sent: 0, cursor: 0, pending: 3, error: 'The webhook receiver answered HTTP 500.' });
    expect(s.sleeps).toEqual([1000, 2000]);
    expect(s.state.get()!.targets.hook).toMatchObject({ seq: 0, failures: 1, lastError: 'The webhook receiver answered HTTP 500.' });

    // A watcher run during the cooldown skips it; a forced run (the CLI) tries again and catches up.
    const waiting = await exporter.run();
    expect(waiting.targets[1]).toMatchObject({ status: 'waiting', pending: 3 });
    const forced = await exporter.run({ force: true });
    expect(forced.targets[1]).toMatchObject({ status: 'sent', sent: 3, cursor: 3 });
    expect(failing.deliveries).toEqual([[1, 2, 3]]);
    expect(s.state.get()!.targets.hook).toMatchObject({ seq: 3, failures: 0 });
    expect(s.state.get()!.targets.hook!.lastError).toBeUndefined();
  });

  it('ends the cooldown after its wait, and does not retry non-retryable failures within a run', async () => {
    const s = await setup(2, [hook]);
    const receiver = webhookReceiver([400]);
    const exporter = createAuditExporter({ ...s.options, http: receiver.http });
    expect((await exporter.run()).targets[0]).toMatchObject({ status: 'failed', error: 'The webhook receiver answered HTTP 400.' });
    expect(s.sleeps).toEqual([]);
    s.advance(61_000);
    expect((await exporter.run()).targets[0]).toMatchObject({ status: 'sent', sent: 2 });
  });

  it('honours Retry-After within the limit', async () => {
    const s = await setup(1, [hook]);
    const receiver = webhookReceiver([429]);
    const result = await createAuditExporter({ ...s.options, http: receiver.http }).run();
    expect(result.targets[0]).toMatchObject({ status: 'sent', sent: 1 });
    expect(s.sleeps).toEqual([2000]);
  });

  it('limits the batches per run; the rest follows on the next run, in order', async () => {
    const s = await setup(7, [syslog], { limits: { maxRecords: 2, maxBatchesPerRun: 2 } });
    expect((await s.exporter.run()).targets[0]).toMatchObject({ status: 'sent', sent: 4, pending: 3 });
    expect((await s.exporter.run()).targets[0]).toMatchObject({ status: 'sent', sent: 3, pending: 0 });
    expect(s.tls.deliveries).toEqual([[1, 2], [3, 4], [5, 6], [7]]);
  });

  it('splits batches by encoded size as well as count', async () => {
    const s = await setup(4, [syslog], { limits: { maxBytes: 200 } });
    await s.exporter.run();
    expect(s.tls.deliveries.length).toBeGreaterThan(1);
    expectNoGaps(s.tls.deliveries, 4);
  });

  it('starts a changed destination from the first entry, and says so', async () => {
    const s = await setup(3, [syslog]);
    await s.exporter.run();
    const moved = createAuditExporter({ ...s.options, targets: [{ ...syslog, host: 'syslog2.example.com' }] });
    const result = await moved.run();
    expect(result.targets[0]).toMatchObject({ status: 'sent', sent: 3, firstSeq: 1 });
    expect(result.targets[0]!.warnings).toContain('The destination changed, so the whole log is sent to it from the first entry.');
  });

  it('refuses a target whose saved position does not match this log (a replaced log)', async () => {
    const s = await setup(3, [syslog]);
    await s.exporter.run();
    const saved = s.state.get()!;
    s.state.set({ ...saved, targets: { siem: { ...saved.targets.siem!, anchor: 'f'.repeat(64) } } });
    const result = await s.exporter.run();
    expect(result.targets[0]).toMatchObject({ status: 'refused', sent: 0 });
    expect(result.targets[0]!.error).toContain('no longer matches what was already exported to siem');
    s.state.set({ ...saved, targets: { siem: { ...saved.targets.siem!, seq: 99 } } });
    expect((await s.exporter.run()).targets[0]!.status).toBe('refused');
    expect(s.tls.deliveries).toHaveLength(1);
  });

  it('restarts from the first entry when saved progress is unreadable', async () => {
    const s = await setup(2, [syslog]);
    s.state.set({ v: 2, nonsense: true });
    const result = await s.exporter.run();
    expect(result.targets[0]).toMatchObject({ status: 'sent', sent: 2, firstSeq: 1 });
    expect(result.targets[0]!.warnings[0]).toContain('starts from the first entry again');
  });

  it('never moves a cursor backwards when another run already got further', async () => {
    const s = await setup(4, [syslog], { limits: { maxRecords: 1 } });
    await s.exporter.run();
    const ahead = s.state.get()!;
    // A concurrent run (say, the watcher) loaded progress before the first run saved: it starts at seq 1 and
    // stops after one batch. Its save must not pull the stored cursor back from 4 to 2.
    const stale = { ...ahead, targets: { siem: { ...ahead.targets.siem!, seq: 1, anchor: undefined } } };
    let first = true;
    const racing = createAuditExporter({ ...s.options, limits: { maxRecords: 1, maxBatchesPerRun: 1 },
      state: { load: async () => { if (first) { first = false; return stale; } return s.state.store.load(); }, save: s.state.store.save } });
    const result = await racing.run();
    expect(result.targets[0]).toMatchObject({ sent: 1, firstSeq: 2 });
    expect(s.state.get()!.targets.siem).toMatchObject({ seq: 4, anchor: ahead.targets.siem!.anchor });
  });

  it('keeps every secret out of records, results, saved progress and errors', async () => {
    const s = await setup(2, [lake, hook]);
    await s.f.vault.set('audit-export/lake/access-key-id', Buffer.from('AKIAEXPORTTEST0000002'));
    await s.f.vault.set('audit-export/lake/secret-access-key', Buffer.from(S3_SECRET));
    const http = new FakeHttp()
      .on('PUT', /amazonaws/, () => text(403, `<Error><Message>Signature ${S3_SECRET}</Message></Error>`))
      .on('POST', /hooks/, () => text(500, `echo ${S3_SECRET}`));
    const result = await createAuditExporter({ ...s.options, http }).run();
    expect(result.targets.map(target => target.status)).toEqual(['failed', 'failed']);
    const visible = JSON.stringify([result, s.state.get()]);
    expect(visible).not.toContain(S3_SECRET);
    expect(visible).not.toContain(Buffer.from(s.f.key.privateKeyDer).toString('base64'));
    for (const call of http.calls) expect(call.body ?? '').not.toContain(S3_SECRET);
  });

  it('shows a dry run without contacting anything, reading credential values or saving progress', async () => {
    const s = await setup(3, [syslog, lake, hook], { limits: { maxRecords: 2 } });
    await s.f.vault.set('audit-export/lake/access-key-id', Buffer.from('AKIAEXPORTTEST0000003'));
    const reads: string[] = [];
    const vault = { ...s.f.vault, get: async (name: string) => { reads.push(name); return s.f.vault.get(name); } };
    let signed = false;
    const plan = await createAuditExporter({ ...s.options, vault, signingKey: async () => { signed = true; return s.options.signingKey(); } }).dryRun();
    expect(plan.entries).toBe(3);
    expect(plan.targets.map(target => [target.id, target.credentials, target.pending, target.batches.map(batch => `${batch.firstSeq}-${batch.lastSeq}`)]))
      .toEqual([['siem', 'not needed', 3, ['1-2', '3-3']], ['lake', 'missing', 3, ['1-2', '3-3']], ['hook', 'device key', 3, ['1-2', '3-3']]]);
    expect(plan.targets[1]!.batches[0]!.location).toBe('audit-bucket/k/2026/10/28/1-2.jsonl');
    expect(plan.targets[0]!.preview.map(record => record.seq)).toEqual([1, 2]);
    expect(reads.filter(name => name.startsWith('audit-export/'))).toEqual([]);
    expect(signed).toBe(false);
    expect(s.tls.deliveries).toEqual([]);
    expect(s.receiver.http.calls).toEqual([]);
    expect(s.state.get()).toBeNull();
  });

  it('reports status per target, with the public key webhook receivers check', async () => {
    const s = await setup(3, [syslog, hook]);
    const failing = webhookReceiver([503, 503, 503]);
    await createAuditExporter({ ...s.options, http: failing.http }).run();
    const status = await s.exporter.status();
    expect(status).toMatchObject({ entries: 3, verified: true });
    expect(status.targets[0]).toMatchObject({ id: 'siem', cursor: 3, pending: 0, failures: 0, lastSuccessAt: '2026-10-28T12:00:00.000Z' });
    expect(status.targets[1]).toMatchObject({ id: 'hook', cursor: 0, pending: 3, failures: 1, lastError: 'The webhook receiver answered HTTP 503.',
      nextAttemptAt: '2026-10-28T12:01:00.000Z' });
    expect(status.targets[1]!.publicKey).toEqual({ keyId: s.f.key.keyId, whpk: expect.stringMatching(/^whpk_/), spkiDerBase64: s.f.key.publicKeyDer.toString('base64') });
  });

  it('labels every envelope with the log identity, so a recreated log is never taken for its predecessor', async () => {
    const first = await setup(2, [hook]);
    await first.exporter.run();
    // The same project after its log was recreated (a fresh CI workspace): same source, new first entry.
    const second = await setup(2, [hook], {}, '2026-10-29T08:00:00.000Z');
    await second.exporter.run();
    const envelope = (s: typeof first) => {
      const call = s.receiver.http.calls[0]!;
      return { id: call.headers!['webhook-id']!, log: (JSON.parse(call.body!) as { data: { log: string } }).data.log };
    };
    const [a, b] = [envelope(first), envelope(second)];
    expect(a.log).toBe((await first.f.reader.load(1)).hashAt(1)!.slice(0, 16));
    expect(a.id).toBe(`src_${a.log}_1-2`);
    expect(a.log).not.toBe(b.log);
    expect(a.id).not.toBe(b.id);
  });

  it('validates target ids and the source id up front', async () => {
    const s = await setup(0, [syslog]);
    expect(() => createAuditExporter({ ...s.options, targets: [syslog, syslog] })).toThrow('unique');
    expect(() => createAuditExporter({ ...s.options, sourceId: 'has.dot' })).toThrow('source id');
    expect(() => createAuditExporter({ ...s.options, limits: { maxRecords: 0 } })).toThrow('limits');
    expect(() => createAuditExporter({ ...s.options, limits: { baseDelayMs: 0.5 } })).toThrow('limits');
    await expect(s.exporter.run({ only: ['nope'] })).rejects.toThrow('Choose audit export target ids');
    expect((await s.exporter.run()).targets[0]).toMatchObject({ status: 'up-to-date', cursor: 0 });
  });
});
