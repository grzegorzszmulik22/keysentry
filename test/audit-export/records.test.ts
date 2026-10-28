import { readFile, writeFile } from 'node:fs/promises';
import { afterEach, describe, expect, it } from 'vitest';
import { AuditExportRefusedError, createAuditFileReader, parseAuditLines, toExportRecord } from '../../src/audit-export/index.js';
import { createRedactor } from '../../src/core/redact.js';
import { auditFixture, cleanupDirs } from './helpers.js';

afterEach(cleanupDirs);

describe('audit export records', () => {
  it('reads the verified prefix as value-free records in sequence order', async () => {
    const f = await auditFixture(3);
    await f.audit.checkpoint();
    const snapshot = await f.reader.load(4);
    expect(snapshot.records.map(record => record.seq)).toEqual([1, 2, 3, 4]);
    expect(snapshot.records[0]).toEqual({ seq: 1, at: '2026-10-28T10:00:01.000Z', kind: 'scan', summary: 'Event 1', data: { n: 1 } });
    expect(snapshot.records[3]!.kind).toBe('checkpoint');
    expect(Object.keys(snapshot.records[3]!.data!).sort()).toEqual(['head', 'keyId', 'sig']);
    // No chain internals (prev, hash, mac) leave in a record.
    for (const record of snapshot.records) expect(Object.keys(record).every(key => ['seq', 'at', 'kind', 'summary', 'data', 'actor'].includes(key))).toBe(true);
    expect(snapshot.hashAt(2)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('reads only the requested prefix even when more entries follow', async () => {
    const f = await auditFixture(5);
    expect((await f.reader.load(2)).records.map(record => record.seq)).toEqual([1, 2]);
  });

  it('refuses a log that is shorter than the verified count or whose chain was edited', async () => {
    const f = await auditFixture(3);
    await expect(f.reader.load(4)).rejects.toBeInstanceOf(AuditExportRefusedError);
    const text = await readFile(f.path, 'utf8');
    await writeFile(f.path, text.replace('Event 2', 'Event X'));
    await expect(f.reader.load(3)).rejects.toThrow('changed while it was being read');
    const lines = text.trimEnd().split('\n');
    expect(() => parseAuditLines([lines[0], lines[2], lines[1]].join('\n'), 3)).toThrow(AuditExportRefusedError);
  });

  it('treats a missing log as empty and refuses a missing log that should have entries', async () => {
    const reader = createAuditFileReader('Z:/definitely/missing/audit.jsonl');
    expect((await reader.load(0)).records).toEqual([]);
    await expect(reader.load(1)).rejects.toBeInstanceOf(AuditExportRefusedError);
  });

  it('masks values registered in this process and known key formats, keys included', () => {
    const redactor = createRedactor();
    redactor.register('registered-value-123456');
    const record = toExportRecord({ seq: 7, at: '2026-10-28T10:00:00.000Z', kind: 'vault-set', summary: 'Stored registered-value-123456',
      data: { name: 'OPENAI_API_KEY', nested: [{ token: 'registered-value-123456' }], ['registered-value-123456']: true } }, redactor);
    const text = JSON.stringify(record);
    expect(text).not.toContain('registered-value-123456');
    expect(record.data!.name).toBe('OPENAI_API_KEY');
  });

  it('keeps a "__proto__" data key as an ordinary field and names the actor when data carries one', () => {
    const data = JSON.parse('{"__proto__":{"polluted":true},"memberId":"ana"}') as Record<string, unknown>;
    const record = toExportRecord({ seq: 1, at: '2026-10-28T10:00:00.000Z', kind: 'approval', summary: 'Approved.', data });
    expect(Object.getPrototypeOf(record.data)).toBe(Object.prototype);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(record.actor).toBe('ana');
    expect(toExportRecord({ seq: 2, at: 'x', kind: 'k', summary: 's', data: { actor: 'device:abc' } }).actor).toBe('device:abc');
    expect(toExportRecord({ seq: 3, at: 'x', kind: 'k', summary: 's', data: { memberId: 'Not Valid!' } }).actor).toBeUndefined();
  });
});
