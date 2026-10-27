import { afterEach, describe, expect, it } from 'vitest';
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInFlightStore } from '../../src/core/inflight.js';
import { DecryptError } from '../../src/security/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';

const temporary: string[] = [];
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'keysentry-inflight-tail-'));
  temporary.push(root);
  const dir = join(root, 'inflight');
  const vault = createFakeVault();
  const reopen = () => createInFlightStore({ dir, vault, projectId: 'project1' });
  return { dir, vault, store: reopen(), reopen, path: join(dir, 'plan1.jsonl') };
}
afterEach(async () => { await Promise.all(temporary.splice(0).map(path => rm(path, { recursive: true, force: true }))); });

describe('in-flight record recovery', () => {
  it('keeps earlier one-time values readable after an unterminated final write', async () => {
    const { path, store, reopen } = await fixture();
    await store.put('plan1', 'old:c1', 'sk-proj-OLDVALUE0123456789abcdef');
    await store.put('plan1', 'new:c1', 'sk-proj-NEWVALUE0123456789abcdef');
    // Adapted from the independent M5 probe: the next append stops mid-envelope.
    await appendFile(path, 'S1MxAQ7x9kPq');
    const before = await readFile(path);

    const recovered = reopen();
    expect(await recovered.get('plan1', 'new:c1')).toBe('sk-proj-NEWVALUE0123456789abcdef');
    expect(await recovered.get('plan1', 'old:c1')).toBe('sk-proj-OLDVALUE0123456789abcdef');
    expect(await recovered.get('plan1', 'new:c2')).toBeNull();
    expect(await recovered.slots('plan1')).toEqual(['old:c1', 'new:c1']);
    expect(await readFile(path)).toEqual(before);
  });

  it('ignores even valid final ciphertext when its terminating newline was not written', async () => {
    const { path, store, reopen } = await fixture();
    await store.put('plan1', 'new:c1', 'durable-value');
    await store.put('plan1', 'new:c1', 'uncommitted-value');
    const records = await readFile(path);
    await writeFile(path, records.subarray(0, records.length - 1));

    const recovered = reopen();
    expect(await recovered.get('plan1', 'new:c1')).toBe('durable-value');
    expect(await recovered.slots('plan1')).toEqual(['new:c1']);
  });

  it.each(['S1MxAQ7x9kPq', 'partial-\u5c3e\ud83d\udd11'])('truncates torn bytes %j before the next durable append', async tail => {
    const { path, store, reopen } = await fixture();
    await store.put('plan1', 'new:c1', 'durable-value');
    const committed = await readFile(path);
    await appendFile(path, tail);

    await reopen().put('plan1', 'old:c1', 'undo-value');

    const repaired = await readFile(path);
    expect(repaired.subarray(0, committed.length)).toEqual(committed);
    expect(repaired.toString('utf8').split('\n')).toHaveLength(3);
    expect(repaired.toString('utf8')).not.toContain(tail);
    const recovered = reopen();
    expect(await recovered.get('plan1', 'new:c1')).toBe('durable-value');
    expect(await recovered.get('plan1', 'old:c1')).toBe('undo-value');
    expect(await recovered.slots('plan1')).toEqual(['new:c1', 'old:c1']);
  });

  it.each(['', 'S1MxAQ7x9kPq'])('can append with an existing key when no complete records remain (%j)', async contents => {
    const { path, store, reopen } = await fixture();
    await store.put('plan1', 'new:c1', 'uncommitted-value');
    await writeFile(path, contents);

    const recovered = reopen();
    expect(await recovered.get('plan1', 'new:c1')).toBeNull();
    expect(await recovered.slots('plan1')).toEqual([]);
    await recovered.put('plan1', 'old:c1', 'undo-value');
    expect(await reopen().get('plan1', 'old:c1')).toBe('undo-value');
    expect(await reopen().slots('plan1')).toEqual(['old:c1']);
    expect((await readFile(path, 'utf8')).split('\n')).toHaveLength(2);
  });

  it.each(['invalid', 'blank', 'encrypted'])('fails closed on a complete %s corrupt line before a torn tail', async kind => {
    const { path, store, reopen } = await fixture();
    await store.put('plan1', 'new:c1', 'durable-value');
    const committed = await readFile(path, 'utf8');
    let corrupt = kind === 'blank' ? '' : 'invalid-ciphertext';
    if (kind === 'encrypted') {
      const sealed = Buffer.from(committed.trim(), 'base64');
      sealed[sealed.length - 1] = sealed[sealed.length - 1]! ^ 1;
      corrupt = sealed.toString('base64');
    }
    await appendFile(path, `${corrupt}\nS1MxAQ7x9kPq`);
    const before = await readFile(path);
    const recovered = reopen();

    await expect(recovered.get('plan1', 'new:c1')).rejects.toThrow(DecryptError);
    await expect(recovered.slots('plan1')).rejects.toThrow(DecryptError);
    await expect(recovered.put('plan1', 'old:c1', 'undo-value')).rejects.toThrow();
    expect(await readFile(path)).toEqual(before);
  });

  it.each(['records', 'empty', 'torn'])('refuses a new key for an existing %s file and gives recovery guidance', async kind => {
    const { path, store, vault, reopen } = await fixture();
    await store.put('plan1', 'new:c1', 'durable-value');
    if (kind === 'empty') await writeFile(path, '');
    if (kind === 'torn') await writeFile(path, 'S1MxAQ7x9kPq');
    await vault.delete('project/project1/inflight/plan1');
    const before = await readFile(path);
    const recovered = reopen();
    expect(await recovered.get('plan1', 'new:c1')).toBeNull();
    expect(await recovered.slots('plan1')).toEqual([]);

    let failure: unknown;
    try { await recovered.put('plan1', 'old:c1', 'undo-value'); }
    catch (error) { failure = error; }

    expect(failure).toBeInstanceOf(Error);
    expect(String(failure)).toContain('plan1');
    expect(String(failure)).toContain('keysentry state reset --force');
    expect(String(failure)).toMatch(/check.*provider.*unrecorded keys/i);
    expect(String(failure)).not.toContain('durable-value');
    expect(String(failure)).not.toContain('undo-value');
    expect(await vault.get('project/project1/inflight/plan1')).toBeNull();
    expect(await readFile(path)).toEqual(before);
  });

  it('creates a key when no records file exists', async () => {
    const { dir, vault, store, reopen } = await fixture();
    await mkdir(dir, { recursive: true });
    await store.put('plan1', 'new:c1', 'fresh-value');
    expect(await vault.get('project/project1/inflight/plan1')).not.toBeNull();
    expect(await reopen().get('plan1', 'new:c1')).toBe('fresh-value');
  });
});
