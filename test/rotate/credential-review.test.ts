import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor, fingerprint } from '../../src/core/index.js';
import { executePlan } from '../../src/rotate/engine.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/engine.js';
import type { JournalEntry, ProviderAdapter, ProviderContext, ProviderId, RotationResult } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

const key = Buffer.alloc(32, 0x69);
const options: RotateOptions = {
  dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 10,
  revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 4,
};

async function fixture(host: FakeHost, providers: ProviderAdapter[]) {
  const inv = buildInventory([{
    host: host.id,
    services: await Promise.all((await host.listServices()).map(async service => ({ service, vars: await host.readVariables(service) }))),
  }], key);
  const plan = buildPlan(inv);
  const entries: JournalEntry[] = [];
  const lines: string[] = [];
  const redactor = createRedactor();
  const log = createLogger({ redactor, level: 'debug', json: true, sink: line => lines.push(line) });
  const prompt = vi.fn<EngineDeps['prompt']>().mockResolvedValue(null);
  const sleep = vi.fn<NonNullable<EngineDeps['sleep']>>().mockResolvedValue(undefined);
  const deps: EngineDeps = {
    hosts: { [host.id]: host },
    providers(id) { const provider = providers.find(p => p.id === id); if (!provider) throw new Error('Missing fake provider'); return provider; },
    providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: { async append(entry) { entries.push(structuredClone(entry)); }, async read() { return entries; } },
    fingerprintKey: key, redactor, log, prompt, sleep, reveal: async () => true,
  };
  return { inv, plan, deps, entries, lines, prompt, sleep };
}

afterEach(() => vi.restoreAllMocks());

describe('rotation review: credentials and irreversible rolls', () => {
  it('finishes every guided interaction before creation, then creates auto/generate values before atomic rolls', async () => {
    const atomic = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const auto = new FakeProvider('resend', 'auto', 're_');
    const generated = new FakeProvider('app-secret', 'generate', 'session_random_');
    const guided = new FakeProvider('anthropic', 'guided', 'sk-ant-api03-');
    const fallback = new FakeProvider('openai', 'auto', 'sk-proj-');
    const host = new FakeHost('railway');
    host.addService('api', {
      CLOUDFLARE_API_TOKEN: atomic.issue().value, RESEND_API_KEY: auto.issue().value,
      SESSION_SECRET: generated.issue().value, ANTHROPIC_API_KEY: guided.issue().value,
      OPENAI_API_KEY: fallback.issue().value,
    }, ['OPENAI_API_KEY']);
    const h = await fixture(host, [atomic, auto, generated, guided, fallback]);
    const order: string[] = [];
    const priority: ProviderId[] = ['cloudflare', 'resend', 'app-secret', 'anthropic', 'openai'];
    h.plan.steps.sort((a, b) => priority.indexOf(a.provider) - priority.indexOf(b.provider));
    for (const provider of [atomic, auto, generated]) {
      const rotate = provider.rotate.bind(provider);
      vi.spyOn(provider, 'rotate').mockImplementation(async (...args) => { order.push(`rotate:${provider.id}`); return rotate(...args); });
    }
    h.prompt.mockImplementation(async prompt => {
      order.push(`prompt:${prompt.provider}`);
      return (prompt.provider === 'anthropic' ? guided : fallback).issue('manual').value;
    });
    const write = host.writeVariables.bind(host);
    vi.spyOn(host, 'writeVariables').mockImplementation(async (...args) => { order.push('write'); return write(...args); });

    await executePlan(h.plan, h.inv, h.deps, options);

    expect(order.filter(event => event.startsWith('prompt:'))).toHaveLength(2);
    expect(order.slice(0, 2).every(event => event.startsWith('prompt:'))).toBe(true);
    expect(order.indexOf('rotate:cloudflare')).toBeGreaterThan(order.indexOf('rotate:resend'));
    expect(order.indexOf('rotate:cloudflare')).toBeGreaterThan(order.indexOf('rotate:app-secret'));
    expect(order.at(-1)).toBe('write');
  });

  it('writes an atomically rolled value even when verification definitively fails, without cleaning it up', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    const h = await fixture(host, [provider]);
    vi.spyOn(provider, 'verify').mockResolvedValue({ ok: false, status: 401 });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    const replacement = [...provider.keys.values()].find(value => value.ref !== old.ref)!;
    expect(host.peek('api', 'CLOUDFLARE_API_TOKEN')).toBe(replacement.value);
    expect(replacement.active).toBe(true);
    expect(provider.revoked).toEqual([]);
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/verif/i);
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/old.*revoked|already.*dead/i);
  });

  it('retries an atomic consumer write three times and preserves the rolled replacement when the last attempt succeeds', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    const h = await fixture(host, [provider]);
    const write = host.writeVariables.bind(host);
    let attempts = 0;
    vi.spyOn(host, 'writeVariables').mockImplementation(async (...args) => { if (++attempts < 4) throw new Error('transient'); return write(...args); });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(attempts).toBe(4);
    expect(h.sleep.mock.calls.filter(([delay]) => delay >= 1000)).toHaveLength(3);
    expect(host.peek('api', 'CLOUDFLARE_API_TOKEN')).not.toBe(old.value);
    expect(report.steps[0]?.status).toBe('revoked');
    expect(provider.revoked).toEqual([]);
  });

  it('reveals an unwritten atomic replacement after retry exhaustion and journals only sanitized recovery metadata', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    host.failWritesFor.add('api');
    const h = await fixture(host, [provider]);
    const reveal = vi.fn<NonNullable<EngineDeps['reveal']>>().mockResolvedValue(true);
    h.deps.reveal = reveal;
    const write = vi.spyOn(host, 'writeVariables');

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    const replacement = [...provider.keys.values()].find(value => value.ref !== old.ref)!;
    expect(write).toHaveBeenCalledTimes(4);
    expect(reveal).toHaveBeenCalledWith(expect.objectContaining({ clusterId: h.plan.steps[0]!.clusterId, provider: 'cloudflare', reason: expect.any(String) }), replacement.value);
    expect(report.steps[0]?.status).toBe('failed');
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/manual|unwritten|unable|failed/i);
    expect(h.entries).toContainEqual(expect.objectContaining({ event: 'failed', data: expect.objectContaining({ phase: 'value-unwritten' }) }));
    expect(provider.revoked).toEqual([]);
    for (const value of [old.value, replacement.value]) expect(JSON.stringify({ report, entries: h.entries, lines: h.lines })).not.toContain(value);
  });

  it('preserves the atomic value when an auto companion conflicts with its consumer variable', async () => {
    const atomic = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const auto = new FakeProvider('resend', 'auto', 're_');
    const oldAtomic = atomic.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: oldAtomic.value, RESEND_API_KEY: auto.issue().value });
    const h = await fixture(host, [atomic, auto]);
    const rotate = auto.rotate.bind(auto);
    vi.spyOn(auto, 'rotate').mockImplementation(async (...args) => ({ ...await rotate(...args), companions: { CLOUDFLARE_API_TOKEN: 'different_companion_abcdef0123456789' } }));
    const recovered: string[] = [];
    h.deps.reveal = async (_info, value) => { recovered.push(value); return true; };

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    const replacement = [...atomic.keys.values()].find(value => value.ref !== oldAtomic.ref)!;
    expect(host.peek('api', 'CLOUDFLARE_API_TOKEN') === replacement.value || recovered.includes(replacement.value)).toBe(true);
    expect(replacement.active).toBe(true);
    expect(atomic.revoked).toEqual([]);
    if (recovered.includes(replacement.value)) {
      expect(report.steps.find(step => step.clusterId === fingerprint(oldAtomic.value, key))?.status).toBe('failed');
      expect(h.entries).toContainEqual(expect.objectContaining({ event: 'failed', data: expect.objectContaining({ phase: 'value-unwritten' }) }));
    }
  });

  it('delivers or reveals every atomic replacement when companion values cannot coexist', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const first = provider.issue('first');
    const second = provider.issue('second');
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: first.value, CLOUDFLARE_BACKUP_TOKEN: second.value });
    const h = await fixture(host, [provider]);
    const rotate = provider.rotate.bind(provider);
    const replacements = new Map<string, { value: string; companion: string }>();
    vi.spyOn(provider, 'rotate').mockImplementation(async (oldValue, ctx) => {
      const result = await rotate(oldValue, ctx);
      const companion = `companion_${result.newKeyRef}_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6`;
      replacements.set(oldValue, { value: result.newValue, companion });
      return { ...result, companions: { SHARED_COMPANION: companion } };
    });
    const recovered: string[] = [];
    h.deps.reveal = async (_info, value) => { recovered.push(value); return true; };

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(recovered.length).toBeGreaterThan(0);
    for (const [old, replacement] of replacements) {
      const name = old === first.value ? 'CLOUDFLARE_API_TOKEN' : 'CLOUDFLARE_BACKUP_TOKEN';
      const delivered = host.peek('api', name) === replacement.value && host.peek('api', 'SHARED_COMPANION') === replacement.companion;
      expect(delivered || recovered.includes(replacement.value)).toBe(true);
      if (!delivered) {
        const clusterId = fingerprint(old, key);
        expect(report.steps.find(step => step.clusterId === clusterId)?.status).toBe('failed');
        expect(h.entries).toContainEqual(expect.objectContaining({ event: 'failed', clusterId, data: expect.objectContaining({ phase: 'value-unwritten' }) }));
      }
    }
    expect(provider.revoked).toEqual([]);
    for (const replacement of replacements.values()) expect(JSON.stringify({ report, entries: h.entries, lines: h.lines })).not.toContain(replacement.value);
  });

  it('keeps an atomic failure visible and sanitized when manual reveal itself rejects', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    host.failWritesFor.add('api');
    const h = await fixture(host, [provider]);
    h.deps.reveal = async (_info, value) => { throw new Error(`unsafe callback error ${value}`); };

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]?.status).toBe('failed');
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/reveal|recover|manual/i);
    expect(h.entries).toContainEqual(expect.objectContaining({ event: 'failed', data: expect.objectContaining({ phase: 'value-unwritten' }) }));
    const replacement = [...provider.keys.values()].find(value => value.ref !== old.ref)!;
    expect(replacement.active).toBe(true);
    expect(JSON.stringify({ report, entries: h.entries, lines: h.lines })).not.toContain(replacement.value);
  });

  it('preserves a rolled value for delivery or manual recovery when the journal fails after creation', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    const h = await fixture(host, [provider]);
    const append = h.deps.journal.append.bind(h.deps.journal);
    h.deps.journal.append = async entry => { if (entry.event === 'created') throw new Error('journal offline'); return append(entry); };
    const recovered: string[] = [];
    h.deps.reveal = async (_info, value) => { recovered.push(value); return true; };

    await expect(executePlan(h.plan, h.inv, h.deps, options)).rejects.toThrow('Unable to record rotation journal');

    const replacement = [...provider.keys.values()].find(value => value.ref !== old.ref)!;
    expect(host.peek('api', 'CLOUDFLARE_API_TOKEN') === replacement.value || recovered.includes(replacement.value)).toBe(true);
    expect(replacement.active).toBe(true);
    expect(provider.revoked).toEqual([]);
    expect(JSON.stringify({ entries: h.entries, lines: h.lines })).not.toContain(replacement.value);
  });

  it('writes the rolled primary to every direct variable even when a companion conflicts with one of them', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value, CLOUDFLARE_BACKUP_TOKEN: old.value });
    const h = await fixture(host, [provider]);
    expect(h.plan.steps).toHaveLength(1);
    const rotate = provider.rotate.bind(provider);
    vi.spyOn(provider, 'rotate').mockImplementation(async (...args) => ({
      ...await rotate(...args), companions: { CLOUDFLARE_API_TOKEN: 'incompatible_companion_Ab3Cd5Ef7Gh9Jk1' },
    }));

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    const replacement = [...provider.keys.values()].find(value => value.ref !== old.ref)!;
    expect(host.peek('api', 'CLOUDFLARE_API_TOKEN')).toBe(replacement.value);
    expect(host.peek('api', 'CLOUDFLARE_BACKUP_TOKEN')).toBe(replacement.value);
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/conflict/i);
    expect(provider.revoked).toEqual([]);
  });

  it('reveals an unwritten rolled value even if its value-unwritten journal entry fails', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    host.failWritesFor.add('api');
    const h = await fixture(host, [provider]);
    const append = h.deps.journal.append.bind(h.deps.journal);
    h.deps.journal.append = async entry => {
      if (entry.event === 'failed' && entry.data?.phase === 'value-unwritten') throw new Error('journal offline');
      return append(entry);
    };
    const reveal = vi.fn<NonNullable<EngineDeps['reveal']>>().mockResolvedValue(true);
    h.deps.reveal = reveal;

    await expect(executePlan(h.plan, h.inv, h.deps, options)).rejects.toThrow('Unable to record rotation journal');

    const replacement = [...provider.keys.values()].find(value => value.ref !== old.ref)!;
    expect(reveal).toHaveBeenCalledWith(expect.objectContaining({ provider: 'cloudflare', reason: expect.stringMatching(/UNWRITTEN/) }), replacement.value);
    expect(replacement.active).toBe(true);
    expect(provider.revoked).toEqual([]);
    expect(JSON.stringify({ entries: h.entries, lines: h.lines })).not.toContain(replacement.value);
  });

  it('preserves a rolled value when post-roll logging fails continuously', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    const h = await fixture(host, [provider]);
    vi.spyOn(h.deps.log, 'info').mockImplementation(() => { throw new Error('logger offline'); });
    vi.spyOn(h.deps.log, 'warn').mockImplementation(() => { throw new Error('logger offline'); });
    const recovered: string[] = [];
    h.deps.reveal = async (_info, value) => { recovered.push(value); return true; };

    await expect(executePlan(h.plan, h.inv, h.deps, options)).rejects.toThrow('logger offline');

    const replacement = [...provider.keys.values()].find(value => value.ref !== old.ref)!;
    expect(host.peek('api', 'CLOUDFLARE_API_TOKEN') === replacement.value || recovered.includes(replacement.value)).toBe(true);
    expect(replacement.active).toBe(true);
    expect(provider.revoked).toEqual([]);
    expect(JSON.stringify({ entries: h.entries, lines: h.lines })).not.toContain(replacement.value);
  });

  it('continues emergency delivery to remaining atomic consumers after a post-write journal outage', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    host.addService('worker', { CLOUDFLARE_API_TOKEN: old.value });
    const h = await fixture(host, [provider]);
    const append = h.deps.journal.append.bind(h.deps.journal);
    h.deps.journal.append = async entry => { if (entry.event === 'written') throw new Error('journal offline'); return append(entry); };

    await expect(executePlan(h.plan, h.inv, h.deps, options)).rejects.toThrow('Unable to record rotation journal');

    const replacement = [...provider.keys.values()].find(value => value.ref !== old.ref)!;
    expect(host.peek('api', 'CLOUDFLARE_API_TOKEN')).toBe(replacement.value);
    expect(host.peek('worker', 'CLOUDFLARE_API_TOKEN')).toBe(replacement.value);
    expect(replacement.active).toBe(true);
    expect(provider.revoked).toEqual([]);
    expect(JSON.stringify({ entries: h.entries, lines: h.lines })).not.toContain(replacement.value);
  });

  it('retries transient new-key verification at 2, 4, 8 and 16 seconds before writing', async () => {
    const provider = new FakeProvider('aws', 'auto', 'aws_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { AWS_SECRET_ACCESS_KEY: old.value, AWS_ACCESS_KEY_ID: 'AKIAABCDEFGHIJKLMNOP' });
    const h = await fixture(host, [provider]);
    const rotate = provider.rotate.bind(provider);
    vi.spyOn(provider, 'rotate').mockImplementation(async (...args) => ({ ...await rotate(...args), companions: { AWS_ACCESS_KEY_ID: 'AKIAQRSTUVWXYZABCDEF' } }));
    let attempts = 0;
    vi.spyOn(provider, 'verify').mockImplementation(async () => ({ ok: ++attempts === 5, status: attempts === 5 ? 200 : 403 }));

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(attempts).toBe(5);
    expect(h.sleep.mock.calls.map(([delay]) => delay).filter(delay => delay >= 2000)).toEqual([2000, 4000, 8000, 16000]);
    expect(host.peek('api', 'AWS_SECRET_ACCESS_KEY')).not.toBe(old.value);
    expect(report.steps[0]?.status).toBe('revoked');
  });

  it('does not retry a definitive 401 and cleans an unused AWS key up with old credentials', async () => {
    const provider = new FakeProvider('aws', 'auto', 'aws_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const old = provider.issue();
    const oldId = 'AKIAABCDEFGHIJKLMNOP';
    const newId = 'AKIAQRSTUVWXYZABCDEF';
    const host = new FakeHost('railway');
    host.addService('api', { AWS_SECRET_ACCESS_KEY: old.value, AWS_ACCESS_KEY_ID: oldId });
    const h = await fixture(host, [provider]);
    const rotate = provider.rotate.bind(provider);
    vi.spyOn(provider, 'rotate').mockImplementation(async (...args) => ({ ...await rotate(...args), companions: { AWS_ACCESS_KEY_ID: newId } }));
    const verify = vi.spyOn(provider, 'verify').mockResolvedValue({ ok: false, status: 401 });
    let cleanupCtx: ProviderContext | undefined;
    const revoke = provider.revoke.bind(provider);
    vi.spyOn(provider, 'revoke').mockImplementation(async (ref, ctx) => { cleanupCtx = ctx; return revoke(ref, ctx); });

    await executePlan(h.plan, h.inv, h.deps, options);

    expect(verify).toHaveBeenCalledTimes(1);
    expect(h.sleep).not.toHaveBeenCalled();
    expect(host.writes).toEqual([]);
    expect(cleanupCtx?.siblingVars?.AWS_ACCESS_KEY_ID).toBe(oldId);
    expect(cleanupCtx?.siblingVars?.AWS_SECRET_ACCESS_KEY).toBe(old.value);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
  });

  it('honors verifyRetries zero when verification is transiently unsuccessful', async () => {
    const provider = new FakeProvider('resend', 'auto', 're_');
    const host = new FakeHost('railway');
    host.addService('api', { RESEND_API_KEY: provider.issue().value });
    const h = await fixture(host, [provider]);
    const verify = vi.spyOn(provider, 'verify').mockResolvedValue({ ok: false, status: 503 });

    await executePlan(h.plan, h.inv, h.deps, { ...options, verifyRetries: 0 });

    expect(verify).toHaveBeenCalledTimes(1);
    expect(h.sleep).not.toHaveBeenCalled();
    expect(host.writes).toEqual([]);
  });

  it('skips a guided replacement classified as another provider before verification or writes', async () => {
    const provider = new FakeProvider('anthropic', 'guided', 'sk-ant-api03-');
    const host = new FakeHost('railway');
    host.addService('api', { ANTHROPIC_API_KEY: provider.issue().value });
    const h = await fixture(host, [provider]);
    h.prompt.mockResolvedValue(`sk-proj-${'z'.repeat(32)}`);
    const verify = vi.spyOn(provider, 'verify');

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]?.status).toBe('skipped');
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/provider|classif|match/i);
    expect(verify).not.toHaveBeenCalled();
    expect(host.writes).toEqual([]);
  });

  it.each([
    ['private-key', 'SIGNING_PRIVATE_KEY', '-----BEGIN PRIVATE KEY-----\nYWJjZGVmZ2hpamtsbW5vcA==\n-----END PRIVATE KEY-----', '-----BEGIN PRIVATE KEY-----'],
    ['unknown', 'CONFIG_SECRET', '{"a":"abcdef0123456789","b":"fedcba9876543210"}', '{"a":"abcdef0123456789","b":'],
  ] as const)('skips truncated multiline or structured input for %s', async (id, name, old, replacement) => {
    const provider = new FakeProvider(id, 'guided');
    const host = new FakeHost('railway');
    host.addService('api', { [name]: old });
    const h = await fixture(host, [provider]);
    // Keep JSON classification intentionally unknown, so parsing safety is tested independently of provider matching.
    h.inv.clusters[0]!.provider = id;
    h.plan.steps[0]!.provider = id;
    h.plan.steps[0]!.method = 'guided';
    h.prompt.mockResolvedValue(replacement);
    vi.spyOn(provider, 'verify').mockResolvedValue({ ok: true });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]?.status).toBe('skipped');
    expect(report.steps[0]?.warnings.length).toBeGreaterThan(0);
    expect(host.writes).toEqual([]);
  });

  it('rejects a multiline secret prefix even when it still classifies as the same provider', async () => {
    const provider = new FakeProvider('unknown', 'guided');
    const old = 'first-line-abcdef0123456789\nsecond-line-fedcba9876543210';
    const host = new FakeHost('railway');
    host.addService('api', { CONFIG_SECRET: old });
    const h = await fixture(host, [provider]);
    // The scanner ignores arbitrary whitespace-bearing values; supply the known multiline finding explicitly.
    if (h.inv.clusters.length === 0) {
      const service = (await host.listServices())[0]!;
      const consumer = { service, varName: 'CONFIG_SECRET', fingerprint: fingerprint(old, key), hint: null, sealed: false };
      h.inv.findings.push({ ...consumer, provider: 'unknown', tier: 'unknown', isSecret: true, confidence: 'low' });
      h.inv.clusters.push({ id: fingerprint(old, key), fingerprint: fingerprint(old, key), provider: 'unknown', tier: 'unknown', method: 'guided', hint: null, consumers: [consumer] });
      h.plan.steps.push({ clusterId: fingerprint(old, key), provider: 'unknown', tier: 'unknown', method: 'guided', hint: null, consumers: [consumer] });
      h.plan.services.push(service);
    }
    h.prompt.mockResolvedValue(old.split('\n')[0]!);
    vi.spyOn(provider, 'verify').mockResolvedValue({ ok: true });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]?.status).toBe('skipped');
    expect(host.writes).toEqual([]);
  });

  it('accepts a complete replacement PEM rather than rejecting all multiline secrets', async () => {
    const provider = new FakeProvider('private-key', 'guided');
    const old = '-----BEGIN PRIVATE KEY-----\nYWJjZGVmZ2hpamtsbW5vcA==\n-----END PRIVATE KEY-----';
    const replacement = '-----BEGIN PRIVATE KEY-----\nUXdlcnR5dWlvcGFzZGZnaA==\n-----END PRIVATE KEY-----';
    const host = new FakeHost('railway');
    host.addService('api', { SIGNING_PRIVATE_KEY: old });
    const h = await fixture(host, [provider]);
    h.prompt.mockResolvedValue(replacement);
    vi.spyOn(provider, 'verify').mockResolvedValue({ ok: true });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(host.peek('api', 'SIGNING_PRIVATE_KEY')).toBe(replacement);
    expect(report.steps[0]?.status).toBe('deployed');
  });

  it('forces encryption-key through guided input even if a stale plan and adapter say generate', async () => {
    const provider = new FakeProvider('encryption-key', 'generate', 'encryption_material_');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { ENCRYPTION_KEY: old.value });
    const h = await fixture(host, [provider]);
    h.inv.clusters[0]!.provider = 'encryption-key';
    h.plan.steps[0]!.provider = 'encryption-key';
    h.plan.steps[0]!.method = 'generate';
    const replacement = provider.issue('manual');
    h.prompt.mockResolvedValue(replacement.value);
    const rotate = vi.spyOn(provider, 'rotate');

    await executePlan(h.plan, h.inv, h.deps, { ...options, allowGenerate: false });

    expect(h.prompt).toHaveBeenCalledTimes(1);
    expect(rotate).not.toHaveBeenCalled();
    expect(host.peek('api', 'ENCRYPTION_KEY')).toBe(replacement.value);
  });

  it('skips generated application secrets with the exact session invalidation warning when generation is disabled', async () => {
    const provider = new FakeProvider('app-secret', 'generate', 'session_material_');
    const host = new FakeHost('railway');
    const old = provider.issue();
    host.addService('api', { SESSION_SECRET: old.value });
    const h = await fixture(host, [provider]);
    const rotate = vi.spyOn(provider, 'rotate');

    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, allowGenerate: false });

    expect(report.steps[0]?.status).toBe('skipped');
    expect(report.steps[0]?.warnings).toContain('self-generated secret: rotate it deliberately; sessions signed with it become invalid');
    expect(rotate).not.toHaveBeenCalled();
    expect(host.peek('api', 'SESSION_SECRET')).toBe(old.value);
  });

  it('copies provider rotation notes into warnings after redacting every returned credential', async () => {
    const provider = new FakeProvider('resend', 'auto', 're_');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { RESEND_API_KEY: old.value });
    const h = await fixture(host, [provider]);
    const rotate = provider.rotate.bind(provider);
    let result: RotationResult | undefined;
    vi.spyOn(provider, 'rotate').mockImplementation(async (...args) => {
      result = await rotate(...args);
      return { ...result, companions: { SECONDARY_SECRET: 'companion_secret_0123456789' }, notes: `Manual follow-up is required; old=${old.value}; new=${result.newValue}; sibling=companion_secret_0123456789` };
    });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]?.warnings.join(' ')).toContain('Manual follow-up is required');
    for (const value of [old.value, result!.newValue, 'companion_secret_0123456789']) expect(JSON.stringify({ report, entries: h.entries, lines: h.lines })).not.toContain(value);
  });
});
