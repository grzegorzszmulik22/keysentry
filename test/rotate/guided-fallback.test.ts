import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor, fingerprint } from '../../src/core/index.js';
import { executePlan } from '../../src/rotate/engine.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/engine.js';
import type { JournalEntry, ProviderAdapter, ProviderId } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

const key = Buffer.alloc(32, 0x73);
const options: RotateOptions = {
  dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 10,
  revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 4,
};
const manualWarning = "automatic rotation would change this key's permissions; rotate it by hand";

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
  const deps: EngineDeps = {
    hosts: { [host.id]: host },
    providers(id) { const provider = providers.find(p => p.id === id); if (!provider) throw new Error('Missing fake provider'); return provider; },
    providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: { async append(entry) { entries.push(structuredClone(entry)); }, async read() { return entries; } },
    fingerprintKey: key, redactor, log, prompt, sleep: async () => {}, reveal: async () => true,
  };
  return { inv, plan, deps, entries, lines, prompt };
}

function guidedError(provider: ProviderId, plain = false): unknown {
  const metadata = { code: 'GUIDED_ROTATION_REQUIRED', provider };
  return plain ? metadata : Object.assign(new Error('Permission-preserving rotation requires a person'), metadata);
}

afterEach(() => vi.restoreAllMocks());

describe('automatic rotation requiring guided permission preservation', () => {
  it.each([
    { id: 'openai' as const, prefix: 'sk-proj-', name: 'OPENAI_API_KEY', plain: false },
    { id: 'resend' as const, prefix: 're_', name: 'RESEND_API_KEY', plain: true },
  ])('rotates $id interactively without provider mutation before the fallback', async ({ id, prefix, name, plain }) => {
    const provider = new FakeProvider(id, 'auto', prefix);
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { [name]: old.value });
    host.addService('worker', { [name]: old.value });
    const h = await fixture(host, [provider]);
    const rotate = vi.spyOn(provider, 'rotate').mockRejectedValue(guidedError(id, plain));
    const verify = vi.spyOn(provider, 'verify');
    const resolve = vi.spyOn(provider, 'resolveKeyRef');
    const revoke = provider.revoke.bind(provider);
    vi.spyOn(provider, 'revoke').mockImplementation(async (ref, ctx) => {
      expect(host.redeploys).toEqual(['api', 'worker']);
      expect(h.entries.filter(entry => entry.event === 'deploy-result' && entry.data?.state === 'success')).toHaveLength(2);
      await revoke(ref, ctx);
    });
    let replacement: { value: string; ref: string } | undefined;
    h.prompt.mockImplementation(async prompt => {
      expect(prompt).toEqual({
        clusterId: h.plan.steps[0]!.clusterId, provider: id, hint: h.plan.steps[0]!.hint,
        guidance: provider.guidance(), consumers: h.plan.steps[0]!.consumers,
      });
      expect(provider.keys.size).toBe(1);
      expect(provider.keys.get(old.ref)?.active).toBe(true);
      expect(provider.revoked).toEqual([]);
      expect(host.writes).toEqual([]);
      replacement = provider.issue('manual replacement');
      return replacement.value;
    });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(h.prompt).toHaveBeenCalledTimes(1);
    expect(rotate).toHaveBeenCalledTimes(1);
    expect(report.steps[0]).toMatchObject({ status: 'revoked', oldKeyRef: old.ref, newKeyRef: replacement?.ref });
    expect(report.steps[0]?.error).toBeUndefined();
    expect(host.peek('api', name) === replacement?.value).toBe(true);
    expect(host.peek('worker', name) === replacement?.value).toBe(true);
    expect(host.writes).toHaveLength(2);
    expect(verify.mock.calls.some(([value]) => value === replacement?.value)).toBe(true);
    expect(resolve.mock.calls.some(([value]) => value === old.value)).toBe(true);
    expect(resolve.mock.calls.some(([value]) => value === replacement?.value)).toBe(true);
    expect(provider.revoked).toEqual([old.ref]);
    expect(h.entries.some(entry => entry.event === 'failed')).toBe(false);
    const serialized = JSON.stringify({ report, entries: h.entries, lines: h.lines });
    expect(serialized.includes(old.value)).toBe(false);
    expect(serialized.includes(replacement!.value)).toBe(false);
  });

  it.each([
    { id: 'openai' as const, prefix: 'sk-proj-', name: 'OPENAI_API_KEY' },
    { id: 'resend' as const, prefix: 're_', name: 'RESEND_API_KEY' },
  ])('skips unattended $id fallback with permission guidance and no failure', async ({ id, prefix, name }) => {
    const provider = new FakeProvider(id, 'auto', prefix);
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { [name]: old.value });
    const h = await fixture(host, [provider]);
    vi.spyOn(provider, 'rotate').mockRejectedValue(guidedError(id));
    const verify = vi.spyOn(provider, 'verify');

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(h.prompt).toHaveBeenCalledTimes(1);
    expect(report.steps[0]).toMatchObject({ status: 'skipped', warnings: [manualWarning] });
    expect(report.steps[0]?.error).toBeUndefined();
    expect(h.entries.some(entry => entry.event === 'failed')).toBe(false);
    expect(verify).not.toHaveBeenCalled();
    expect(provider.keys.size).toBe(1);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
    expect(provider.revoked).toEqual([]);
    expect(host.writes).toEqual([]);
    expect(host.redeploys).toEqual([]);
  });

  it('updates a Resend-shaped fallback without a resolver and leaves old-key revocation to the operator', async () => {
    const provider = new FakeProvider('resend', 'auto', 're_');
    const old = provider.issue();
    const revoke = vi.spyOn(provider, 'revoke');
    const adapter: ProviderAdapter = {
      id: 'resend', method: 'auto',
      rotate: async () => { throw guidedError('resend'); },
      verify: provider.verify.bind(provider), revoke: provider.revoke.bind(provider),
      guidance: () => provider.guidance(),
    };
    const host = new FakeHost('railway');
    host.addService('api', { RESEND_API_KEY: old.value });
    const h = await fixture(host, [adapter]);
    let replacement: string | undefined;
    h.prompt.mockImplementation(async () => {
      replacement = provider.issue('manual replacement').value;
      return replacement;
    });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(h.prompt).toHaveBeenCalledTimes(1);
    expect(report.steps[0]).toMatchObject({ status: 'deployed', oldKeyRef: null, newKeyRef: null });
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/revoke it manually/i);
    expect(report.steps[0]?.error).toBeUndefined();
    expect(host.peek('api', 'RESEND_API_KEY') === replacement).toBe(true);
    expect(host.writes).toHaveLength(1);
    expect(host.redeploys).toEqual(['api']);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
    expect(revoke).not.toHaveBeenCalled();
    expect(h.entries.some(entry => entry.event === 'failed')).toBe(false);
    const serialized = JSON.stringify({ report, entries: h.entries, lines: h.lines });
    for (const value of [old.value, replacement!]) expect(serialized.includes(value)).toBe(false);
  });

  it.each(['wrong provider', 'truncated', 'empty'])('rejects %s pasted input before writing or revoking', async kind => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: old.value });
    const h = await fixture(host, [provider]);
    vi.spyOn(provider, 'rotate').mockRejectedValue(guidedError('openai'));
    const verify = vi.spyOn(provider, 'verify');
    const value = kind === 'wrong provider' ? `sk-ant-api03-${'x'.repeat(40)}` : kind === 'truncated' ? old.value.slice(0, -1) : '   ';
    h.prompt.mockResolvedValue(value);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(h.prompt).toHaveBeenCalledTimes(1);
    expect(report.steps[0]?.status).toBe('skipped');
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/incomplete|different provider/i);
    expect(verify).not.toHaveBeenCalled();
    expect(host.writes).toEqual([]);
    expect(provider.revoked).toEqual([]);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
  });

  it('retains the old key when a pasted fallback replacement fails verification', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: old.value });
    const h = await fixture(host, [provider]);
    vi.spyOn(provider, 'rotate').mockRejectedValue(guidedError('openai'));
    const verify = vi.spyOn(provider, 'verify').mockResolvedValue({ ok: false, status: 401 });
    h.prompt.mockImplementation(async () => provider.issue('manual replacement').value);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(h.prompt).toHaveBeenCalledTimes(1);
    expect(verify).toHaveBeenCalledTimes(1);
    expect(report.steps[0]?.status).toBe('failed');
    expect(report.steps[0]?.error).toMatch(/verification failed/i);
    expect(host.writes).toEqual([]);
    expect(provider.revoked).toEqual([]);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
  });

  it('keeps ordinary rotate errors as failures without prompting', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: provider.issue().value });
    const h = await fixture(host, [provider]);
    vi.spyOn(provider, 'rotate').mockRejectedValue(Object.assign(new Error('GUIDED_ROTATION_REQUIRED'), { code: 'OTHER_FAILURE' }));

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]?.status).toBe('failed');
    expect(h.prompt).not.toHaveBeenCalled();
    expect(host.writes).toEqual([]);
    expect(provider.revoked).toEqual([]);
  });

  it('finishes an automatic fallback prompt before any planned atomic roll', async () => {
    const automatic = new FakeProvider('openai', 'auto', 'sk-proj-');
    const atomic = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const oldAtomic = atomic.issue();
    const host = new FakeHost('railway');
    host.addService('api', { OPENAI_API_KEY: automatic.issue().value, CLOUDFLARE_API_TOKEN: oldAtomic.value });
    const h = await fixture(host, [automatic, atomic]);
    expect(h.plan.steps[0]?.provider).toBe('cloudflare');
    vi.spyOn(automatic, 'rotate').mockRejectedValue(guidedError('openai'));
    const order: string[] = [];
    const rotate = atomic.rotate.bind(atomic);
    vi.spyOn(atomic, 'rotate').mockImplementation(async (...args) => { order.push('atomic'); return rotate(...args); });
    h.prompt.mockImplementation(async () => {
      order.push('prompt');
      expect(atomic.keys.get(oldAtomic.ref)?.active).toBe(true);
      expect(atomic.keys.size).toBe(1);
      return automatic.issue('manual replacement').value;
    });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(order).toEqual(['prompt', 'atomic']);
    expect(report.steps.every(step => step.status === 'revoked')).toBe(true);
    expect(host.writes).toHaveLength(1);
    expect(host.redeploys).toEqual(['api']);
    expect(h.entries).toContainEqual(expect.objectContaining({ event: 'created', data: expect.objectContaining({ phase: 'guided-fallback', atomicRollsAlreadyRan: false }) }));
  });

  it('delivers an earlier atomic roll and journals it before a late fallback prompt', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const first = provider.issue('first');
    const second = provider.issue('second');
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: first.value, CLOUDFLARE_BACKUP_TOKEN: second.value });
    const h = await fixture(host, [provider]);
    const firstId = fingerprint(first.value, key);
    h.plan.steps.sort((a, b) => Number(b.clusterId === firstId) - Number(a.clusterId === firstId));
    const rotate = provider.rotate.bind(provider);
    let rolled: string | undefined;
    vi.spyOn(provider, 'rotate').mockImplementation(async (value, ctx) => {
      if (value === second.value) throw guidedError('cloudflare', true);
      const result = await rotate(value, ctx);
      rolled = result.newValue;
      return result;
    });
    let replacement: string | undefined;
    h.prompt.mockImplementation(async () => {
      expect(rolled).toBeDefined();
      expect(host.peek('api', 'CLOUDFLARE_API_TOKEN') === rolled).toBe(true);
      expect(provider.keys.get(first.ref)?.active).toBe(false);
      expect(provider.keys.get(second.ref)?.active).toBe(true);
      expect(h.entries).toContainEqual(expect.objectContaining({ event: 'created', data: expect.objectContaining({ phase: 'guided-fallback', atomicRollsAlreadyRan: true }) }));
      replacement = provider.issue('manual replacement').value;
      return replacement;
    });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(h.prompt).toHaveBeenCalledTimes(1);
    expect(report.steps.every(step => step.status === 'revoked')).toBe(true);
    expect(host.peek('api', 'CLOUDFLARE_API_TOKEN') === rolled).toBe(true);
    expect(host.peek('api', 'CLOUDFLARE_BACKUP_TOKEN') === replacement).toBe(true);
    expect(provider.revoked).toEqual([second.ref]);
    expect(host.redeploys).toEqual(['api']);
    expect(h.entries.some(entry => entry.event === 'failed')).toBe(false);
    const serialized = JSON.stringify({ report, entries: h.entries, lines: h.lines });
    for (const value of [first.value, second.value, rolled!, replacement!]) expect(serialized.includes(value)).toBe(false);
  });

  it('reveals and journals an undelivered earlier roll before prompting and retries delivery afterward', async () => {
    const provider = new FakeProvider('cloudflare', 'atomic-roll', 'cf_Ab3Cd5Ef7Gh9Jk1Lm2No4Pq6Rs8Tu0Vw_');
    const first = provider.issue('first');
    const second = provider.issue('second');
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: first.value, CLOUDFLARE_BACKUP_TOKEN: second.value });
    host.failWritesFor.add('api');
    const write = vi.spyOn(host, 'writeVariables');
    const h = await fixture(host, [provider]);
    const firstId = fingerprint(first.value, key);
    h.plan.steps.sort((a, b) => Number(b.clusterId === firstId) - Number(a.clusterId === firstId));
    const rotate = provider.rotate.bind(provider);
    let rolled: string | undefined;
    vi.spyOn(provider, 'rotate').mockImplementation(async (value, ctx) => {
      if (value === second.value) throw guidedError('cloudflare', true);
      const result = await rotate(value, ctx);
      rolled = result.newValue;
      return result;
    });
    const reveal = vi.fn<NonNullable<EngineDeps['reveal']>>().mockResolvedValue(true);
    h.deps.reveal = reveal;
    const revoke = provider.revoke.bind(provider);
    vi.spyOn(provider, 'revoke').mockImplementation(async (ref, ctx) => {
      expect(ref).toBe(second.ref);
      expect(host.redeploys).toEqual(['api']);
      expect(h.entries.some(entry => entry.event === 'deploy-result' && entry.data?.state === 'success')).toBe(true);
      await revoke(ref, ctx);
    });
    let replacement: string | undefined;
    h.prompt.mockImplementation(async () => {
      expect(write).toHaveBeenCalledTimes(4);
      expect(reveal).toHaveBeenCalledTimes(1);
      expect(reveal.mock.calls[0]?.[1] === rolled).toBe(true);
      expect(reveal.mock.calls[0]?.[0].reason).toMatch(/URGENT.*UNWRITTEN/i);
      expect(host.peek('api', 'CLOUDFLARE_API_TOKEN') === first.value).toBe(true);
      expect(provider.keys.get(first.ref)?.active).toBe(false);
      expect(provider.keys.get(second.ref)?.active).toBe(true);
      expect(provider.revoked).toEqual([]);
      expect(h.entries).toContainEqual(expect.objectContaining({
        event: 'failed', clusterId: firstId, data: expect.objectContaining({ phase: 'value-unwritten', oldRevoked: true }),
      }));
      expect(h.entries).toContainEqual(expect.objectContaining({
        event: 'created', data: expect.objectContaining({ phase: 'guided-fallback', atomicRollsAlreadyRan: true }),
      }));
      host.failWritesFor.delete('api');
      replacement = provider.issue('manual replacement').value;
      return replacement;
    });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(h.prompt).toHaveBeenCalledTimes(1);
    expect(write).toHaveBeenCalledTimes(5);
    expect(host.writes).toHaveLength(1);
    expect(host.peek('api', 'CLOUDFLARE_API_TOKEN') === rolled).toBe(true);
    expect(host.peek('api', 'CLOUDFLARE_BACKUP_TOKEN') === replacement).toBe(true);
    expect(report.steps.find(step => step.clusterId === fingerprint(second.value, key))?.status).toBe('revoked');
    expect(provider.revoked).toEqual([second.ref]);
    expect(host.redeploys).toEqual(['api']);
    const serialized = JSON.stringify({ report, entries: h.entries, lines: h.lines });
    for (const value of [first.value, second.value, rolled!, replacement!]) expect(serialized.includes(value)).toBe(false);
  });
});
