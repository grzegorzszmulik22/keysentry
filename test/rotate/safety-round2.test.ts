import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor, fingerprint } from '../../src/core/index.js';
import { executePlan } from '../../src/rotate/engine.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/engine.js';
import { RotationAbortedError } from '../../src/types.js';
import type { JournalEntry, ProviderAdapter } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

const key = Buffer.alloc(32, 0x82);
const options: RotateOptions = {
  dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 1,
  revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0,
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
  const deps: EngineDeps = {
    hosts: { [host.id]: host },
    providers(id) { const provider = providers.find(candidate => candidate.id === id); if (!provider) throw new Error('Missing test provider'); return provider; },
    providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: { async append(entry) { entries.push(structuredClone(entry)); }, async read() { return entries; } },
    prompt: async () => null, reveal: async () => true, fingerprintKey: key, redactor, log,
    sleep: async () => undefined,
  };
  return { inv, plan, deps, entries, lines };
}

function atomicProvider() { return new FakeProvider('cloudflare', 'atomic-roll', 'cf_TokenAz9Y8X7W6V5U4T3S2R1Q_'); }

afterEach(() => vi.restoreAllMocks());

describe('round 2 atomic roll safety', () => {
  it('skips unattended atomic rolls before any mutation', async () => {
    const provider = atomicProvider();
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    const h = await fixture(host, [provider]);
    delete h.deps.reveal;

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]).toMatchObject({ status: 'skipped', warnings: expect.arrayContaining(['atomic roll needs an interactive run']) });
    expect(provider.keys.size).toBe(1);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
    expect(host.writes).toEqual([]);
    expect(host.redeploys).toEqual([]);
  });

  it.each([false, true])('honors revoke never even with revokeUnconfirmed=%s', async revokeUnconfirmed => {
    const provider = atomicProvider();
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    const h = await fixture(host, [provider]);

    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, revoke: 'never', revokeUnconfirmed });

    expect(report.steps[0]?.status).toBe('skipped');
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/atomic.*revoke.*never/i);
    expect(provider.keys.size).toBe(1);
    expect(provider.keys.get(old.ref)?.active).toBe(true);
    expect(host.writes).toEqual([]);
  });

  for (const kind of ['host-without-redeploy', 'redeploy-disabled', 'vercel-preview', 'vercel-development', 'fly-manual', 'shared-without-references'] as const) {
    it(`skips atomic roll with known unconfirmed activation: ${kind}`, async () => {
      const provider = atomicProvider();
      const old = provider.issue();
      const host = new FakeHost(kind.startsWith('vercel') ? 'vercel' : kind === 'fly-manual' ? 'fly' : 'railway', { redeploy: kind !== 'host-without-redeploy' });
      const id = kind === 'shared-without-references' ? '' : 'api';
      host.addService(id, { CLOUDFLARE_API_TOKEN: old.value }, [], kind === 'vercel-preview' ? 'preview' : kind === 'vercel-development' ? 'development' : 'production');
      const h = await fixture(host, [provider]);

      const report = await executePlan(h.plan, h.inv, h.deps, { ...options, redeploy: kind !== 'redeploy-disabled' });

      expect(report.steps[0]?.status).toBe('skipped');
      expect(report.steps[0]?.warnings.join(' ')).toMatch(/atomic.*activation.*unconfirmed/i);
      expect(provider.keys.size).toBe(1);
      expect(provider.keys.get(old.ref)?.active).toBe(true);
      expect(host.writes).toEqual([]);
      expect(host.redeploys).toEqual([]);
    });
  }

  it('allows explicitly accepted unconfirmed activation and warns before the atomic roll', async () => {
    const provider = atomicProvider();
    const old = provider.issue();
    const host = new FakeHost('dotenv', { redeploy: false });
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    const h = await fixture(host, [provider]);
    const rotate = provider.rotate.bind(provider);
    vi.spyOn(provider, 'rotate').mockImplementation(async (...args) => {
      expect(h.lines.join(' ')).toMatch(/revokeUnconfirmed/);
      return rotate(...args);
    });

    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, revokeUnconfirmed: true });

    expect(provider.keys.get(old.ref)?.active).toBe(false);
    expect(host.writes).toHaveLength(1);
    expect(report.deployments[0]?.state).toBe('unconfirmed');
    expect(report.steps[0]?.warnings.join(' ')).toMatch(/revokeUnconfirmed/);
  });

  it('skips an atomic shared source whose only cluster reference points to another direct copy', async () => {
    const provider = atomicProvider();
    const old = provider.issue();
    const host = new FakeHost('railway');
    const shared = host.addService('', { CLOUDFLARE_API_TOKEN: old.value });
    shared.serviceName = 'shared';
    host.addService('source', { CLOUDFLARE_API_TOKEN: old.value });
    host.addService('api', { CLOUDFLARE_API_TOKEN: '${{source.CLOUDFLARE_API_TOKEN}}' });
    const h = await fixture(host, [provider]);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]?.status).toBe('skipped');
    expect(provider.keys.get(old.ref)?.active).toBe(true);
    expect(provider.keys.size).toBe(1);
    expect(host.writes).toEqual([]);
  });

  it('allows atomic shared rotation when every service in its reference chain deploys', async () => {
    const provider = atomicProvider();
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    const shared = host.addService('', { CLOUDFLARE_API_TOKEN: old.value });
    shared.serviceName = 'shared';
    host.addService('middle', { CLOUDFLARE_API_TOKEN: '${{shared.CLOUDFLARE_API_TOKEN}}' });
    host.addService('api', { CLOUDFLARE_API_TOKEN: '${{middle.CLOUDFLARE_API_TOKEN}}' });
    const h = await fixture(host, [provider]);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]?.status).toBe('revoked');
    expect(report.deployments.every(deployment => deployment.state === 'success')).toBe(true);
    expect(host.redeploys.sort()).toEqual(['api', 'middle']);
    expect(provider.keys.get(old.ref)?.active).toBe(false);
    expect(provider.revoked).toEqual([]);
  });

  it.each(['false', 'throws', 'undefined', 'missing-after-roll', 'true'] as const)('records actual delivery when reveal is %s', async outcome => {
    const provider = atomicProvider();
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    host.failWritesFor.add('api');
    const h = await fixture(host, [provider]);
    if (outcome === 'undefined') h.deps.reveal = (async () => undefined) as unknown as NonNullable<EngineDeps['reveal']>;
    else h.deps.reveal = async (_info, value) => {
      if (outcome === 'throws') throw new Error(`unsafe reveal failure ${value}`);
      return outcome === 'true';
    };
    const rotate = provider.rotate.bind(provider);
    vi.spyOn(provider, 'rotate').mockImplementation(async (...args) => {
      const result = await rotate(...args);
      if (outcome === 'missing-after-roll') delete h.deps.reveal;
      return result;
    });

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    const replacement = [...provider.keys.values()].find(candidate => candidate.ref !== old.ref)!;
    expect(report.steps[0]?.status).toBe('failed');
    const recovery = h.entries.find(entry => entry.data?.phase === 'value-unwritten');
    expect(recovery?.data).toMatchObject({ revealed: outcome === 'true', valueLost: outcome !== 'true', oldRevoked: true });
    if (outcome === 'true') {
      expect(report.steps[0]?.error).toMatch(/revealed.*paste|paste.*revealed/i);
      expect(report.steps[0]?.error).not.toMatch(/LOST/);
    } else {
      expect(report.steps[0]?.error).toMatch(/LOST.*provider dashboard.*roll again/i);
      expect(JSON.stringify(recovery)).toMatch(/LOST.*provider dashboard.*roll again/i);
      expect(report.steps[0]?.warnings.join(' ')).not.toMatch(/was revealed|paste the replacement/i);
    }
    expect(host.peek('api', 'CLOUDFLARE_API_TOKEN')).toBe(old.value);
    expect(provider.keys.get(old.ref)?.active).toBe(false);
    expect(JSON.stringify({ report, entries: h.entries, lines: h.lines })).not.toContain(replacement.value);
  });

  it('records loss during emergency recovery when reveal does not deliver', async () => {
    const provider = atomicProvider();
    const old = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: old.value });
    host.failWritesFor.add('api');
    const h = await fixture(host, [provider]);
    h.deps.reveal = async () => false;
    const append = h.deps.journal.append.bind(h.deps.journal);
    h.deps.journal.append = async entry => { if (entry.event === 'created') throw new Error('journal unavailable'); await append(entry); };

    await expect(executePlan(h.plan, h.inv, h.deps, options)).rejects.toThrow('Unable to record rotation journal');

    expect(h.entries).toContainEqual(expect.objectContaining({ event: 'failed', data: expect.objectContaining({ phase: 'value-unwritten', valueLost: true, revealed: false, error: expect.stringMatching(/LOST.*provider dashboard.*roll again/i) }) }));
    expect(h.lines.join(' ')).toMatch(/LOST.*provider dashboard.*roll again/i);
  });

  it('reports a lost earlier atomic value before a late fallback prompt', async () => {
    const provider = atomicProvider();
    const first = provider.issue();
    const second = provider.issue();
    const host = new FakeHost('railway');
    host.addService('api', { CLOUDFLARE_API_TOKEN: first.value, CLOUDFLARE_OTHER_TOKEN: second.value });
    host.failWritesFor.add('api');
    const h = await fixture(host, [provider]);
    h.plan.steps.sort((a, b) => Number(b.clusterId === fingerprint(first.value, key)) - Number(a.clusterId === fingerprint(first.value, key)));
    const rotate = provider.rotate.bind(provider);
    vi.spyOn(provider, 'rotate').mockImplementation(async (oldValue, ctx) => {
      if (oldValue === second.value) throw Object.assign(new Error('guided required'), { code: 'GUIDED_ROTATION_REQUIRED' });
      return rotate(oldValue, ctx);
    });
    h.deps.reveal = async () => false;
    h.deps.prompt = async () => {
      expect(h.entries).toContainEqual(expect.objectContaining({ event: 'failed', data: expect.objectContaining({ valueLost: true }) }));
      return null;
    };

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps.find(step => step.clusterId === fingerprint(first.value, key))?.error).toMatch(/LOST.*provider dashboard.*roll again/i);
  });
});

describe('round 2 prompt cancellation', () => {
  it('aborts all remaining guided, automatic, generated and atomic work without mutation', async () => {
    const guided = new FakeProvider('anthropic', 'guided', 'sk-ant-api03-');
    const automatic = new FakeProvider('openai', 'auto', 'sk-proj-');
    const atomic = atomicProvider();
    const generated = new FakeProvider('app-secret', 'generate', 'session_random_');
    const oldGuided = guided.issue();
    const host = new FakeHost('railway');
    host.addService('api', {
      ANTHROPIC_API_KEY: oldGuided.value, OPENAI_API_KEY: automatic.issue().value,
      CLOUDFLARE_API_TOKEN: atomic.issue().value, SESSION_SECRET: generated.issue().value,
    });
    const h = await fixture(host, [guided, automatic, atomic, generated]);
    h.deps.prompt = async () => { throw new RotationAbortedError(`unsafe cancellation ${oldGuided.value}`); };

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps.every(step => step.status === 'skipped')).toBe(true);
    expect(host.writes).toEqual([]);
    expect(host.redeploys).toEqual([]);
    for (const provider of [guided, automatic, atomic, generated]) {
      expect(provider.keys.size).toBe(1);
      expect(provider.revoked).toEqual([]);
    }
    expect(h.entries.at(-1)).toMatchObject({ event: 'plan-end', data: { aborted: true } });
    expect(report.finishedAt).not.toBe('');
    expect(JSON.stringify({ report, entries: h.entries, lines: h.lines })).not.toContain(oldGuided.value);
  });

  it('stops on cancellation of the second guided prompt before any host or provider mutation', async () => {
    const provider = new FakeProvider('anthropic', 'guided', 'sk-ant-api03-');
    const host = new FakeHost('railway');
    host.addService('api', { ANTHROPIC_API_KEY: provider.issue().value, ANTHROPIC_OTHER_KEY: provider.issue().value });
    const h = await fixture(host, [provider]);
    let prompts = 0;
    h.deps.prompt = async () => { if (++prompts === 2) throw new RotationAbortedError(); return provider.issue('manual').value; };

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(prompts).toBe(2);
    expect(host.writes).toEqual([]);
    expect(host.redeploys).toEqual([]);
    expect(provider.revoked).toEqual([]);
    expect(report.steps.map(step => step.status)).toEqual(['skipped', 'skipped']);
    expect(h.entries.at(-1)?.data?.aborted).toBe(true);
  });

  it('delivers an earlier provider result without cleanup or further creation after fallback cancellation', async () => {
    const automatic = new FakeProvider('openai', 'auto', 'sk-proj-');
    const fallback = new FakeProvider('resend', 'auto', 're_');
    const atomic = atomicProvider();
    const host = new FakeHost('railway');
    host.addService('api', {
      OPENAI_API_KEY: automatic.issue().value, RESEND_API_KEY: fallback.issue().value,
      CLOUDFLARE_API_TOKEN: atomic.issue().value,
    });
    const h = await fixture(host, [automatic, fallback, atomic]);
    vi.spyOn(fallback, 'rotate').mockRejectedValue(Object.assign(new Error('guided required'), { code: 'GUIDED_ROTATION_REQUIRED' }));
    h.deps.prompt = async () => { throw new RotationAbortedError(); };

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(automatic.keys.size).toBe(2);
    expect(automatic.revoked).toEqual([]);
    expect(atomic.keys.size).toBe(1);
    expect(host.writes).toHaveLength(1);
    expect(host.writes[0]?.vars).toEqual({ OPENAI_API_KEY: [...automatic.keys.values()].find(key => key.name.startsWith('rotated'))!.value });
    expect(host.redeploys).toEqual(['api']);
    expect(report.steps.filter(step => step.status === 'skipped')).toHaveLength(2);
    expect(report.steps.find(step => step.status !== 'skipped')?.status).toBe('deployed');
    expect(h.entries.at(-1)?.data?.aborted).toBe(true);
  });

  it('finishes delivery and deployment after cancellation in a late atomic fallback', async () => {
    const provider = atomicProvider();
    const olds = [provider.issue(), provider.issue(), provider.issue()];
    const host = new FakeHost('railway');
    host.addService('api', Object.fromEntries(olds.map((old, i) => [`CLOUDFLARE_${i}_TOKEN`, old.value])));
    const h = await fixture(host, [provider]);
    h.plan.steps.sort((a, b) => olds.findIndex(old => fingerprint(old.value, key) === a.clusterId) - olds.findIndex(old => fingerprint(old.value, key) === b.clusterId));
    const rotate = provider.rotate.bind(provider);
    let cancelled = false;
    let mutationsAfterCancel = 0;
    vi.spyOn(provider, 'rotate').mockImplementation(async (oldValue, ctx) => {
      if (cancelled) mutationsAfterCancel++;
      if (oldValue === olds[1]!.value) throw Object.assign(new Error('guided required'), { code: 'GUIDED_ROTATION_REQUIRED' });
      return rotate(oldValue, ctx);
    });
    h.deps.prompt = async () => { cancelled = true; throw new RotationAbortedError(); };

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(cancelled).toBe(true);
    expect(mutationsAfterCancel).toBe(0);
    expect(host.redeploys).toEqual(['api']);
    expect(provider.keys.size).toBe(4);
    expect(provider.keys.get(olds[2]!.ref)?.active).toBe(true);
    expect(report.steps.slice(1).map(step => step.status)).toEqual(['skipped', 'skipped']);
    expect(h.entries.at(-1)?.data?.aborted).toBe(true);
  });
});
