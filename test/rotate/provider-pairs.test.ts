import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { buildInventory, buildPlan, createLogger, createRedactor } from '../../src/core/index.js';
import { executePlan } from '../../src/rotate/engine.js';
import type { EngineDeps, RotateOptions } from '../../src/rotate/engine.js';
import type { JournalEntry, ProviderAdapter, ProviderContext, RotationResult } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

// Engine changes for the phase 6 providers (notes/providers-a.md §3).
const key = Buffer.alloc(32, 0x52);
const options: RotateOptions = {
  dryRun: false, revoke: 'after-deploy', redeploy: true, deployTimeoutMs: 100, pollIntervalMs: 1,
  revokeUnconfirmed: false, acceptUnplannedSealed: false, allowGenerate: true, verifyRetries: 0,
};
const sid = () => `SK${randomBytes(16).toString('hex')}`;
const secret = () => randomBytes(24).toString('base64url');

/** Twilio-shaped: an API key secret paired with its public SK… SID, which travels as a companion. */
class FakeTwilio implements ProviderAdapter {
  readonly id = 'twilio' as const;
  readonly method = 'auto' as const;
  readonly keys = new Map<string, { secret: string; active: boolean }>();
  readonly revoked: string[] = [];
  rotations = 0;
  issue(): { sid: string; secret: string } { const pair = { sid: sid(), secret: secret() }; this.keys.set(pair.sid, { secret: pair.secret, active: true }); return pair; }
  private sidOf(value: string): string | null { for (const [ref, item] of this.keys) if (item.secret === value) return ref; return null; }
  async verify(value: string) { const ref = this.sidOf(value); return ref && this.keys.get(ref)!.active ? { ok: true, status: 200 } : { ok: false, status: 401 }; }
  async rotate(value: string, ctx: ProviderContext): Promise<RotationResult> {
    this.rotations++;
    const oldSid = this.sidOf(value);
    const next = this.issue();
    const holders = Object.entries(ctx.siblingVars ?? {}).filter(([, current]) => current === oldSid).map(([name]) => name);
    return { newValue: next.secret, oldKeyRef: oldSid, newKeyRef: next.sid, oldRevoked: false,
      companions: Object.fromEntries(holders.map(name => [name, next.sid])) };
  }
  async revoke(ref: string) { const item = this.keys.get(ref); if (!item) throw new Error('unknown'); item.active = false; this.revoked.push(ref); }
  async resolveKeyRef(value: string) { return this.sidOf(value); }
  guidance() { return { url: 'https://example.invalid/twilio', steps: ['Create a key'] }; }
}

async function fixture(host: FakeHost, providers: ProviderAdapter[]) {
  const inv = buildInventory([{ host: host.id, services: await Promise.all((await host.listServices())
    .map(async service => ({ service, vars: await host.readVariables(service) }))) }], key);
  const plan = buildPlan(inv);
  const entries: JournalEntry[] = [];
  const redactor = createRedactor();
  const log = createLogger({ redactor, level: 'debug', json: true, sink: () => undefined });
  const deps: EngineDeps = {
    hosts: { [host.id]: host }, providers(id) { const found = providers.find(candidate => candidate.id === id); if (!found) throw new Error('missing'); return found; },
    providerCtx: { http: new FakeHttp(), credentials: {}, log },
    journal: { async append(entry) { entries.push(structuredClone(entry)); }, async read() { return entries; } },
    prompt: async () => null, reveal: async () => true, fingerprintKey: key, redactor, log, sleep: async () => undefined,
  };
  return { inv, plan, deps, entries };
}

describe('Twilio key SIDs', () => {
  it('stay readable in journal and report key references, so finish and grace revocation can name the old key', async () => {
    const twilio = new FakeTwilio();
    const old = twilio.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('api', { TWILIO_API_KEY: old.sid, TWILIO_API_SECRET: old.secret });
    const h = await fixture(host, [twilio]);
    expect(h.plan.steps).toHaveLength(1);
    expect(h.plan.steps[0]!.provider).toBe('twilio');

    const report = await executePlan(h.plan, h.inv, h.deps, { ...options, revoke: 'never' });

    const created = h.entries.find(entry => entry.event === 'created');
    expect(created?.data?.oldKeyRef).toBe(old.sid);
    expect(created?.data?.newKeyRef).toMatch(/^SK[0-9a-f]{32}$/);
    expect(report.steps[0]!.oldKeyRef).toBe(old.sid);
    // The secret itself never reaches the journal.
    expect(JSON.stringify(h.entries)).not.toContain(old.secret);
    // The new SID was delivered with its secret, under the same variable name.
    expect(host.peek('api', 'TWILIO_API_KEY')).toBe(created?.data?.newKeyRef);
  });

  it('refuses before any change when consumers hold different SIDs for the same secret', async () => {
    const twilio = new FakeTwilio();
    const old = twilio.issue();
    const host = new FakeHost('railway');
    host.addService('api', { TWILIO_API_KEY: old.sid, TWILIO_API_SECRET: old.secret });
    host.addService('worker', { TWILIO_API_KEY: sid(), TWILIO_API_SECRET: old.secret });
    const h = await fixture(host, [twilio]);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]).toMatchObject({ status: 'failed', error: expect.stringMatching(/Twilio API key SIDs are missing or held under different variable names/) });
    expect(twilio.rotations).toBe(0);
    expect(host.writes).toEqual([]);
  });

  it('refuses when consumers hold the same SID under different variable names', async () => {
    const twilio = new FakeTwilio();
    const old = twilio.issue();
    const host = new FakeHost('railway');
    host.addService('api', { TWILIO_API_KEY: old.sid, TWILIO_API_SECRET: old.secret });
    host.addService('worker', { TWILIO_API_SID: old.sid, TWILIO_API_SECRET: old.secret });
    const h = await fixture(host, [twilio]);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.steps[0]!.status).toBe('failed');
    expect(twilio.rotations).toBe(0);
    expect(host.writes).toEqual([]);
  });

  it('rotates matching pairs in every consumer and revokes the old key by its SID', async () => {
    const twilio = new FakeTwilio();
    const old = twilio.issue();
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('api', { TWILIO_API_KEY: old.sid, TWILIO_API_SECRET: old.secret });
    host.addService('worker', { TWILIO_API_KEY: old.sid, TWILIO_API_SECRET: old.secret });
    const h = await fixture(host, [twilio]);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.status).toBe('complete');
    expect(twilio.revoked).toEqual([old.sid]);
    const newSid = host.peek('api', 'TWILIO_API_KEY');
    expect(newSid).not.toBe(old.sid);
    expect(host.peek('worker', 'TWILIO_API_KEY')).toBe(newSid);
    expect(h.entries.find(entry => entry.event === 'revoked')?.data?.oldKeyRef).toBe(old.sid);
  });
});

describe('companion write scope (Upstash and every other companion)', () => {
  it('writes a companion only where that variable already holds the same old value', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const rotate = provider.rotate.bind(provider);
    provider.rotate = async (value, ctx) => ({ ...await rotate(value, ctx), companions: { SECOND_FORM: 'second-form-new' } });
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    // api is the context service. worker never had the variable; other holds a different credential under that name.
    host.addService('api', { OPENAI_API_KEY: old.value, SECOND_FORM: 'second-form-old' });
    host.addService('worker', { OPENAI_API_KEY: old.value });
    host.addService('other', { OPENAI_API_KEY: old.value, SECOND_FORM: 'another-database' });
    host.addService('same', { OPENAI_API_KEY: old.value, SECOND_FORM: 'second-form-old' });
    const h = await fixture(host, [provider]);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(report.status).toBe('complete');
    expect(host.peek('api', 'SECOND_FORM')).toBe('second-form-new');
    expect(host.peek('same', 'SECOND_FORM')).toBe('second-form-new');
    expect(host.peek('worker', 'SECOND_FORM')).toBeUndefined();
    expect(host.peek('other', 'SECOND_FORM')).toBe('another-database');
    for (const write of host.writes.filter(write => write.serviceId === 'worker' || write.serviceId === 'other')) {
      expect(Object.keys(write.vars)).toEqual(['OPENAI_API_KEY']);
    }
  });

  it('warns instead of writing when the companion is write-only in another consumer', async () => {
    const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
    const old = provider.issue();
    const rotate = provider.rotate.bind(provider);
    provider.rotate = async (value, ctx) => ({ ...await rotate(value, ctx), companions: { SECOND_FORM: 'second-form-new' } });
    const host = new FakeHost('railway');
    host.pendingPolls = 0;
    host.addService('api', { OPENAI_API_KEY: old.value, SECOND_FORM: 'second-form-old' });
    host.addService('worker', { OPENAI_API_KEY: old.value, SECOND_FORM: 'second-form-old' }, ['SECOND_FORM']);
    const h = await fixture(host, [provider]);

    const report = await executePlan(h.plan, h.inv, h.deps, options);

    expect(host.peek('worker', 'SECOND_FORM')).toBe('second-form-old');
    expect(report.steps[0]!.warnings.join(' ')).toMatch(/Companion SECOND_FORM at .* is write-only and was not changed/);
  });
});
