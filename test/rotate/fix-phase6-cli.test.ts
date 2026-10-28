// fix-phase6 M1, end to end: a real CLI run (runCli with the runtime's redactor, journal wrapper and report store)
// keeps public key ids readable, so `keysentry undo` can retire the replacement key it names.
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '../../src/cli/index.js';
import { createRuntime } from '../../src/cli/runtime.js';
import { getProvider } from '../../src/providers/index.js';
import type { ProviderAdapter, ProviderContext, RotationResult } from '../../src/types.js';
import { FakeHost } from '../helpers/fakes.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { createFakeInFlight } from '../helpers/fake-inflight.js';

const sid = () => `SK${randomBytes(16).toString('hex')}`;
const secret = () => randomBytes(24).toString('base64url');

/** Twilio-shaped: a secret paired with its public SK… SID, which travels as a companion and names the key. */
class FakeTwilio implements ProviderAdapter {
  readonly id = 'twilio' as const;
  readonly method = 'auto' as const;
  readonly keys = new Map<string, { secret: string; active: boolean }>();
  issue() { const pair = { sid: sid(), secret: secret() }; this.keys.set(pair.sid, { secret: pair.secret, active: true }); return pair; }
  private sidOf(value: string) { for (const [ref, item] of this.keys) if (item.secret === value) return ref; return null; }
  async verify(value: string) { const ref = this.sidOf(value); return ref && this.keys.get(ref)!.active ? { ok: true, status: 200 } : { ok: false, status: 401 }; }
  async rotate(value: string, ctx: ProviderContext): Promise<RotationResult> {
    const oldSid = this.sidOf(value);
    const next = this.issue();
    const holders = Object.entries(ctx.siblingVars ?? {}).filter(([, current]) => current === oldSid).map(([name]) => name);
    return { newValue: next.secret, oldKeyRef: oldSid, newKeyRef: next.sid, oldRevoked: false, companions: Object.fromEntries(holders.map(name => [name, next.sid])) };
  }
  async revoke(ref: string) { const item = this.keys.get(ref); if (!item) throw new Error('unknown'); item.active = false; }
  async resolveKeyRef(value: string) { return this.sidOf(value); }
  guidance() { return { url: 'https://example.invalid/twilio', steps: ['Create a key'] }; }
}

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

describe('public key ids through the CLI (M1)', () => {
  it('rotate --execute journals and reports the readable SID, and undo retires the replacement it names', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'keysentry-fix6-cli-')); dirs.push(cwd);
    const twilio = new FakeTwilio();
    const old = twilio.issue();
    const host = new FakeHost('railway'); host.pendingPolls = 0;
    host.addService('api', { TWILIO_API_KEY: old.sid, TWILIO_API_SECRET: old.secret });
    const runtime = await createRuntime({
      cwd, vault: createFakeVault(), inflight: createFakeInFlight(), userDir: join(cwd, '.user'),
      stdinIsTTY: true, stdoutIsTTY: true, grace: async () => 'defer',
      env: {}, hosts: [host], providers: id => id === 'twilio' ? twilio : getProvider(id), http: new FakeHttp(), log: silentLogger, feeds: [], sleep: async () => {},
    });
    const output: string[] = []; const errors: string[] = [];
    const io = { runtime, output: (line: string) => output.push(line), error: (line: string) => errors.push(line) };

    expect(await runCli(['scan', '--json'], io), errors.join('\n')).toBe(0);
    expect(await runCli(['rotate', '--execute', '--yes', '--json'], io), errors.join('\n')).toBe(0);
    const newSid = host.peek('api', 'TWILIO_API_KEY')!;
    expect(newSid).toMatch(/^SK[0-9a-f]{32}$/);
    expect(newSid).not.toBe(old.sid);
    const printed = JSON.parse(output.at(-1)!) as { report: { planId: string; status: string; steps: { newKeyRef?: string; oldKeyRef?: string }[] } };
    const { report } = printed;
    expect(report.status).toBe('grace-pending');
    expect(report.steps[0]).toMatchObject({ oldKeyRef: old.sid, newKeyRef: newSid });

    // The runtime's journal wrapper and report store keep the ids; the secrets stay out of everything persisted.
    const entries = (await runtime.store.journal().read()).filter(entry => entry.planId === report.planId);
    const refs = entries.flatMap(entry => [entry.data?.oldKeyRef, entry.data?.newKeyRef, entry.data?.keyRef]).filter((ref): ref is string => typeof ref === 'string');
    expect(refs).toContain(newSid);
    expect(refs.filter(ref => !/^SK[0-9a-f]{32}$/.test(ref))).toEqual([]);
    expect((await runtime.rotationReport(report.planId))?.steps[0]?.newKeyRef).toBe(newSid);
    const persisted = JSON.stringify(entries) + JSON.stringify(await runtime.rotationReport(report.planId));
    expect(persisted).not.toContain(old.secret);
    expect(persisted).not.toContain(host.peek('api', 'TWILIO_API_SECRET')!);
    expect([...output, ...errors].join('\n')).not.toContain(old.secret);

    expect(await runCli(['undo', report.planId, '--json'], io), errors.join('\n')).toBe(0);
    const undone = JSON.parse(output.at(-1)!) as { unavailable: unknown[]; newKeysRevoked: string[] };
    expect(undone.unavailable).toEqual([]);
    expect(undone.newKeysRevoked).toEqual([newSid]);
    expect(host.peek('api', 'TWILIO_API_KEY')).toBe(old.sid);
    expect(host.peek('api', 'TWILIO_API_SECRET')).toBe(old.secret);
    expect(twilio.keys.get(newSid)?.active).toBe(false);
    expect(twilio.keys.get(old.sid)?.active).toBe(true);
  });
});
