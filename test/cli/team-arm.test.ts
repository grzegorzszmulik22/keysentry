// Arming inside a team policy: refused keys and hosts, clamped wave size and grace, multi-admin widening refused,
// and governance blockers stop arming before any scan.
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { buildInventory, createStateCipher, createStateStore } from '../../src/core/index.js';
import { generateDeviceKey } from '../../src/security/index.js';
import { createAutopilotManager, recordDrill } from '../../src/cli/autopilot.js';
import { CliError } from '../../src/cli/errors.js';
import { svc } from '../helpers/fakes.js';
import type { TeamPolicy } from '../../src/types.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
const at = new Date('2026-10-27T12:00:00Z');

function rules(changes: Partial<Pick<TeamPolicy, 'autopilot' | 'approvals' | 'rotation'>>): TeamPolicy {
  return { v: 1, teamId: 'team-test-0001', version: 1, prev: null, updatedAt: at.toISOString(), autopilot: {}, approvals: { required: 1, wideningAdmins: 1 },
    network: {}, notify: {}, rotation: {}, audit: {}, ...changes };
}

async function fixture(policy: TeamPolicy | null, blocked = false) {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-team-arm-')); dirs.push(cwd);
  const store = createStateStore({ cwd, cipher: createStateCipher(Buffer.alloc(32, 6)) });
  const inventory = buildInventory([
    { host: 'railway', services: [{ service: svc('railway', 'api'), vars: [{ name: 'OPENROUTER_API_KEY', value: 'sk-or-v1-old-secret-value-00000000000000', sealed: false }] }] },
    { host: 'vercel', services: [{ service: svc('vercel', 'web'), vars: [{ name: 'OPENAI_API_KEY', value: 'sk-proj-old-secret-value-000000000000000000', sealed: false }] }] },
  ], Buffer.alloc(32, 8), at);
  let scans = 0;
  const manager = createAutopilotManager({ store, projectId: 'project', deviceKey: async () => generateDeviceKey(),
    audit: { append: async () => {}, checkpoint: async () => {}, verify: async () => ({ ok: true, entries: 0, checkpoints: 0 }) },
    scan: async () => { scans++; return inventory; }, rotateCluster: async () => { throw new Error('no rotation in this test'); }, now: () => at, assertHuman: () => {},
    teamPolicy: () => policy, assertChanges: async () => { if (blocked) throw new CliError('Changes are paused. The team policy requires audit export.'); } });
  await recordDrill(store, { passed: true, at });
  return { manager, inventory, get scans() { return scans; } };
}

it('arms only keys and hosts the policy allows, and clamps wave size and grace', async () => {
  const f = await fixture(rules({ autopilot: { allowedHosts: ['railway'], maxServicesPerWave: 2 }, rotation: { minGraceSeconds: 1800 } }));
  const result = await f.manager.arm({ graceMinutes: 5, maxServices: 50 });
  expect(result.plan.hosts).toEqual(['railway']);
  expect(result.plan.clusters.map(cluster => cluster.provider)).toEqual(['openrouter']);
  expect(result.plan.maxServicesPerWave).toBe(2);
  expect(result.plan.graceSeconds).toBe(1800);
  expect(result.refused).toContainEqual({ clusterId: expect.any(String), reason: 'The team policy does not let autopilot change one of the hosts that use this key.' });
});

it('refuses an explicit host outside the policy, a provider outside it, and multi-admin widening', async () => {
  const hosts = await fixture(rules({ autopilot: { allowedHosts: ['railway'] } }));
  await expect(hosts.manager.arm({ hosts: ['railway', 'vercel'] })).rejects.toThrow('The armed plan is outside the team policy. The armed plan watches a host the team policy does not allow.');
  const providers = await fixture(rules({ autopilot: { allowedProviders: ['anthropic'] } }));
  await expect(providers.manager.arm()).rejects.toThrow('No selected keys are eligible for autopilot. The team policy does not let autopilot rotate keys from this provider.');
  const widening = await fixture(rules({ approvals: { required: 1, wideningAdmins: 2 } }));
  await expect(widening.manager.arm()).rejects.toThrow(/arming need 2 admins/);
  expect(widening.scans).toBe(0);
});

it('a governance blocker stops arming before anything is scanned; disarm still works', async () => {
  const f = await fixture(null, true);
  await expect(f.manager.arm()).rejects.toThrow('Changes are paused. The team policy requires audit export.');
  expect(f.scans).toBe(0);
  await expect(f.manager.disarm()).resolves.toEqual({ disarmed: true, relay: false });
});
