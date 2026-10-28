// Runtime governance: a sealed watcher takes the roster and policy from its authenticated config; a computer with a
// roster checkpoint refuses to fall back to single-user mode when the state file disappears.
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { createRuntime } from '../../src/cli/runtime.js';
import { configSchema } from '../../src/cli/config.js';
import { preparePolicyDraft, signPolicy } from '../../src/policy/index.js';
import { applyRoster, rosterPath, signRoster, vaultTeamAnchor } from '../../src/team/index.js';
import { FakeHttp, silentLogger } from '../helpers/fake-http.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { NOW, rosterOf, testMember } from '../team/helpers.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
const ana = testMember('ana', 'admin');

async function sealedRuntime(teamBundle: Parameters<typeof createRuntime>[0] extends infer O ? O extends { teamBundle?: infer B } ? B : never : never, settings = configSchema.parse({ team: { enabled: true } })) {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-team-rt-')); dirs.push(cwd);
  return createRuntime({ cwd, userDir: join(cwd, 'user'), vault: createFakeVault(), env: {}, hosts: [], http: new FakeHttp(), log: silentLogger,
    stdinIsTTY: false, stdoutIsTTY: false, watcherAuthorized: true, teamBundle, settings });
}

it('a sealed watcher uses the bundle roster and policy, not local state', async () => {
  const roster = signRoster({ roster: rosterOf([ana]), signatures: [] }, 'ana', ana.key);
  const draft = preparePolicyDraft({ approvals: { required: 2 }, network: { offline: true } }, { roster: roster.roster, head: null, now: NOW });
  const policy = signPolicy(draft, 'ana', ana.key);
  const rt = await sealedRuntime({ roster, policy });
  expect(rt.teamPolicy?.approvals.required).toBe(2);
  expect(rt.network.feedMode).toEqual({ offline: true, source: 'policy' });
  expect(rt.governance.policy).toMatchObject({ status: 'ok', path: 'sealed watcher config' });
  await expect(rt.assertGovernance()).resolves.toBeUndefined();
  // The watcher's quorum comes from the same bundle (createWatchRuntime), not a state reader.
  expect(rt.teamQuorum()).toBeNull();
});

it('a sealed watcher in team mode without a sealed roster pauses changes', async () => {
  const rt = await sealedRuntime(null);
  await expect(rt.assertGovernance()).rejects.toThrow('Changes are paused. Team mode is on, but the sealed watcher config carries no team roster. Run keysentry watcher setup again.');
  await expect(rt.prepareExecution()).rejects.toThrow(/sealed watcher config carries no team roster/);
});

it('a deleted roster state file with a vault checkpoint pauses changes instead of falling back to single-user mode', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-team-rt-')); dirs.push(cwd);
  const vault = createFakeVault();
  const open = () => createRuntime({ cwd, userDir: join(cwd, 'user'), vault, env: {}, hosts: [], http: new FakeHttp(), log: silentLogger, stdinIsTTY: true, stdoutIsTTY: true,
    settings: configSchema.parse({ team: { enabled: false } }) });
  const first = await open();
  await applyRoster(first.store, signRoster({ roster: rosterOf([ana]), signatures: [] }, 'ana', ana.key), { anchor: vaultTeamAnchor(vault, first.projectId, 'roster') });
  await rm(rosterPath(first.store));
  const second = await open();
  await expect(second.assertGovernance()).rejects.toThrow(/The saved team roster is missing, but this computer applied version 1/);
  // State reset removes the checkpoints with the state files.
  await second.resetState(true);
  expect(await vault.get(`project/${second.projectId}/team/roster-head`)).toBeNull();
  await expect((await open()).assertGovernance()).resolves.toBeUndefined();
});
