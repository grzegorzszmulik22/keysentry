import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configSchema, type ConfigSettings } from '../../src/cli/config.js';
import { createStateCipher, createStateStore, type StateStore } from '../../src/core/store.js';
import { assertChangesAllowed, buildTeamBundle, loadGovernance, parseTeamBundle, policyRules, preparePolicyDraft, signPolicy } from '../../src/policy/index.js';
import { applyRoster, signRoster } from '../../src/team/index.js';
import { parseWatcherConfig, WatcherConfigError } from '../../src/watcher/config.js';
import { openWatcherConfig, sealWatcherConfig } from '../../src/watcher/seal.js';
import type { SignedTeamPolicy, SignedTeamRoster } from '../../src/types.js';
import { NOW, rosterOf, testMember } from '../team/helpers.js';

const ana = testMember('ana', 'admin');
const cat = testMember('cat', 'operator');
let dir: string;
let store: StateStore;
let roster: SignedTeamRoster;
let policy: SignedTeamPolicy;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'keysentry-governance-'));
  store = createStateStore({ cwd: dir, cipher: createStateCipher(Buffer.alloc(32, 5)) });
  roster = signRoster(rosterOf([ana, cat]), 'ana', ana.key);
  policy = signPolicy(preparePolicyDraft({ network: { requireProxy: true }, autopilot: { maxServicesPerWave: 2 } }, { roster: roster.roster, head: null, now: NOW }), 'ana', ana.key);
});
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

const settingsWith = (team: { enabled?: boolean; policyFile?: string }, extra: Record<string, unknown> = {}): ConfigSettings => configSchema.parse({ team, ...extra });
const governance = (settings: ConfigSettings, env: NodeJS.ProcessEnv = {}) => loadGovernance({ store, settings, cwd: dir, env });

describe('loadGovernance', () => {
  test('no team and no policy: nothing changes and nothing is blocked', async () => {
    const result = await governance(settingsWith({}));
    expect(result).toMatchObject({ team: null, policy: { status: 'none' }, blockers: [] });
    expect(() => assertChangesAllowed(result)).not.toThrow();
    expect(policyRules(result)).toBeNull();
  });

  test('team mode and the saved roster must agree', async () => {
    expect((await governance(settingsWith({ enabled: true }))).blockers).toEqual([expect.stringMatching(/Team mode is on in keysentry.yaml, but this project has no team roster/)]);
    await applyRoster(store, roster);
    expect((await governance(settingsWith({ enabled: false }))).blockers).toEqual([expect.stringMatching(/team.enabled is false/)]);
    expect((await governance(settingsWith({ enabled: true }))).blockers).toEqual([]);
  });

  test('a policy narrows the settings and adds its own requirements', async () => {
    await applyRoster(store, roster);
    await writeFile(join(dir, 'policy.json'), JSON.stringify(policy));
    const blocked = await governance(settingsWith({ enabled: true, policyFile: 'policy.json' }));
    expect(blocked.settings.autopilot.maxServices).toBe(2);
    expect(blocked.blockers).toEqual(['The team policy requires an HTTP proxy. Set network.proxy in keysentry.yaml or HTTPS_PROXY.']);
    expect(() => assertChangesAllowed(blocked)).toThrow('Changes are paused. The team policy requires an HTTP proxy.');
    const allowed = await governance(settingsWith({ enabled: true, policyFile: 'policy.json' }), { HTTPS_PROXY: 'http://proxy.internal:3128' });
    expect(allowed.blockers).toEqual([]);
    expect(policyRules(allowed)?.network.requireProxy).toBe(true);
  });

  test('a missing policy file or an unreadable roster blocks changes with a specific message', async () => {
    await applyRoster(store, roster);
    expect((await governance(settingsWith({ enabled: true, policyFile: 'nope.json' }))).blockers).toEqual(['The team policy file named in team.policyFile was not found.']);
    const raw = await store.readJson<Record<string, unknown>>('plan', join(store.paths.dir, 'team-roster.json'));
    await store.writeJson('plan', join(store.paths.dir, 'team-roster.json'), { ...raw, hash: 'f'.repeat(64) });
    const result = await governance(settingsWith({ enabled: true, policyFile: 'policy.json' }));
    expect(result.blockers).toEqual(['The saved team roster could not be verified. Restore it with keysentry team apply.', 'The team policy cannot be checked without a trusted roster.']);
  });
});

describe('the sealed watcher config carries the team', () => {
  const base = { v: 1, projectId: 'project-1', armed: null, trustedKeyIds: [], devicePublicKeys: [], passkeys: [], notify: { channels: [] },
    sources: { disabled: [], extra: [] }, approvals: { publicOrigin: null, relay: null }, intervalSeconds: 300 };

  test('configs without a team still parse unchanged', () => {
    expect(parseWatcherConfig(base)).toEqual(base);
  });

  test('a roster and a policy signed by its admins round-trip, including through the seal', () => {
    const parsed = parseWatcherConfig({ ...base, team: { roster, policy } });
    expect(parsed.team).toEqual({ roster, policy });
    const key = Buffer.alloc(32, 7);
    expect(openWatcherConfig(sealWatcherConfig(parsed, key), key).team).toEqual({ roster, policy });
    expect(parseTeamBundle({ roster, policy: null })).toMatchObject({ policy: null, rosterHash: expect.stringMatching(/^[a-f0-9]{64}$/) });
  });

  test('an invalid roster, a policy not signed by its admins, or unknown fields are refused', () => {
    const unsigned = { ...policy, signatures: [] };
    for (const team of [{ roster: { ...roster, extra: 1 }, policy: null }, { roster, policy: unsigned }, { roster, policy: null, more: true }, 'roster']) {
      expect(() => parseWatcherConfig({ ...base, team })).toThrow(WatcherConfigError);
    }
  });

  test('buildTeamBundle refuses while changes are blocked and returns null without a team', async () => {
    expect(await buildTeamBundle({ store, settings: settingsWith({}), cwd: dir })).toBeNull();
    await applyRoster(store, roster);
    await writeFile(join(dir, 'policy.json'), JSON.stringify(policy));
    await expect(buildTeamBundle({ store, settings: settingsWith({ enabled: true, policyFile: 'policy.json' }), cwd: dir })).rejects.toThrow(/requires an HTTP proxy/);
    const bundle = await buildTeamBundle({ store, settings: settingsWith({ enabled: true, policyFile: 'policy.json' }, { network: { proxy: 'http://proxy.internal:3128' } }), cwd: dir });
    expect(bundle).toEqual({ roster, policy });
  });
});
