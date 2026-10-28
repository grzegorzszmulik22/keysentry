import type { Command } from 'commander';
import { randomBytes } from 'node:crypto';
import { readFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import {
  BOX_DEPLOYMENT_VARIABLES, BOX_STATE_DIR, createHttpBoxRelay, createNoticeSender, encodeBoxPayload, isAllowed, isBoxId, startBoxAgent,
  startProductionBoxAgent, verifyAllowList, BoxAgentError, BoxRelayError, TeeTokenError,
  type AllowListVerificationKey, type BoxEnrollPayload, type BoxNoticeKit, type BoxRelay, type BoxSettings,
} from '../box/index.js';
import { createFetchHttp } from '../http.js';
import { RELEASE_PUBLIC_KEYS } from '../release/index.js';
import { assertHumanForMutation } from '../safety/index.js';
import type { BoxSealMode, HttpClient, Logger } from '../types.js';
import { BOX_HONEST_CLAIM, openVerifiedBoxSession, renderBoxVerification, type BoxTrust } from './box-flow.js';
import { CliError } from './errors.js';
import { localDeviceKeys } from './phase2.js';
import { listPasskeys } from './passkeys.js';
import { promptVaultValue, type PromptIO } from './prompts.js';
import type { KeysentryRuntime } from './runtime.js';
import { buildWatcherSetupConfig, createWatcherDeployment } from './watcher.js';
import { prepareWatcherDeployment } from './watcher-bootstrap.js';

/** A box this project knows. Only emulator boxes exist until the hosted box launches. */
export interface BoxRecord {
  boxId: string;
  emulator: true;
  mode: BoxSealMode;
  relayOrigin: string;
  emulatorOrigin: string;
  policy: { projectId: string; serviceAccount: string; allowedDigests: string[]; audience: string; keyName: string };
}
interface BoxRegistry { v: 1; boxes: BoxRecord[] }

/** The parts of the control-plane package's local runner the CLI uses (it is loaded, never bundled). */
export interface LocalBoxRunner {
  startLocalBox(options: { boxId?: string; enrollmentDeviceKey?: Buffer; bootBox(runtime: {
    boxId: string; relay: BoxRelay; tee: { token(input: { audience: string; nonces: string[] }): Promise<string>; defaultToken(): Promise<string> }; http: HttpClient;
  }): Promise<{ stop(): Promise<void> }> }): Promise<{
    boxId: string; origin: string; cliToken: string; restart(): Promise<void>; close(): Promise<void>;
    emulator: { baseUrl: string; policy: BoxRecord['policy'] & { projectNumber: string } };
  }>;
}

export interface BoxCommandsOptions {
  getRuntime(): Promise<KeysentryRuntime>;
  human(action: string): void;
  emit(value: unknown, text?: string): void;
  diagnostic(text: string): void;
  json(): boolean;
  setExit(code: number): void;
  promptIO?: PromptIO;
  /** Tests inject these; the CLI loads the runner from a source checkout and uses loopback HTTP. */
  loadLocalBox?: () => Promise<LocalBoxRunner>;
  loopback?: HttpClient;
  /** Resolves when the emulator should stop: Ctrl+C in a terminal. Each `restart` line restarts the box. */
  emulatorControl?: (restart: () => Promise<void>) => Promise<void>;
  startWatcher?: (env: Record<string, string>, signal: AbortSignal, cwd: string) => Promise<unknown>;
  allowListKeys?: readonly AllowListVerificationKey[];
  sessionTimeoutMs?: number;
  pollMs?: number;
  env: NodeJS.ProcessEnv;
}

const MODES: readonly BoxSealMode[] = ['standard', 'byo-kms', 'unlock-on-restart'];
const EMULATOR_NOTE = 'Local emulator: the checks used the emulator\'s test signing keys and test digests, not Google\'s.';
const NOT_LAUNCHED = 'The hosted cloud box is not launched yet, so nothing was created. Try the whole flow on this computer with: keysentry box provision --emulator';
const registryPath = (rt: KeysentryRuntime) => join(rt.paths.dir, 'boxes.json');
const shareName = (boxId: string) => `box/${boxId}/share-b`;
const tokenName = (boxId: string) => `box/${boxId}/relay-token`;
/** The public key of the watcher a box runs; trusted for its signed approval requests and notices. */
export const boxWatcherKeyName = (boxId: string) => `box/${boxId}/watcher-public`;

async function registry(rt: KeysentryRuntime): Promise<BoxRegistry> {
  return await rt.store.readJson<BoxRegistry>('plan', registryPath(rt)) ?? { v: 1, boxes: [] };
}
async function record(rt: KeysentryRuntime, boxId: string): Promise<BoxRecord> {
  if (!isBoxId(boxId)) throw new CliError('Box names use lowercase letters, digits and hyphens, and start with a letter.');
  const found = (await registry(rt)).boxes.find(box => box.boxId === boxId);
  if (!found) throw new CliError(`There is no box named ${boxId} in this project. Start one with: keysentry box provision --emulator`);
  return found;
}

/** Exactly the given loopback origins over plain HTTP; nothing else. */
function loopbackHttp(transport: HttpClient, origins: string[]): HttpClient {
  const allowed = new Set(origins.filter(origin => /^http:\/\/127\.0\.0\.1:\d{1,5}$/.test(origin)));
  return { request(input) {
    let origin: string;
    try { origin = new URL(input.url).origin; } catch { return Promise.reject(new CliError('The local box address is invalid.')); }
    if (!allowed.has(origin)) return Promise.reject(new CliError('Only the local emulator\'s own address can be reached here.'));
    return transport.request(input);
  } };
}

async function connect(rt: KeysentryRuntime, opts: BoxCommandsOptions, box: BoxRecord): Promise<{ relay: BoxRelay; trust: BoxTrust }> {
  const http = loopbackHttp(opts.loopback ?? createFetchHttp(), [box.relayOrigin, box.emulatorOrigin]);
  const token = await rt.vault.get(tokenName(box.boxId));
  if (!token) throw new CliError(`The local emulator for ${box.boxId} is not running. Start it again with: keysentry box provision --emulator --name ${box.boxId}`);
  const credential = token.toString('utf8'); token.fill(0);
  let keys: unknown;
  try {
    const response = await http.request({ method: 'GET', url: `${box.emulatorOrigin}/jwks` });
    if (response.status !== 200) throw new Error();
    keys = (response.json<{ keys?: unknown }>()).keys;
    if (!Array.isArray(keys)) throw new Error();
  } catch { throw new CliError(`The local emulator for ${box.boxId} is not answering. Start it again with: keysentry box provision --emulator --name ${box.boxId}`); }
  return {
    relay: createHttpBoxRelay({ http, origin: box.relayOrigin, boxId: box.boxId, credential: async () => credential }),
    // Emulator trust is the emulator's own test keys and digests, and the output says so.
    trust: { jwks: async () => structuredClone(keys) as never, projectIds: [box.policy.projectId], serviceAccounts: [box.policy.serviceAccount],
      allowedDigests: box.policy.allowedDigests, emulator: true },
  };
}

async function verified(rt: KeysentryRuntime, opts: BoxCommandsOptions, boxId: string) {
  const box = await record(rt, boxId);
  const { relay, trust } = await connect(rt, opts, box);
  const deviceKey = await rt.signingKey();
  try {
    const session = await openVerifiedBoxSession({ relay, boxId, deviceKey, trust, now: rt.now,
      ...(opts.sessionTimeoutMs ? { timeoutMs: opts.sessionTimeoutMs } : {}), ...(opts.pollMs ? { pollMs: opts.pollMs } : {}) });
    return { box, session, deviceKey };
  } catch (error) { deviceKey.privateKeyDer.fill(0); throw error; }
}

async function noticeKit(rt: KeysentryRuntime): Promise<BoxNoticeKit> {
  const channels = rt.config.settings.notify.channels.filter(channel => channel.kind !== 'console');
  const secrets: BoxNoticeKit['secrets'] = [];
  for (const channel of channels) for (const name of await rt.vault.list(`notify/${channel.id}/`)) {
    const bytes = await rt.vault.get(name);
    try { if (bytes) secrets.push({ name, value: bytes.toString('utf8') }); } finally { bytes?.fill(0); }
  }
  return { channels: channels.map(channel => ({ ...channel })) as BoxNoticeKit['channels'], secrets };
}

/** The same deployment `watcher setup` makes, held in memory for the bundle instead of printed. */
async function deploymentFor(rt: KeysentryRuntime, opts: BoxCommandsOptions): Promise<{ values: BoxEnrollPayload['deployment']; exported: string[]; watcherPublicKeyDer: Buffer; watcherKeyId: string }> {
  const outputDir = join(rt.paths.dir, `box-deploy-${randomBytes(8).toString('hex')}`);
  try {
    const config = await buildWatcherSetupConfig({ projectId: rt.projectId, store: rt.store, vault: rt.vault,
      notifications: rt.config.settings.notify.channels, deviceKeys: () => localDeviceKeys(rt), passkeys: () => listPasskeys(rt.store, rt.vault),
      intervalSeconds: rt.config.monitor.intervalMs / 1000, relayServer: rt.config.settings.notify.relay?.server });
    const prepared = await createWatcherDeployment({ vault: rt.vault, audit: rt.audit, config, outputDir,
      prepareDeployment: secrets => prepareWatcherDeployment({ sourceVault: rt.vault, credentials: rt.credentials, settings: rt.config.settings, outputDir,
        confirmEnvironmentCredential: async name => {
          opts.diagnostic(`Copy ${name} from your environment into the cloud box? [y/N]`);
          return /^(?:y|yes)$/i.test(await promptVaultValue(`y to copy ${name}`, opts.diagnostic, opts.promptIO) ?? '');
        } }, secrets) }, 'cloud-box', { persistSigningKey: false });
    if (!prepared.deployment) throw new CliError('The deployment vault could not be prepared, so nothing was sent.');
    const values = { ...prepared.values, KEYSENTRY_WATCHER_VAULT: prepared.deployment.vaultBlob };
    if (BOX_DEPLOYMENT_VARIABLES.some(name => !values[name])) throw new CliError('The deployment is incomplete, so nothing was sent.');
    return { values, exported: prepared.deployment.exportedCredentialNames ?? [], watcherPublicKeyDer: prepared.watcherPublicKeyDer, watcherKeyId: prepared.watcherKeyId };
  } finally { await rm(outputDir, { recursive: true, force: true }); }
}

function defaultControl(restart: () => Promise<void>): Promise<void> {
  return new Promise(resolve => {
    const lines = createInterface({ input: process.stdin });
    lines.on('line', () => { void restart(); });
    const stop = () => { lines.close(); process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); resolve(); };
    process.once('SIGINT', stop); process.once('SIGTERM', stop);
  });
}

async function loadRunner(): Promise<LocalBoxRunner> {
  // A source checkout carries the control-plane package; the release bundle and the box image never do.
  const location = new URL('../../packages/control-plane/src/local-box.ts', import.meta.url).href;
  try { return await import(location) as LocalBoxRunner; }
  catch {
    throw new CliError('The local emulator runs from a source checkout of keysentry, which includes packages/control-plane. '
      + 'Clone the repository and run: npm run dev -- box provision --emulator');
  }
}

const quietLog: Logger = { debug() {}, info() {}, warn() {}, error() {} };

export function registerBoxCommands(program: Command, opts: BoxCommandsOptions): void {
  const box = program.command('box').description('Cloud box (not launched): try it locally with the emulator');

  box.command('provision').description('Start a local emulated cloud box (the hosted box is not launched)')
    .option('--emulator', 'Run the box, attestation and key release on this computer')
    .option('--mode <mode>', 'standard, byo-kms or unlock-on-restart', 'standard')
    .option('--name <name>', 'Box name', 'local-box')
    .action(async (options: { emulator?: boolean; mode: string; name: string }) => {
      if (!options.emulator) { opts.diagnostic(NOT_LAUNCHED); opts.setExit(1); return; }
      if (!MODES.includes(options.mode as BoxSealMode)) throw new CliError('Choose standard, byo-kms or unlock-on-restart.');
      if (!isBoxId(options.name)) throw new CliError('Box names use lowercase letters, digits and hyphens, and start with a letter.');
      opts.human('start a local cloud box');
      const rt = await opts.getRuntime();
      const runner = await (opts.loadLocalBox ?? loadRunner)();
      const device = (await localDeviceKeys(rt)).map(key => key.publicKeyDer);
      if (device.length === 0) throw new CliError('This computer has no device key yet. Run keysentry init first.');
      const stateDir = join(rt.paths.dir, 'box-emulator', options.name);
      const startWatcher = opts.startWatcher ?? (async (env: Record<string, string>, signal: AbortSignal, cwd: string) => {
        const { runCli } = await import('./index.js');
        return runCli(['watch'], { env, cwd, signal, stdinIsTTY: false, stdoutIsTTY: false, output: () => {}, error: () => {} });
      });
      // The emulator writes this key into the instance metadata, as the hosted control plane does.
      const local = await runner.startLocalBox({ boxId: options.name, enrollmentDeviceKey: device[0], bootBox: runtime => startBoxAgent({ boxId: runtime.boxId, relay: runtime.relay,
        tee: runtime.tee, http: runtime.http, stateDir, enrollmentDeviceKeys: device, log: quietLog, pollIntervalMs: 1_000,
        startWatcher: (env, signal) => startWatcher(env, signal, stateDir),
        sendNotice: createNoticeSender({ transport: createFetchHttp(), log: quietLog }) }) });
      const entry: BoxRecord = { boxId: local.boxId, emulator: true, mode: options.mode as BoxSealMode, relayOrigin: local.origin,
        emulatorOrigin: local.emulator.baseUrl, policy: { projectId: local.emulator.policy.projectId, serviceAccount: local.emulator.policy.serviceAccount,
          allowedDigests: [...local.emulator.policy.allowedDigests], audience: local.emulator.policy.audience, keyName: local.emulator.policy.keyName } };
      try {
        const saved = await registry(rt);
        await rt.store.writeJson('plan', registryPath(rt), { v: 1, boxes: [...saved.boxes.filter(item => item.boxId !== entry.boxId), entry] });
        await rt.vault.set(tokenName(entry.boxId), Buffer.from(local.cliToken, 'utf8'));
        opts.emit({ boxId: entry.boxId, mode: entry.mode, emulator: true, running: true }, [
          `Local emulated box ${entry.boxId} is running (${entry.mode}). Nothing here reaches Google and nothing is spent.`,
          'In another terminal in this project:',
          `  keysentry box check ${entry.boxId}`,
          `  keysentry box send-tokens ${entry.boxId}`,
          ...(entry.mode === 'unlock-on-restart' ? [`  keysentry box unlock ${entry.boxId}   (after a restart)`] : []),
          'Press Enter to restart the box, as host maintenance would. Press Ctrl+C to stop; the emulator and its box are removed.',
        ].join('\n'));
        await (opts.emulatorControl ?? defaultControl)(async () => {
          await local.restart();
          if (!opts.json()) opts.diagnostic(`Box ${entry.boxId} restarted.`);
        });
      } finally {
        await local.close();
        // The emulated box is gone with its state, so its relay token, device share and watcher key go too.
        for (const name of [tokenName(entry.boxId), shareName(entry.boxId), boxWatcherKeyName(entry.boxId)]) await rt.vault.delete(name);
        const after = await registry(rt);
        await rt.store.writeJson('plan', registryPath(rt), { v: 1, boxes: after.boxes.filter(item => item.boxId !== entry.boxId) });
        await rm(stateDir, { recursive: true, force: true });
      }
    });

  box.command('card').description('Print this computer\'s device public key, for creating a cloud box')
    .action(async () => {
      const rt = await opts.getRuntime();
      const [device] = await localDeviceKeys(rt);
      if (!device) throw new CliError('This computer has no device key yet. Run keysentry init first.');
      const deviceKey = device.publicKeyDer.toString('base64');
      opts.emit({ deviceKey, keyId: device.keyId }, ['Device public key for this computer:', deviceKey, '', `Key ID: ${device.keyId}`,
        'Paste it into "Create a box" on the keysentry cloud box page. It is a public key, not a secret.',
        'Only this computer can then send the box its tokens, after checking what the box runs.'].join('\n'));
    });

  box.command('check <box>').description('Verify the box\'s attestation and image before anything is sent')
    .action(async (boxId: string) => {
      const rt = await opts.getRuntime();
      const { box: entry, session, deviceKey } = await verified(rt, opts, boxId);
      deviceKey.privateKeyDer.fill(0);
      opts.emit({ boxId, ...session.verification, emulator: entry.emulator, claim: BOX_HONEST_CLAIM },
        renderBoxVerification(boxId, session.verification, entry.emulator));
      if (!session.verification.ok) opts.setExit(1);
    });

  box.command('send-tokens <box>').description('Verify the box, then seal this project\'s watcher deployment to its attested key')
    .action(async (boxId: string) => {
      opts.human('send tokens to a cloud box');
      const rt = await opts.getRuntime();
      const { box: entry, session, deviceKey } = await verified(rt, opts, boxId);
      try {
        if (!session.send) {
          opts.diagnostic(renderBoxVerification(boxId, session.verification, entry.emulator));
          throw new CliError(`Nothing was sent. The box failed these checks: ${session.verification.failed.join(', ')}.`);
        }
        const { values, exported, watcherPublicKeyDer, watcherKeyId } = await deploymentFor(rt, opts);
        const settings: BoxSettings = { mode: entry.mode, audience: entry.policy.audience, keyName: entry.policy.keyName,
          deviceKeys: [deviceKey.publicKeyDer.toString('base64')] };
        let share: Buffer | null = null;
        try {
          if (entry.mode === 'unlock-on-restart') {
            // The box's sealed record needs the share it was sealed with, so an existing share is reused: replacing it
            // before the box confirms would lock the box for good if this send never lands. A first share is kept
            // before sending: a box sealed with a share this computer lost could never be unlocked.
            share = await rt.vault.get(shareName(boxId));
            if (!share || share.length !== 32) { share?.fill(0); share = randomBytes(32); await rt.vault.set(shareName(boxId), share); }
          }
          const bytes = encodeBoxPayload({ v: 1, kind: 'enroll', boxId, settings, deployment: values, notice: await noticeKit(rt),
            ...(share ? { shareB: share.toString('base64') } : {}) });
          try { await session.send(bytes); } finally { bytes.fill(0); }
        } finally { share?.fill(0); }
        // Only now, after the box confirmed it sealed this deployment, does this computer trust its watcher key.
        await rt.vault.set(boxWatcherKeyName(boxId), watcherPublicKeyDer);
        await rt.audit.append({ kind: 'box:send-tokens', summary: 'Watcher deployment sealed to a verified cloud box.',
          data: { boxId, mode: entry.mode, digest: session.verification.digest, emulator: entry.emulator, watcherKeyId } });
        opts.emit({ boxId, sent: true, mode: entry.mode, digest: session.verification.digest, emulator: entry.emulator, exportedCredentialNames: exported },
          [`Box ${boxId} verified every check and confirmed it sealed the tokens (${entry.mode}).`,
            `Exported credential names: ${exported.length ? exported.join(', ') : 'none'}.`,
            ...(entry.mode === 'unlock-on-restart' ? ['The device share stays in this computer\'s vault. After a box restart, run keysentry box unlock ' + boxId + '.'] : []),
            ...(entry.emulator ? [EMULATOR_NOTE] : [])].join('\n'));
      } finally { deviceKey.privateKeyDer.fill(0); }
    });

  box.command('unlock <box>').description('Send the device share to a verified box after it restarted (unlock-on-restart)')
    .action(async (boxId: string) => {
      opts.human('unlock a cloud box');
      const rt = await opts.getRuntime();
      const entry = await record(rt, boxId);
      if (entry.mode !== 'unlock-on-restart') throw new CliError(`Box ${boxId} uses ${entry.mode}; it resumes by itself after a restart.`);
      const share = await rt.vault.get(shareName(boxId));
      if (!share || share.length !== 32) { share?.fill(0); throw new CliError('This computer does not hold the device share for that box. Send tokens to it again from this computer.'); }
      try {
        const { session, deviceKey } = await verified(rt, opts, boxId);
        deviceKey.privateKeyDer.fill(0);
        if (!session.send) {
          opts.diagnostic(renderBoxVerification(boxId, session.verification, entry.emulator));
          throw new CliError(`The device share was not sent. The box failed these checks: ${session.verification.failed.join(', ')}.`);
        }
        const bytes = encodeBoxPayload({ v: 1, kind: 'unlock', boxId, shareB: share.toString('base64') });
        try { await session.send(bytes); } finally { bytes.fill(0); }
        await rt.audit.append({ kind: 'box:unlock', summary: 'Device share sent to a verified cloud box.', data: { boxId, digest: session.verification.digest } });
        opts.emit({ boxId, unlocked: true, emulator: entry.emulator }, [`Box ${boxId} verified every check and received the device share. Autopilot resumes on its next check.`,
          ...(entry.emulator ? [EMULATOR_NOTE] : [])].join('\n'));
      } finally { share.fill(0); }
    });

  box.command('allowlist').description('The public log of box image digests').command('verify')
    .description('Verify the signed allow-list of box image digests')
    .option('--log <path>', 'Allow-list log', 'allowlist/log.jsonl').option('--head <path>', 'Signed head', 'allowlist/head.json')
    .action(async (options: { log: string; head: string }) => {
      const rt = await opts.getRuntime();
      const keys = opts.allowListKeys ?? RELEASE_PUBLIC_KEYS.map(key => ({ keyId: key.keyId, publicKeyDer: Buffer.from(key.publicKeyDer, 'base64') }));
      if (keys.length === 0) throw new CliError('This build has no pinned release signing key yet, so the allow-list cannot be verified. The key is pinned with the first signed release.');
      let log: string, head: string;
      try {
        log = await readFile(resolve(rt.config.cwd, options.log), 'utf8');
        head = await readFile(resolve(rt.config.cwd, options.head), 'utf8');
      } catch { throw new CliError('Could not read the allow-list log and signed head. Download both from the release, or pass --log and --head.'); }
      const checkpointPath = join(rt.paths.dir, 'box-allowlist-head.json');
      const previous = await rt.store.readJson<{ seq: number; hash: string }>('plan', checkpointPath);
      const result = verifyAllowList(log, head, keys, previous ? { previousHead: previous } : {});
      if (!result.ok) {
        opts.emit({ ok: false, problems: result.problems }, ['The allow-list did not verify. Do not trust a box against it.', ...result.problems.map(problem => `  ${problem}`)].join('\n'));
        opts.setExit(1); return;
      }
      const last = result.entries.at(-1);
      if (last) await rt.store.writeJson('plan', checkpointPath, { seq: last.seq, hash: last.hash });
      const allowed = [...new Set(result.entries.map(entry => entry.digest.toLowerCase()))].filter(digest => isAllowed(result.entries, digest, rt.now()));
      opts.emit({ ok: true, entries: result.entries.length, allowed }, [`The allow-list verified: ${result.entries.length} entries, signed and linked.`,
        ...(previous ? [`It extends the checkpoint saved on this computer (entry ${previous.seq}).`] : ['This computer saved its first checkpoint; later checks must extend it.']),
        'Allowed box images:', ...(allowed.length ? allowed.map(digest => `  ${digest}`) : ['  none'])].join('\n'));
    });

  // The entry point of the box image (Dockerfile.box). Hidden from help: it is useful only inside the box.
  box.command('agent', { hidden: true }).description('Run the cloud box agent inside the box image')
    .option('--state-dir <path>', 'Private directory for the sealed record', BOX_STATE_DIR)
    .action(async (options: { stateDir: string }) => {
      // A container has no terminal; an AI agent environment is still refused, as for the watcher.
      assertHumanForMutation({ env: opts.env, stdinIsTTY: true, stdoutIsTTY: true, action: 'run the cloud box agent' });
      const line = (level: string) => (message: string) => { process.stderr.write(`${JSON.stringify({ level, message })}\n`); };
      const log: Logger = { debug() {}, info: line('info'), warn: line('warn'), error: line('error') };
      let agent;
      try {
        agent = await startProductionBoxAgent({ stateDir: options.stateDir, log, startWatcher: async (env, signal) => {
          const { runCli } = await import('./index.js');
          return runCli(['watch'], { env, cwd: options.stateDir, signal, stdinIsTTY: false, stdoutIsTTY: false, output: () => {}, error: () => {} });
        } });
      } catch (error) {
        // These errors carry fixed text only.
        if (error instanceof BoxAgentError || error instanceof TeeTokenError || error instanceof BoxRelayError) throw new CliError(error.message);
        throw error;
      }
      await new Promise<void>(resolve => { process.once('SIGTERM', () => resolve()); process.once('SIGINT', () => resolve()); });
      await agent.stop();
    });
}
