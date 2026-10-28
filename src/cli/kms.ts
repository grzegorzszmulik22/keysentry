import type { Command } from 'commander';
import { createFetchHttp } from '../http.js';
import {
  createKeyWrapper, createKmsHttp, migrateStateKey, PROVIDER_LABELS, rotateStateKey, stateKeyStatus,
  type MigrateStateKeyOptions, type StateKeyStatus,
} from '../kms/index.js';
import type { HttpClient, KeyWrapper } from '../types.js';
import { CliError } from './errors.js';
import { confirmAction, type PromptIO } from './prompts.js';
import type { KeysentryRuntime } from './runtime.js';
import { knownWatcherKeys } from './watcher-keys.js';

/** Shown by `kms rotate` when this computer set up a watcher or a cloud box. */
export const WATCHER_ROTATION_NOTE = 'Your deployed watcher keeps its own KEYSENTRY_STATE_KEY_WRAPPED, wrapped under the key version current at '
  + 'watcher setup; this rotation does not change it. Keep that version enabled, or run watcher setup again and redeploy before you disable it.';

export interface KmsCommandsOptions {
  getRuntime(): Promise<KeysentryRuntime>;
  /** `assertHumanForMutation` for the calling terminal. */
  human(action: string): void;
  emit(value: unknown, human?: string): void;
  diagnostic(text: string): void;
  json(): boolean;
  setExit(code: number): void;
  promptIO?: PromptIO;
  /** The raw transport the KMS egress guard wraps (the runtime's injected client, or the proxy-aware transport). */
  transport?: HttpClient;
  now?: () => Date;
  /** Test hooks. */
  confirm?: (word: string) => Promise<boolean>;
  migrationCheckpoint?: MigrateStateKeyOptions['checkpoint'];
}

function wrapperFor(rt: KeysentryRuntime, options: KmsCommandsOptions): KeyWrapper | undefined {
  const kms = rt.config.settings.kms;
  if (!kms) return undefined;
  // The runtime's raw transport carries the configured proxy and CA; the KMS guard below limits it to the KMS hosts.
  const http = createKmsHttp(options.transport ?? rt.network?.transport ?? createFetchHttp(), kms, { receipt: rt.receipt, log: rt.log });
  return createKeyWrapper(kms, { http, credentials: rt.credentials, now: options.now ?? rt.now });
}

function envWrapped(rt: KeysentryRuntime): string | undefined {
  return rt.vault.backend === 'env' ? rt.mutationContext.env.KEYSENTRY_STATE_KEY_WRAPPED || undefined : undefined;
}

function requireWrapper(rt: KeysentryRuntime, options: KmsCommandsOptions): KeyWrapper {
  const wrapper = wrapperFor(rt, options);
  if (!wrapper) throw new CliError('No KMS is configured. Add a kms section to keysentry.yaml first.');
  return wrapper;
}

export function renderKmsStatus(status: StateKeyStatus): string {
  const lines = [status.configured
    ? `KMS: ${PROVIDER_LABELS[status.configured.provider]}, key ${status.configured.keyRef}`
    : 'KMS: not configured'];
  if (!status.wrapped) lines.push('State key: not wrapped');
  else {
    const where = status.wrapped.matchesConfig ? 'with the configured key' : `with a different key (${PROVIDER_LABELS[status.wrapped.provider]}, ${status.wrapped.keyRef})`;
    lines.push(`State key: wrapped ${where}${status.wrapped.keyVersion ? `, key version ${status.wrapped.keyVersion}` : ''}, at ${status.wrapped.wrappedAt}`);
  }
  lines.push(`Plain copy in the vault: ${status.plainCopy ? 'yes' : 'no'}`);
  lines.push(`Live check: ${status.check.ok ? 'passed' : 'failed'}. ${status.check.message}`);
  return lines.join('\n');
}

export function registerKmsCommands(program: Command, options: KmsCommandsOptions): void {
  const kms = program.command('kms').description('Wrap the state key with your own KMS key (AWS KMS, Google Cloud KMS, Azure Key Vault, Vault Transit)');

  kms.command('status').description('Show the KMS key, whether the state key is wrapped, and check that it unwraps')
    .action(async () => {
      const rt = await options.getRuntime();
      const status = await stateKeyStatus({ vault: rt.vault, projectId: rt.projectId, wrapper: wrapperFor(rt, options), envWrapped: envWrapped(rt) });
      options.emit(status, renderKmsStatus(status));
      if (!status.check.ok) options.setExit(1);
    });

  kms.command('migrate').description('Wrap the existing state key with the configured KMS key, then remove its plain copy')
    .option('--yes', 'Skip the typed confirmation')
    .action(async (flags: { yes?: boolean }) => {
      options.human('wrap the state key with a KMS key');
      const rt = await options.getRuntime();
      const wrapper = requireWrapper(rt, options);
      if (!flags.yes) {
        options.diagnostic(`After this, saved state opens only while ${PROVIDER_LABELS[wrapper.provider]} key ${wrapper.keyRef} can be used. `
          + 'The plain copy of the state key is removed from the vault only after the wrapped copy is checked.');
        const confirm = options.confirm ?? (word => confirmAction(word, options.diagnostic, options.promptIO));
        if (!await confirm('MIGRATE')) throw new CliError('Migration cancelled. Nothing was changed.');
      }
      const outcome = await migrateStateKey({ vault: rt.vault, projectId: rt.projectId, wrapper, now: options.now ?? rt.now,
        ...(options.migrationCheckpoint ? { checkpoint: options.migrationCheckpoint } : {}) });
      if (outcome.result !== 'already-wrapped') {
        await rt.audit.append({ kind: 'kms:migrate', summary: 'State key wrapped with the configured KMS key; plain copy removed.',
          data: { provider: wrapper.provider, keyRef: wrapper.keyRef, result: outcome.result } });
      }
      const text = outcome.result === 'migrated' ? 'The state key is now wrapped with your KMS key, and its plain copy was removed from the vault.'
        : outcome.result === 'finished' ? 'Finished an earlier migration: the wrapped copy checked out and the plain copy was removed.'
        : 'The state key is already wrapped with the configured key. Nothing was changed.';
      options.emit({ result: outcome.result, provider: wrapper.provider, keyRef: wrapper.keyRef, wrappedAt: outcome.record.wrappedAt }, text);
    });

  kms.command('rotate').description('Rewrap the state key under the KMS key\'s current version')
    .action(async () => {
      options.human('rewrap the state key');
      const rt = await options.getRuntime();
      const wrapper = requireWrapper(rt, options);
      const outcome = await rotateStateKey({ vault: rt.vault, projectId: rt.projectId, wrapper, now: options.now ?? rt.now });
      await rt.audit.append({ kind: 'kms:rotate', summary: 'State key rewrapped under the KMS key\'s current version.',
        data: { provider: wrapper.provider, keyRef: wrapper.keyRef, ...(outcome.after ? { keyVersion: outcome.after } : {}) } });
      // AWS KMS always encrypts with the key's current key material and does not report a version label for it.
      const text = wrapper.provider === 'aws-kms' && outcome.before === outcome.after
        ? 'Rewrapped with the AWS KMS key\'s current key material.'
        : outcome.before && outcome.after && outcome.before === outcome.after
          ? `Rewrapped. The key version is unchanged (${outcome.after}); rotate the key in ${PROVIDER_LABELS[wrapper.provider]} first to move to a new version.`
          : `Rewrapped under the current key version${outcome.after ? ` (${outcome.after})` : ''}.`;
      // A deployed watcher's KEYSENTRY_STATE_KEY_WRAPPED is a separate wrap made at watcher setup; this rotation does not
      // touch it, so disabling the old key version would stop that watcher (review L6).
      const watcherNote = (await knownWatcherKeys(rt.vault)).length ? WATCHER_ROTATION_NOTE : null;
      options.emit({ provider: wrapper.provider, keyRef: wrapper.keyRef, before: outcome.before ?? null, after: outcome.after ?? null,
        wrappedAt: outcome.record.wrappedAt, watcherNote }, watcherNote ? `${text}\n${watcherNote}` : text);
    });
}
