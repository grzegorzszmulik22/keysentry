import { createHash } from 'node:crypto';
import { join } from 'node:path';
import type * as tls from 'node:tls';
import type { Command } from 'commander';
import {
  AUDIT_EXPORT_PURPOSE, AuditExportRefusedError, EXPORT_SECRET_FIELDS, auditExportSyslogAllowance, auditExportUrls, createAuditExporter,
  createAuditFileReader, createStoreExportState, createTlsSyslogConnector, decodeWebhookSecret, exportSecretName, parseOtlpHeader,
  proxyAppliesTo, type AuditExporter, type AuditExportDryRun, type AuditExportRunResult, type AuditExportStatus, type AuditExportTarget,
  type ExportSecretField,
} from '../audit-export/index.js';
import { CaBundleError, loadCaBundle } from '../net/transport.js';
import type { ConfigSettings } from './config.js';
import { CliError } from './errors.js';
import { promptVaultValue, type PromptIO } from './prompts.js';
import type { KeysentryRuntime } from './runtime.js';
import { knownWatcherKeys } from './watcher-keys.js';

/** The runtime members audit export needs; the full KeysentryRuntime satisfies it. */
export type AuditExportRuntime = Pick<KeysentryRuntime, 'config' | 'paths' | 'audit' | 'store' | 'vault' | 'receipt' | 'redactor' | 'now'
  | 'signingKey' | 'httpForUrls' | 'projectId'> & Partial<Pick<KeysentryRuntime, 'singleHostHttp' | 'network' | 'auditMacKey'>>;

export interface AuditExportCommandsOptions {
  getRuntime(): Promise<AuditExportRuntime>;
  emit(value: unknown, human?: string): void;
  diagnostic(text: string): void;
  human(action: string, allowPipedStdin?: boolean): void;
  setExit(code: number): void;
  env?: NodeJS.ProcessEnv;
  promptIO?: PromptIO;
  /** Test seams: the TLS connect function for syslog and the retry sleep. */
  connect?: (options: tls.ConnectionOptions) => tls.TLSSocket;
  sleep?: (ms: number) => Promise<void>;
}

// Compile-time check that the configuration schema and the exporter agree on every target field.
type ConfiguredTarget = ConfigSettings['audit']['export'][number];
const sameShape = (target: ConfiguredTarget): AuditExportTarget => target;

const STATE_FILE = 'audit-export.json';

/** Stable and non-secret: identifies this project's log to receivers without revealing the project id. */
export function auditExportSourceId(projectId: string): string {
  return createHash('sha256').update(`keysentry-audit-source:v1:${projectId}`).digest('hex').slice(0, 16);
}

export async function createRuntimeAuditExporter(rt: AuditExportRuntime, opts: Pick<AuditExportCommandsOptions, 'env' | 'connect' | 'sleep'> = {}): Promise<AuditExporter> {
  const settings = rt.config.settings;
  const targets = settings.audit.export.map(sameShape);
  // Syslog over TLS trusts exactly what the HTTPS transport trusts (review L1): the runtime's loaded bundle (from the
  // project file, or from a deployed watcher's encrypted vault), and it is refused whenever the transport refuses.
  let ca: string[] | undefined;
  if (rt.network) ca = rt.network.ca ?? undefined;
  else if (settings.network.caFile && targets.some(target => target.kind === 'syslog')) {
    try { ca = (await loadCaBundle(settings.network.caFile, { cwd: rt.config.cwd })).pems; }
    catch (error) { if (error instanceof CaBundleError) throw new CliError(error.message); throw error; }
  }
  const env = opts.env ?? process.env;
  const requireProxy = rt.network?.summary.requireProxy === true;
  // Like notification webhooks, a configured URL may carry a token in its path: never print it whole.
  for (const target of targets) if (target.kind === 'webhook' || target.kind === 'otlp') rt.redactor.register(target.url);
  return createAuditExporter({
    targets,
    audit: rt.audit,
    reader: createAuditFileReader(rt.paths.audit, { redactor: rt.redactor }),
    // Guarded like every other request: each export URL authorizes only its own host.
    http: rt.httpForUrls(auditExportUrls(targets), AUDIT_EXPORT_PURPOSE),
    // Each target also gets its own client limited to its one host, from the runtime's raw (proxy-aware) transport.
    ...(rt.singleHostHttp ? { httpFor: singleHostClients(targets, rt.singleHostHttp) } : {}),
    tls: createTlsSyslogConnector({ allow: auditExportSyslogAllowance(targets), ...(ca ? { ca } : {}), receipt: rt.receipt, now: rt.now,
      unavailable: rt.network?.problem ?? null,
      proxied: (host, port) => proxyAppliesTo(host, { ...(settings.network.proxy ? { proxy: settings.network.proxy } : {}),
        noProxy: requireProxy ? [] : settings.network.noProxy, env, port, requireProxy }),
      ...(opts.connect ? { connect: opts.connect } : {}) }),
    vault: rt.vault,
    signingKey: rt.signingKey,
    // The audit log's own vault view (the environment vault keeps its MAC key in memory), for the per-entry check.
    ...(rt.auditMacKey ? { macKey: rt.auditMacKey } : {}),
    // A deployed watcher or cloud box signs its webhook batches with its own key: status lists those too (review M3).
    otherSigningKeys: () => knownWatcherKeys(rt.vault),
    state: createStoreExportState(rt.store, join(rt.paths.dir, STATE_FILE)),
    now: rt.now,
    ...(opts.sleep ? { sleep: opts.sleep } : {}),
    sourceId: auditExportSourceId(rt.projectId),
  });
}

/** One single-host guarded client per HTTP target, created once per exporter. */
function singleHostClients(targets: readonly AuditExportTarget[], create: NonNullable<AuditExportRuntime['singleHostHttp']>) {
  const clients = new Map<string, ReturnType<typeof create>>();
  for (const target of targets) {
    const [url] = auditExportUrls([target]);
    if (url) clients.set(target.id, create(url, AUDIT_EXPORT_PURPOSE));
  }
  return (target: AuditExportTarget) => {
    const client = clients.get(target.id);
    if (!client) throw new CliError('Audit export has no network client for this target.');
    return client;
  };
}

/**
 * Watcher hook: export after each cycle. Unforced, so a target that keeps failing waits out its cooldown instead of
 * slowing every cycle. Returns null when nothing is configured. Throws only for a refusal (the log did not verify).
 */
export async function runAuditExportForRuntime(rt: AuditExportRuntime, opts: Pick<AuditExportCommandsOptions, 'env' | 'connect' | 'sleep'> & { force?: boolean } = {}): Promise<AuditExportRunResult | null> {
  if (!rt.config.settings.audit.export.length) return null;
  // Sign the tail first, so the exported log ends in a checkpoint receivers can check.
  await rt.audit.checkpoint();
  const exporter = await createRuntimeAuditExporter(rt, opts);
  return exporter.run({ force: opts.force ?? false });
}

const NONE = 'No audit export targets are configured. Add them under audit.export in keysentry.yaml.';
const range = (first?: number, last?: number) => first === undefined ? '' : first === last ? ` (seq ${first})` : ` (seq ${first}-${last})`;
const plural = (count: number, word: string, many = `${word}s`) => `${count} ${count === 1 ? word : many}`;

function renderRun(result: AuditExportRunResult): string {
  const lines = [`Audit log verified: ${plural(result.entries, 'entry', 'entries')}.`];
  for (const target of result.targets) {
    const label = `${target.id} (${target.kind})`;
    const sent = target.sent ? `sent ${plural(target.sent, 'record')}${range(target.firstSeq, target.lastSeq)} in ${plural(target.batches, 'batch', 'batches')}` : '';
    if (target.status === 'up-to-date') lines.push(`${label}: up to date at seq ${target.cursor}.`);
    else if (target.status === 'sent') lines.push(`${label}: ${sent}; ${target.pending ? `${target.pending} more wait for the next run, in order.` : 'up to date.'}`);
    else if (target.status === 'waiting') lines.push(`${label}: not tried this time. ${target.error ?? ''}`.trimEnd());
    else {
      lines.push(`${label}: ${target.status === 'refused' ? 'refused' : 'failed'}${sent ? ` after it ${sent}` : ''}. ${target.error ?? ''}`.trimEnd());
      if (target.status === 'failed' && target.pending) lines.push(`  ${target.pending} entries wait and will be sent in order next time; nothing is skipped.`);
    }
    for (const warning of target.warnings) lines.push(`  Note: ${warning}`);
  }
  return lines.join('\n');
}

function renderDryRun(result: AuditExportDryRun): string {
  const lines = ['Dry run: nothing was sent and no progress was saved.', `Audit log verified: ${result.entries} entries.`];
  for (const target of result.targets) {
    lines.push(`${target.id}: ${target.destination}`);
    lines.push(`  ${target.pending} entries wait after seq ${target.cursor}. Credentials: ${target.credentials}.`);
    for (const batch of target.batches) {
      lines.push(`  batch seq ${batch.firstSeq}-${batch.lastSeq}: ${plural(batch.records, 'record')}, ${batch.bytes} bytes -> ${batch.location}`);
    }
    for (const record of target.preview) lines.push(`    #${record.seq} ${record.at} ${record.kind}: ${record.summary}`);
    for (const note of target.notes) lines.push(`  Note: ${note}`);
  }
  return lines.join('\n');
}

function renderStatus(result: AuditExportStatus): string {
  const lines = [result.verified ? `Audit log: ${result.entries} entries, verified.` : `Audit log: ${result.entries} entries; it did not verify, so nothing will be exported until it does${result.problem ? ` (${result.problem})` : ''}.`];
  for (const target of result.targets) {
    lines.push(`${target.id}: ${target.destination}`);
    lines.push(`  At seq ${target.cursor}; ${target.pending} waiting. Last success: ${target.lastSuccessAt ?? 'never'}.`);
    if (target.lastError) lines.push(`  Last problem (${plural(target.failures, 'failed attempt')}): ${target.lastError}`);
    if (target.nextAttemptAt) lines.push(`  The watcher tries again after ${target.nextAttemptAt}; keysentry audit export tries now.`);
    if (target.warning) lines.push(`  Note: ${target.warning}`);
    if (target.publicKeys?.length) {
      lines.push('  Receivers trust exactly these keys and pick one by the keysentry-key-id header:');
      for (const key of target.publicKeys) lines.push(`    ${key.whpk} (key id ${key.keyId}, ${key.signer})`);
    } else if (target.publicKey) lines.push(`  Receivers verify signatures with ${target.publicKey.whpk} (key id ${target.publicKey.keyId}).`);
  }
  return lines.join('\n');
}

async function readPiped(io?: PromptIO): Promise<string> {
  const input = io?.input ?? process.stdin;
  if (input.isTTY) throw new CliError('--stdin requires piped input.');
  const chunks: Buffer[] = []; let bytes = 0;
  for await (const chunk of input) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    bytes += buffer.length;
    if (bytes > 64 * 1024) throw new CliError('Credential input is too large.');
    chunks.push(buffer);
  }
  const value = Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
  if (!value || /[\x00\r\n]/.test(value)) throw new CliError('Provide one nonempty credential value on stdin.');
  return value;
}

function checkCredential(field: ExportSecretField, value: string, singleHost: boolean): void {
  if (field === 'hmac-secret') {
    const key = decodeWebhookSecret(Buffer.from(value, 'utf8'));
    if (!key) throw new CliError('The webhook secret must be whsec_ followed by base64 of 24 to 64 random bytes, for example from: openssl rand -base64 32');
    key.fill(0);
  } else if (field === 'header') {
    // Exactly what the export sends (review L3): any ordinary name on the per-target client the runtime provides.
    if (!parseOtlpHeader(value, { singleHost })) {
      throw new CliError(singleHost ? 'Enter the header as "Name: value" with an ordinary header name (letters, digits and "-"), not a transport header such as Host or Content-Type.'
        : 'Enter the header as "Name: value"; the name must contain token, secret, key or auth.');
    }
  } else if (!/^[\x21-\x7e]{1,8192}$/.test(value)) throw new CliError('The credential must be printable ASCII without spaces.');
}

const collect = (value: string, previous: string[] = []) => [...previous, ...value.split(',').map(item => item.trim()).filter(Boolean)];

export function registerAuditExportCommands(program: Command, options: AuditExportCommandsOptions): void {
  const audit = program.commands.find(command => command.name() === 'audit')
    ?? program.command('audit').description('Check the local tamper-evident audit log');
  const seams = { ...(options.env ? { env: options.env } : {}), ...(options.connect ? { connect: options.connect } : {}), ...(options.sleep ? { sleep: options.sleep } : {}) };

  async function exporter(): Promise<{ rt: AuditExportRuntime; exporter: AuditExporter } | null> {
    const rt = await options.getRuntime();
    if (!rt.config.settings.audit.export.length) { options.emit({ targets: [] }, NONE); return null; }
    return { rt, exporter: await createRuntimeAuditExporter(rt, seams) };
  }
  function only(ids: string[] | undefined, rt: AuditExportRuntime): string[] | undefined {
    if (!ids?.length) return undefined;
    const known = new Set(rt.config.settings.audit.export.map(target => target.id));
    if (ids.some(id => !known.has(id))) throw new CliError('Choose --target ids from audit.export in keysentry.yaml.');
    return ids;
  }
  async function refusalsAsCliErrors<T>(work: () => Promise<T>): Promise<T> {
    try { return await work(); }
    catch (error) { if (error instanceof AuditExportRefusedError) throw new CliError(error.message); throw error; }
  }

  const exportCommand = audit.command('export')
    .description('Send the verified audit log to the export targets in keysentry.yaml (syslog, OpenTelemetry, S3, webhooks)')
    .option('--dry-run', 'Show what would be sent; send nothing, read no credential values and save no progress')
    .option('--target <ids>', 'Only these target ids, comma-separated or repeatable', collect)
    .allowExcessArguments(false)
    .action(async (opts: { dryRun?: boolean; target?: string[] }) => {
      const prepared = await exporter(); if (!prepared) return;
      const selection = only(opts.target, prepared.rt);
      if (opts.dryRun) {
        const result = await refusalsAsCliErrors(() => prepared.exporter.dryRun(selection ? { only: selection } : {}));
        options.emit(result, renderDryRun(result));
        return;
      }
      await prepared.rt.audit.checkpoint();
      const result = await refusalsAsCliErrors(() => prepared.exporter.run({ force: true, ...(selection ? { only: selection } : {}) }));
      options.emit(result, renderRun(result));
      if (result.targets.some(target => target.status === 'failed' || target.status === 'refused')) options.setExit(1);
    });

  exportCommand.command('status').description('Show how far each export target has received the audit log')
    .allowExcessArguments(false)
    .action(async () => {
      const prepared = await exporter(); if (!prepared) return;
      const result = await prepared.exporter.status();
      options.emit(result, renderStatus(result));
      if (!result.verified) options.setExit(1);
    });

  exportCommand.command('secret <id> <field>')
    .description('Store or remove a credential for an export target (OTLP bearer/header, S3 keys, webhook HMAC secret)')
    .option('--stdin', 'Read one value from piped stdin').option('--remove', 'Remove the stored credential')
    .action(async (id: string, field: string, opts: { stdin?: boolean; remove?: boolean }) => {
      options.human(opts.remove ? 'remove an audit export credential' : 'store an audit export credential', opts.stdin === true);
      const rt = await options.getRuntime();
      const target = rt.config.settings.audit.export.find(item => item.id === id);
      if (!target) throw new CliError('No audit export target has that id in keysentry.yaml.');
      const fields: readonly string[] = target.kind === 'webhook' && target.signing === 'ed25519' ? [] : EXPORT_SECRET_FIELDS[target.kind];
      if (!fields.includes(field)) {
        throw new CliError(fields.length ? `The ${target.kind} target ${id} takes these credentials: ${fields.join(', ')}.` : `The ${target.kind} target ${id} needs no stored credential.`);
      }
      const name = exportSecretName(id, field as ExportSecretField);
      if (opts.remove) {
        const removed = await rt.vault.delete(name);
        await rt.audit.append({ kind: 'audit-export:credential-remove', summary: 'Audit export credential removed.', data: { target: id, field } });
        options.emit({ removed, target: id, field }, removed ? `Removed the ${field} for ${id}.` : `No ${field} was stored for ${id}.`);
        return;
      }
      const value = opts.stdin ? await readPiped(options.promptIO) : await promptVaultValue(`${id} ${field}`, options.diagnostic, options.promptIO);
      if (value === null) { options.emit({ cancelled: true }, 'Credential entry cancelled.'); return; }
      rt.redactor.register(value);
      checkCredential(field as ExportSecretField, value, rt.singleHostHttp !== undefined);
      const bytes = Buffer.from(value, 'utf8');
      try { await rt.vault.set(name, bytes); } finally { bytes.fill(0); }
      await rt.audit.append({ kind: 'audit-export:credential-set', summary: 'Audit export credential stored.', data: { target: id, field } });
      options.emit({ stored: true, target: id, field }, `Stored the ${field} for ${id}.`);
    });
}
