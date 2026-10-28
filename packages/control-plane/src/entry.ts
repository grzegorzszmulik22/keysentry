import type { HttpClient } from '../../../src/types.js';
import { createHostedHttp, createMetadataHttp, createSecretManagerHttp } from './egress.js';
import { createHostedControlPlane, HostedConfigError, hostedConfigFromEnv, type HostedConfig, type HostedSecrets } from './hosted.js';
import { readSecret, SecretUnavailableError } from './secrets.js';
import { metadataAccessToken, type Storage } from './storage.js';

/**
 * One structured log line: an event name and a status, nothing else. Requests log their HTTP status; lifecycle
 * events log 0 (fine) or 1 (failed). A refused setting names the variable (`setting`), never its value.
 */
export type HostedLogEntry =
  | { event: 'request' | 'cleanup'; status: number }
  | { event: 'started' | 'stopping' | 'stopped'; status: 0 }
  | { event: 'config-invalid' | 'secret-unavailable'; status: 1; setting: string }
  | { event: 'listen-failed' | 'stop-failed' | 'crashed'; status: 1 };

/** Thrown after the matching log line was written; fixed text. */
export class HostedStartError extends Error {
  constructor() { super('The control plane could not start.'); this.name = 'HostedStartError'; }
}

export interface StartHostedOptions {
  env: NodeJS.ProcessEnv;
  /** The raw transport (createFetchHttp). Only the guarded, metadata and Secret Manager clients built here use it. */
  transport: HttpClient;
  log(entry: HostedLogEntry): void;
  now?: () => number;
  /** Tests: in-memory state instead of the bucket. */
  storage?: Storage;
  sleep?: (ms: number) => Promise<void>;
  /** Connections still open this long after SIGTERM are closed. Cloud Run sends SIGKILL ten seconds after SIGTERM. */
  shutdownDeadlineMs?: number;
}

export interface RunningControlPlane {
  origin: string;
  port: number;
  /** Graceful shutdown: stop accepting, let requests finish, close what is left at the deadline. Idempotent. */
  stop(): Promise<void>;
}

function safeLog(log: StartHostedOptions['log'], entry: HostedLogEntry): void {
  try { log(entry); } catch { /* Logging never changes the outcome. */ }
}

/**
 * The Cloud Run process: configuration from non-secret environment variables, the two Stripe credentials from
 * Secret Manager through the metadata-server token, then the hosted composition on `PORT`.
 */
export async function startHosted(options: StartHostedOptions): Promise<RunningControlPlane> {
  const now = options.now ?? Date.now;
  let config: HostedConfig;
  try { config = hostedConfigFromEnv(options.env); }
  catch (error) {
    safeLog(options.log, { event: 'config-invalid', status: 1, setting: error instanceof HostedConfigError ? error.setting : 'unknown' });
    throw new HostedStartError();
  }
  const metadata = createMetadataHttp(options.transport);
  const accessToken = metadataAccessToken(metadata, now);
  let secrets: HostedSecrets;
  try {
    const refs = config.secretRefs;
    const secretHttp = createSecretManagerHttp(options.transport, [refs.stripeWebhookSecret, refs.stripeApiKey]);
    const read = (reference: string, setting: string) => readSecret({ http: secretHttp, accessToken, reference, setting, ...(options.sleep ? { sleep: options.sleep } : {}) });
    secrets = {
      stripeWebhookSecret: await read(refs.stripeWebhookSecret, 'KEYSENTRY_STRIPE_WEBHOOK_SECRET_REF'),
      stripeApiKey: await read(refs.stripeApiKey, 'KEYSENTRY_STRIPE_API_KEY_REF'),
    };
    // The values must look like what Stripe issues; a wrong secret fails here rather than on the first webhook.
    if (!/^whsec_[A-Za-z0-9]{8,240}$/.test(secrets.stripeWebhookSecret)) throw new SecretUnavailableError('KEYSENTRY_STRIPE_WEBHOOK_SECRET_REF');
    if (!/^(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,240}$/.test(secrets.stripeApiKey)) throw new SecretUnavailableError('KEYSENTRY_STRIPE_API_KEY_REF');
  } catch (error) {
    safeLog(options.log, { event: 'secret-unavailable', status: 1, setting: error instanceof SecretUnavailableError ? error.setting : 'unknown' });
    throw new HostedStartError();
  }
  const http = createHostedHttp(options.transport, { bucket: config.bucket,
    compute: config.live ? { projectId: config.boxProjectId, zone: config.live.zone } : null });
  const server = createHostedControlPlane({ config, secrets, http, metadata, accessToken, now,
    log: entry => safeLog(options.log, entry), ...(options.storage ? { storage: options.storage } : {}) });
  let address: { origin: string; port: number };
  try { address = await server.listen(); }
  catch {
    safeLog(options.log, { event: 'listen-failed', status: 1 });
    throw new HostedStartError();
  }
  safeLog(options.log, { event: 'started', status: 0 });
  let stopping: Promise<void> | undefined;
  return {
    ...address,
    stop() {
      stopping ??= (async () => {
        safeLog(options.log, { event: 'stopping', status: 0 });
        try { await server.close({ deadlineMs: options.shutdownDeadlineMs ?? 8_000 }); }
        catch { safeLog(options.log, { event: 'stop-failed', status: 1 }); throw new Error('The control plane could not stop cleanly.'); }
        safeLog(options.log, { event: 'stopped', status: 0 });
      })();
      return stopping;
    },
  };
}

/** SIGTERM (Cloud Run) and SIGINT (a terminal) start one graceful shutdown; the exit code reports how it went. */
export function stopOnSignals(signals: { once(signal: 'SIGTERM' | 'SIGINT', listener: () => void): unknown }, running: RunningControlPlane,
  setExitCode: (code: number) => void): void {
  const stop = () => { void running.stop().then(() => setExitCode(0), () => setExitCode(1)); };
  signals.once('SIGTERM', stop);
  signals.once('SIGINT', stop);
}
