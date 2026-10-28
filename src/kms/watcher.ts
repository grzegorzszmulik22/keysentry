import { createFileReceipt } from '../net/index.js';
import type { CredentialSource, HttpClient } from '../types.js';
import { KmsError } from './errors.js';
import { createKmsHttp, type KmsSettings } from './settings.js';
import { unwrapWatcherStateKey } from './state-key.js';
import { createKeyWrapper } from './wrapper.js';

export interface DeploymentStateKeyOptions {
  /** The value of `KEYSENTRY_STATE_KEY_WRAPPED`. */
  encoded: string;
  /** The deployment's kms settings (from its encrypted runtime settings). */
  kms: KmsSettings | undefined;
  projectId: string;
  credentials: CredentialSource;
  /** Raw transport; only the configured KMS hosts are reachable through the guard built here. */
  transport: HttpClient;
  /** The watcher's network receipt file. */
  receiptPath: string;
  now?: () => Date;
}

/** Watcher bootstrap: unwrap `KEYSENTRY_STATE_KEY_WRAPPED` with the deployment's kms settings, or refuse to start. */
export async function unwrapDeploymentStateKey(options: DeploymentStateKeyOptions): Promise<Buffer> {
  if (!options.kms) {
    throw new KmsError('config', 'KEYSENTRY_STATE_KEY_WRAPPED needs the kms settings from watcher setup, but this deployment has none. Run watcher setup again with kms configured, or use KEYSENTRY_STATE_KEY.');
  }
  const http = createKmsHttp(options.transport, options.kms, { receipt: createFileReceipt(options.receiptPath) });
  const wrapper = createKeyWrapper(options.kms, { http, credentials: options.credentials, ...(options.now ? { now: options.now } : {}) });
  return unwrapWatcherStateKey({ wrapper, projectId: options.projectId, encoded: options.encoded });
}
