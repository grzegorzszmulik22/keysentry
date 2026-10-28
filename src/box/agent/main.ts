import { request as httpRequest, type ClientRequest, type IncomingMessage, type RequestOptions } from 'node:http';
import { createFetchHttp } from '../../http.js';
import { EGRESS_RULES, createGuardedHttp } from '../../net/index.js';
import type { HttpClient, Logger, SignedNotifyMessage } from '../../types.js';
import { BoxAgentError, startBoxAgent, type BoxAgent } from './agent.js';
import { createNoticeSender } from './notice.js';
import { isBoxId, isEd25519Spki, type BoxNoticeKit } from './payload.js';
import { createHttpBoxRelay } from './relay.js';
import { createTeeTokenSource, type TeeTokenSource } from './tee.js';

/** Container path for the sealed record and the watcher's encrypted state. */
export const BOX_STATE_DIR = '/var/lib/keysentry-box';
export const METADATA_ATTRIBUTES = { boxId: 'keysentry-box-id', relay: 'keysentry-relay-origin', device: 'keysentry-enroll-device-key' } as const;

export interface BoxRouteMetadata { boxId: string; relayOrigin: string; enrollmentDeviceKey: Buffer }

/**
 * One instance attribute from the GCE metadata server. Only these three non-secret values are read, and none is
 * trusted for security: the relay is untrusted anyway and the enrollment key is explained in notes/box-agent.md.
 */
export function readMetadataAttribute(name: string, options: {
  request?: (options: RequestOptions, callback: (response: IncomingMessage) => void) => ClientRequest; timeoutMs?: number;
} = {}): Promise<string> {
  if (!Object.values(METADATA_ATTRIBUTES).includes(name as never)) return Promise.reject(new Error('Unknown metadata attribute.'));
  return new Promise((resolve, reject) => {
    const req = (options.request ?? httpRequest)({ host: 'metadata.google.internal', method: 'GET', timeout: options.timeoutMs ?? 5_000,
      path: `/computeMetadata/v1/instance/attributes/${name}`, headers: { 'Metadata-Flavor': 'Google' } }, response => {
      const chunks: Buffer[] = []; let length = 0;
      response.on('data', (chunk: Buffer) => { length += chunk.length; if (length > 4096) response.destroy(new Error('too large')); else chunks.push(chunk); });
      response.on('error', () => reject(new BoxAgentError('The box could not read its instance metadata.')));
      response.on('end', () => {
        if (response.statusCode !== 200 || response.headers['metadata-flavor'] !== 'Google') { reject(new BoxAgentError('The box could not read its instance metadata.')); return; }
        resolve(Buffer.concat(chunks).toString('utf8').trim());
      });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => reject(new BoxAgentError('The box could not read its instance metadata.')));
    req.end();
  });
}

export async function readBoxRoute(read: (name: string) => Promise<string> = name => readMetadataAttribute(name)): Promise<BoxRouteMetadata> {
  const [boxId, relayOrigin, device] = await Promise.all([read(METADATA_ATTRIBUTES.boxId), read(METADATA_ATTRIBUTES.relay), read(METADATA_ATTRIBUTES.device)]);
  if (!isBoxId(boxId)) throw new BoxAgentError('The box id in the instance metadata is invalid.');
  let origin: URL;
  try { origin = new URL(relayOrigin); } catch { throw new BoxAgentError('The relay address in the instance metadata is invalid.'); }
  if (origin.protocol !== 'https:' || origin.origin !== relayOrigin) throw new BoxAgentError('The relay address in the instance metadata is invalid.');
  const key = Buffer.from(device, 'base64');
  if (key.length !== 44 || key.toString('base64') !== device || !isEd25519Spki(key)) throw new BoxAgentError('The enrollment device key in the instance metadata is invalid.');
  return { boxId, relayOrigin, enrollmentDeviceKey: key };
}

/** The relay authenticates the box by an attestation token for its own origin, refreshed before it expires. */
export function relayCredential(tee: TeeTokenSource, origin: string, now: () => number = Date.now): () => Promise<string> {
  let cached: { token: string; refreshAt: number } | undefined;
  return async () => {
    if (cached && now() < cached.refreshAt) return cached.token;
    const token = await tee.token({ audience: origin, nonces: [] });
    let exp = 0;
    try { exp = Number((JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString('utf8')) as { exp?: unknown }).exp); } catch { /* refresh next time */ }
    cached = { token, refreshAt: Number.isFinite(exp) ? Math.min(exp * 1000 - 300_000, now() + 1_800_000) : 0 };
    return token;
  };
}

export interface ProductionBoxOptions {
  startWatcher(env: Record<string, string>, signal: AbortSignal): Promise<unknown>;
  log: Logger;
  stateDir?: string;
  transport?: HttpClient;
  tee?: TeeTokenSource;
  route?: BoxRouteMetadata;
  sendNotice?: (kit: BoxNoticeKit, message: SignedNotifyMessage) => Promise<void>;
}

/** `keysentry box agent`: the entry point of the box image. */
export async function startProductionBoxAgent(options: ProductionBoxOptions): Promise<BoxAgent> {
  const route = options.route ?? await readBoxRoute();
  const transport = options.transport ?? createFetchHttp();
  const tee = options.tee ?? createTeeTokenSource();
  const relayHost = new URL(route.relayOrigin).hostname;
  const boxRules = EGRESS_RULES.filter(rule => rule.owner === 'box' && (rule.host === 'sts.googleapis.com' || rule.host === 'cloudkms.googleapis.com'));
  const http = createGuardedHttp(transport, { rules: boxRules, log: options.log });
  const relayHttp = createGuardedHttp(transport, { rules: [{ host: relayHost, owner: 'box', purpose: 'Cloud box relay' }], log: options.log });
  return startBoxAgent({
    boxId: route.boxId,
    relay: createHttpBoxRelay({ http: relayHttp, origin: route.relayOrigin, boxId: route.boxId, credential: relayCredential(tee, route.relayOrigin) }),
    tee, http, stateDir: options.stateDir ?? BOX_STATE_DIR, enrollmentDeviceKeys: [route.enrollmentDeviceKey],
    startWatcher: options.startWatcher, log: options.log,
    sendNotice: options.sendNotice ?? createNoticeSender({ transport, log: options.log }),
  });
}
