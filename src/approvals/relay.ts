import { canonicalJson, verifyDetached } from '../security/index.js';
import type { AuditLog, HttpClient } from '../types.js';

export const APPROVAL_PREFIX = 'keysentry-approval:v1\n';
export const DISARM_PREFIX = 'keysentry-disarm:v1\n';

export interface SignedDeviceApproval {
  actionId: string;
  keyId: string;
  digest: string;
  at: string;
  /** Base64 Ed25519 signature. */
  sig: string;
}

export interface SignedDisarm {
  keyId: string;
  at: string;
  /** Base64 Ed25519 signature. */
  sig: string;
}

export interface RelayOptions {
  http: HttpClient;
  server: string;
  topic: string;
  token?: string;
  trustedKeyIds: string[];
  /** Key IDs alone cannot verify signatures. Absent key material accepts no messages. */
  deviceKeys?: () => Promise<{ keyId: string; publicKeyDer: Buffer }[]>;
  audit: AuditLog;
  now?: () => Date;
}

export interface RelayPollResult {
  approvals: SignedDeviceApproval[];
  disarms: SignedDisarm[];
  cursor: string | null;
  ignored: number;
}

const MAX_RESPONSE = 4 * 1024 * 1024;
const MAX_LINE = 16 * 1024;
const WINDOW_MS = 10 * 60 * 1000;
const MAX_DISARM_CACHE = 10_000;
type IgnoreReason = 'message-too-large' | 'invalid-envelope' | 'invalid-message' | 'approval-not-verified'
  | 'disarm-not-verified' | 'disarm-replay' | 'disarm-cache-full';

function* ndjsonLines(body: string): Generator<string> {
  let offset = 0;
  while (offset < body.length) {
    const end = body.indexOf('\n', offset);
    if (end === -1) { yield body.slice(offset); return; }
    yield body.slice(offset, end);
    offset = end + 1;
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function fields(value: Record<string, unknown>, allowed: string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === allowed.length && keys.every(key => allowed.includes(key));
}

function parseJson(value: string): unknown {
  try { return JSON.parse(value) as unknown; } catch { return null; }
}

function validAt(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return false;
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return false;
  const canonical = new Date(ms).toISOString();
  return canonical === value || canonical.replace('.000Z', 'Z') === value;
}

function validSigned(value: unknown): value is SignedDisarm & Record<string, unknown> {
  if (!record(value) || typeof value.keyId !== 'string' || !/^[a-f0-9]{16}$/.test(value.keyId) || !validAt(value.at)) return false;
  if (typeof value.sig !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(value.sig)) return false;
  const decoded = Buffer.from(value.sig, 'base64');
  return decoded.length === 64 && decoded.toString('base64') === value.sig;
}

function validApproval(value: unknown): value is SignedDeviceApproval {
  return validSigned(value) && fields(value, ['actionId', 'keyId', 'digest', 'at', 'sig'])
    && typeof value.actionId === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value.actionId)
    && typeof value.digest === 'string' && /^[a-f0-9]{64}$/.test(value.digest);
}

function validDisarm(value: unknown): value is SignedDisarm {
  return validSigned(value) && fields(value, ['keyId', 'at', 'sig']);
}

function validWrapper(value: unknown, topic: string): value is Record<string, unknown> & { id: string; event: string } {
  return record(value) && typeof value.id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value.id)
    && typeof value.time === 'number' && Number.isSafeInteger(value.time) && value.time >= 0
    && value.topic === topic && typeof value.event === 'string';
}

/**
 * ntfy.sh free topics are public read/write. Setup must generate a random 32-character base32 topic;
 * secrecy of that name is not an authorization control. Only verified device signatures are accepted.
 */
export function createRelay(opts: RelayOptions): {
  publishApproval(signed: SignedDeviceApproval): Promise<void>;
  poll(since: string | null): Promise<RelayPollResult>;
} {
  let server: URL;
  try { server = new URL(opts.server); } catch { throw new Error('Invalid approval relay configuration.'); }
  if (server.protocol !== 'https:' || server.username || server.password || server.pathname !== '/'
    || server.search || server.hash || !/^[A-Za-z0-9_-]{1,64}$/.test(opts.topic)
    || (opts.token !== undefined && (typeof opts.token !== 'string' || /[\r\n\x00]/.test(opts.token)))) {
    throw new Error('Invalid approval relay configuration.');
  }
  if (!opts.audit || typeof opts.audit.append !== 'function') throw new Error('Invalid approval relay configuration.');
  const url = server.origin + '/' + opts.topic;
  const headers: Record<string, string> = opts.token ? { Authorization: `Bearer ${opts.token}` } : {};
  const trustedKeyIds = new Set(opts.trustedKeyIds);
  const now = opts.now ?? (() => new Date());
  // Replay protection for disarm is deliberately local to this relay instance. Approval service owns durable approval replay state.
  const usedDisarms = new Map<string, number>();
  let pollQueue: Promise<unknown> = Promise.resolve();

  function queuePoll(operation: () => Promise<RelayPollResult>): Promise<RelayPollResult> {
    const current = pollQueue.catch(() => undefined).then(operation);
    pollQueue = current;
    return current;
  }

  return {
    async publishApproval(signed) {
      if (!validApproval(signed)) throw new Error('Invalid signed approval.');
      let status: number;
      try {
        const response = await opts.http.request({ method: 'POST', url,
          headers: { 'Content-Type': 'application/json', ...headers },
          body: JSON.stringify({ type: 'keysentry-approval', v: 1, approval: signed }) });
        status = response.status;
      } catch { throw new Error('Unable to publish the approval.'); }
      if (status < 200 || status >= 300) throw new Error('Unable to publish the approval.');
    },

    poll(since) {
      return queuePoll(async () => {
        if (since !== null && (typeof since !== 'string' || since.length > 128 || !/^[A-Za-z0-9_-]+$/.test(since))) {
          throw new Error('Invalid approval relay cursor.');
        }
        let body: string;
        try {
          const response = await opts.http.request({ method: 'GET', url: url + '/json?poll=1&since=' + encodeURIComponent(since ?? '10m'), headers: { ...headers } });
          if (response.status < 200 || response.status >= 300) throw new Error('HTTP failure');
          body = response.text;
        } catch { throw new Error('Unable to poll the approval relay.'); }
        if (Buffer.byteLength(body, 'utf8') > MAX_RESPONSE) throw new Error('Approval relay response is too large.');
        const result: RelayPollResult = { approvals: [], disarms: [], cursor: since, ignored: 0 };
        const ignoredCounts = new Map<IgnoreReason, number>();
        const pendingDisarms = new Map<string, number>();
        function ignored(reason: IgnoreReason): void {
          result.ignored++;
          ignoredCounts.set(reason, (ignoredCounts.get(reason) ?? 0) + 1);
        }
        let keys: { keyId: string; publicKeyDer: Buffer }[];
        try { keys = opts.deviceKeys ? await opts.deviceKeys() : []; }
        catch { throw new Error('Unable to load approval relay device keys.'); }
        const trustedKeys = new Map(keys.filter(key => trustedKeyIds.has(key.keyId)).map(key => [key.keyId, key.publicKeyDer]));
        const nowMs = now().getTime();
        if (!Number.isFinite(nowMs)) throw new Error('Unable to read the approval relay clock.');
        for (const [sig, expiresAt] of usedDisarms) if (expiresAt < nowMs) usedDisarms.delete(sig);

        for (const line of ndjsonLines(body)) {
          if (!line.trim()) continue;
          if (Buffer.byteLength(line, 'utf8') > MAX_LINE) { ignored('message-too-large'); continue; }
          const envelope = parseJson(line);
          if (!validWrapper(envelope, opts.topic)) { ignored('invalid-envelope'); continue; }
          if ((envelope.event === 'open' || envelope.event === 'keepalive')
            && fields(envelope, ['id', 'time', 'event', 'topic'])) continue;
          if (envelope.event !== 'message' || typeof envelope.message !== 'string') { ignored('invalid-envelope'); continue; }
          result.cursor = envelope.id;
          const payload = parseJson(envelope.message);
          if (!record(payload) || payload.v !== 1) { ignored('invalid-message'); continue; }

          if (payload.type === 'keysentry-approval' && fields(payload, ['type', 'v', 'approval']) && validApproval(payload.approval)) {
            const signed = payload.approval;
            const publicKey = trustedKeys.get(signed.keyId);
            const data = Buffer.from(APPROVAL_PREFIX + canonicalJson({ actionId: signed.actionId, digest: signed.digest, at: signed.at }));
            if (!publicKey || Math.abs(Date.parse(signed.at) - nowMs) > WINDOW_MS || !verifyDetached(publicKey, data, Buffer.from(signed.sig, 'base64'))) {
              ignored('approval-not-verified'); continue;
            }
            result.approvals.push(signed);
          } else if (payload.type === 'keysentry-disarm' && fields(payload, ['type', 'v', 'keyId', 'at', 'sig'])) {
            const signed = { keyId: payload.keyId, at: payload.at, sig: payload.sig };
            if (!validDisarm(signed)) { ignored('disarm-not-verified'); continue; }
            const publicKey = trustedKeys.get(signed.keyId);
            const data = Buffer.from(DISARM_PREFIX + canonicalJson({ at: signed.at }));
            if (!publicKey || Math.abs(Date.parse(signed.at) - nowMs) > WINDOW_MS || !verifyDetached(publicKey, data, Buffer.from(signed.sig, 'base64'))) {
              ignored('disarm-not-verified'); continue;
            }
            if (usedDisarms.has(signed.sig) || pendingDisarms.has(signed.sig)) { ignored('disarm-replay'); continue; }
            if (usedDisarms.size + pendingDisarms.size >= MAX_DISARM_CACHE) { ignored('disarm-cache-full'); continue; }
            pendingDisarms.set(signed.sig, Date.parse(signed.at) + WINDOW_MS);
            result.disarms.push(signed);
          } else {
            ignored('invalid-message');
          }
        }
        // Seven fixed reasons cap audit writes regardless of the number of untrusted lines.
        for (const [reason, count] of ignoredCounts) {
          try {
            await opts.audit.append({ kind: 'approvals:relay-ignored', summary: 'Approval relay messages were ignored.', data: { reason, count } });
          } catch { throw new Error('Unable to record the approval relay outcome.'); }
        }
        for (const [sig, expiresAt] of pendingDisarms) usedDisarms.set(sig, expiresAt);
        return result;
      });
    },
  };
}
