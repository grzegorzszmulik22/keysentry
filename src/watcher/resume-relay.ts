import type { HttpClient } from '../types.js';
import { verifyWatcherResume, type RecoveryDeviceKey, type SignedWatcherResume } from './recovery.js';

export interface WatcherResumeRelayOptions {
  http: HttpClient;
  server: string;
  topic: string;
  token?: string;
  watcherId: string;
  trustedKeyIds: string[];
  deviceKeys: () => Promise<RecoveryDeviceKey[]>;
  now?: () => Date;
}

export interface WatcherResumeRelayPollResult {
  resumes: SignedWatcherResume[];
  /** Persist independently of the approval/disarm relay cursor, after recovery processing succeeds. */
  cursor: string | null;
  ignored: number;
}

export interface WatcherResumeRelay {
  publishResume(signed: SignedWatcherResume): Promise<void>;
  poll(since: string | null): Promise<WatcherResumeRelayPollResult>;
}

const MAX_RESPONSE = 4 * 1024 * 1024;
const MAX_LINE = 16 * 1024;

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseJson(value: string): unknown {
  try { return JSON.parse(value) as unknown; } catch { return null; }
}

function* lines(body: string): Generator<string> {
  let offset = 0;
  while (offset < body.length) {
    const end = body.indexOf('\n', offset);
    if (end === -1) { yield body.slice(offset); return; }
    yield body.slice(offset, end);
    offset = end + 1;
  }
}

function validWrapper(value: unknown, topic: string): value is Record<string, unknown> & { id: string; event: string } {
  return record(value) && typeof value.id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value.id)
    && typeof value.time === 'number' && Number.isSafeInteger(value.time) && value.time >= 0
    && value.topic === topic && typeof value.event === 'string';
}

/**
 * Resume has its own durable caller-owned cursor so approval polling cannot consume it. This adapter authenticates
 * but does not consume signatures: createActionsRecovery owns durable single-use tracking and the recovery latch.
 */
export function createWatcherResumeRelay(opts: WatcherResumeRelayOptions): WatcherResumeRelay {
  let server: URL;
  try {
    server = new URL(opts.server);
    if (server.protocol !== 'https:' || server.username || server.password || server.pathname !== '/'
      || server.search || server.hash || !/^[A-Za-z0-9_-]{1,64}$/.test(opts.topic)
      || (opts.token !== undefined && (typeof opts.token !== 'string' || /[\r\n\x00]/.test(opts.token)))
      || typeof opts.watcherId !== 'string' || opts.watcherId.length === 0 || opts.watcherId.length > 256
      || /[\u0000-\u001f\u007f]/.test(opts.watcherId) || typeof opts.deviceKeys !== 'function') {
      throw new Error();
    }
  } catch { throw new Error('Invalid watcher resume relay configuration.'); }
  const url = server.origin + '/' + opts.topic;
  const headers: Record<string, string> = opts.token ? { Authorization: `Bearer ${opts.token}` } : {};
  let pollQueue: Promise<unknown> = Promise.resolve();

  async function authentication() {
    let deviceKeys: RecoveryDeviceKey[];
    try {
      deviceKeys = await opts.deviceKeys();
      if (!Array.isArray(deviceKeys)) throw new Error();
    } catch { throw new Error('Unable to load watcher resume relay device keys.'); }
    let now: Date;
    try {
      now = (opts.now ?? (() => new Date()))();
      if (!Number.isFinite(now.getTime())) throw new Error();
    } catch { throw new Error('Unable to read the watcher resume relay clock.'); }
    return { watcherId: opts.watcherId, trustedKeyIds: opts.trustedKeyIds, deviceKeys, now };
  }

  async function poll(since: string | null): Promise<WatcherResumeRelayPollResult> {
    if (since !== null && (typeof since !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(since))) {
      throw new Error('Invalid watcher resume relay cursor.');
    }
    let body: string;
    try {
      const response = await opts.http.request({
        method: 'GET', url: url + '/json?poll=1&since=' + encodeURIComponent(since ?? '24h'), headers: { ...headers },
      });
      if (response.status < 200 || response.status >= 300 || typeof response.text !== 'string') throw new Error();
      body = response.text;
    } catch { throw new Error('Unable to poll the watcher resume relay.'); }
    if (Buffer.byteLength(body, 'utf8') > MAX_RESPONSE) throw new Error('Watcher resume relay response is too large.');
    const auth = await authentication();
    const result: WatcherResumeRelayPollResult = { resumes: [], cursor: since, ignored: 0 };

    for (const line of lines(body)) {
      if (!line.trim()) continue;
      if (Buffer.byteLength(line, 'utf8') > MAX_LINE) { result.ignored++; continue; }
      const envelope = parseJson(line);
      if (!validWrapper(envelope, opts.topic)) { result.ignored++; continue; }
      if ((envelope.event === 'open' || envelope.event === 'keepalive')
        && Object.keys(envelope).length === 4) continue;
      if (envelope.event !== 'message' || typeof envelope.message !== 'string') { result.ignored++; continue; }
      result.cursor = envelope.id;
      const payload = parseJson(envelope.message);
      if (!record(payload) || typeof payload.type !== 'string') { result.ignored++; continue; }
      // Shared topics normally contain approvals and disarms. Their validation belongs to their own relay.
      if (payload.type !== 'keysentry-resume') continue;
      const verified = verifyWatcherResume(payload, auth);
      if (verified.ok) result.resumes.push(verified.resume);
      else result.ignored++;
    }
    return result;
  }

  return {
    async publishResume(signed) {
      const verified = verifyWatcherResume(signed, await authentication());
      if (!verified.ok) throw new Error('Invalid signed watcher resume.');
      try {
        const response = await opts.http.request({ method: 'POST', url,
          headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(verified.resume) });
        if (response.status < 200 || response.status >= 300) throw new Error();
      } catch { throw new Error('Unable to publish the watcher resume.'); }
    },
    poll(since) {
      const result = pollQueue.then(() => poll(since));
      pollQueue = result.then(() => undefined, () => undefined);
      return result;
    },
  };
}
