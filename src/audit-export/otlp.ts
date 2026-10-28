import type { AuditExportRecord, HttpClient, Vault } from '../types.js';
import { credentialText, readSecret, retryAfterMs, sendRequest } from './delivery.js';
import { AuditExportError, type ExportSink, type OtlpTarget } from './types.js';

const RECEIVER = 'OpenTelemetry receiver';
/** OTLP/HTTP: only these statuses may be retried; every other 4xx/5xx must not be. */
const RETRYABLE = new Set([429, 502, 503, 504]);
/** OpenTelemetry SeverityNumber INFO (logs data model). */
const SEVERITY_INFO = 9;
const HEADER_NAME = /^[A-Za-z0-9-]{1,64}$/;
/** The egress guard strips these on a cross-host redirect, so a custom credential header must look like one. */
const CREDENTIAL_HEADER = /token|secret|key|auth/i;
const RESERVED_HEADERS = new Set(['host', 'content-type', 'content-length', 'connection', 'transfer-encoding', 'te', 'upgrade',
  'trailer', 'expect', 'proxy-authorization', 'keep-alive']);

/** A URL with no path gets the OTLP default logs path; any other path is used as given. */
export function otlpLogsUrl(url: string): string {
  const parsed = new URL(url);
  if (parsed.pathname === '/' || parsed.pathname === '') parsed.pathname = '/v1/logs';
  return parsed.href;
}

type AnyValue = Record<string, unknown>;

/** OTLP JSON AnyValue: 64-bit integers are decimal strings; objects become kvlistValue. */
function anyValue(value: unknown): AnyValue {
  if (typeof value === 'string') return { stringValue: value };
  if (typeof value === 'boolean') return { boolValue: value };
  if (typeof value === 'number') return Number.isSafeInteger(value) ? { intValue: String(value) } : { doubleValue: value };
  if (Array.isArray(value)) return { arrayValue: { values: value.map(anyValue) } };
  if (value && typeof value === 'object') {
    return { kvlistValue: { values: Object.entries(value).map(([key, item]) => ({ key, value: anyValue(item) })) } };
  }
  return {};
}

function unixNanos(iso: string): string {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? (BigInt(ms) * 1_000_000n).toString() : '0';
}

/** ExportLogsServiceRequest in OTLP/JSON (field names in lowerCamelCase, enums as integers). */
export function buildOtlpLogsBody(batch: readonly AuditExportRecord[], opts: { observedAt: Date; sourceId?: string; logId?: string }): string {
  const observed = unixNanos(opts.observedAt.toISOString());
  return JSON.stringify({
    resourceLogs: [{
      resource: { attributes: [
        { key: 'service.name', value: { stringValue: 'keysentry' } },
        ...(opts.sourceId ? [{ key: 'keysentry.source', value: { stringValue: opts.sourceId } }] : []),
        ...(opts.logId ? [{ key: 'keysentry.audit.log', value: { stringValue: opts.logId } }] : []),
      ] },
      scopeLogs: [{
        scope: { name: 'keysentry.audit', version: '1' },
        logRecords: batch.map(record => ({
          timeUnixNano: unixNanos(record.at),
          observedTimeUnixNano: observed,
          severityNumber: SEVERITY_INFO,
          severityText: 'INFO',
          body: { stringValue: record.summary },
          attributes: [
            { key: 'keysentry.audit.seq', value: { intValue: String(record.seq) } },
            { key: 'keysentry.audit.kind', value: { stringValue: record.kind } },
            ...(record.actor === undefined ? [] : [{ key: 'keysentry.audit.actor', value: { stringValue: record.actor } }]),
            ...(record.data === undefined ? [] : [{ key: 'keysentry.audit.data', value: anyValue(record.data) }]),
          ],
        })),
      }],
    }],
  });
}

/** `partialSuccess.rejectedLogRecords` from an ExportLogsServiceResponse; 0 when absent or unreadable. */
function rejectedRecords(text: string): number {
  if (!text.trim()) return 0;
  try {
    const parsed = JSON.parse(text) as { partialSuccess?: { rejectedLogRecords?: unknown } } | null;
    const value = parsed?.partialSuccess?.rejectedLogRecords;
    const count = typeof value === 'string' && /^\d{1,15}$/.test(value) ? Number(value) : typeof value === 'number' ? value : 0;
    return Number.isSafeInteger(count) && count > 0 ? count : 0;
  } catch { return 0; }
}

/**
 * The stored custom header line, `Name: value`, as the sink sends it (name lower-cased), or null when it cannot be sent.
 * `keysentry audit export secret <id> header` checks with this same function (review L3). With `singleHost` (the
 * runtime's per-target client, which follows no redirect) any ordinary header name works; on a shared client the name
 * must look like a credential header, which the egress guard strips on a cross-host redirect. Transport and framing
 * headers are never accepted.
 */
export function parseOtlpHeader(line: string, opts: { singleHost: boolean }): { name: string; value: string } | null {
  const colon = line.indexOf(':');
  const name = colon > 0 ? line.slice(0, colon).trim() : '';
  const value = colon > 0 ? line.slice(colon + 1).trim() : '';
  if (!HEADER_NAME.test(name) || RESERVED_HEADERS.has(name.toLowerCase())
    || (!opts.singleHost && !CREDENTIAL_HEADER.test(name)) || !/^[\x20-\x7e]{1,4096}$/.test(value)) return null;
  return { name: name.toLowerCase(), value };
}

/**
 * `singleHost: true` says `http` reaches only this target's host and follows no redirect elsewhere (the runtime's
 * per-target client), so the custom header may have any name. On a shared client its name must look like a credential
 * header, which the egress guard strips on a cross-host redirect.
 */
export function createOtlpSink(target: OtlpTarget, deps: { http: HttpClient; vault: Vault; now: () => Date; sourceId?: string; logId?: string; singleHost?: boolean }): ExportSink {
  const labels = { ...(deps.sourceId ? { sourceId: deps.sourceId } : {}), ...(deps.logId ? { logId: deps.logId } : {}) };
  const url = otlpLogsUrl(target.url);
  let headers: Record<string, string> | undefined;

  async function credentials(): Promise<Record<string, string>> {
    if (headers) return headers;
    const result: Record<string, string> = { 'content-type': 'application/json' };
    const bearer = await readSecret(deps.vault, target.id, 'bearer');
    const header = await readSecret(deps.vault, target.id, 'header');
    try {
      if (bearer) {
        const token = credentialText(bearer);
        if (!token) throw new AuditExportError('The stored OTLP bearer token has an unsupported format.', false);
        result.authorization = `Bearer ${token}`;
      }
      if (header) {
        const parsed = parseOtlpHeader(header.toString('utf8'), { singleHost: deps.singleHost === true });
        if (!parsed || parsed.name in result) {
          throw new AuditExportError(deps.singleHost ? 'The stored OTLP header must be "Name: value" with an ordinary header name.'
            : 'The stored OTLP header must be "Name: value", with a name containing token, secret, key or auth.', false);
        }
        result[parsed.name] = parsed.value;
      }
    } finally { bearer?.fill(0); header?.fill(0); }
    headers = result;
    return result;
  }

  return {
    target,
    // Host only: a URL path can carry a token, and it never appears in output.
    destination: `OpenTelemetry logs at ${new URL(url).host}`,
    async deliver(batch) {
      const body = buildOtlpLogsBody(batch, { observedAt: deps.now(), ...labels });
      const response = await sendRequest(deps.http, { method: 'POST', url, headers: { ...await credentials() }, body }, RECEIVER);
      if (response.status === 200 || response.status === 201 || response.status === 202) {
        const rejected = rejectedRecords(response.text);
        // OTLP: a partial success must not be retried. The rejection is reported, never hidden.
        return rejected ? { warnings: [`The OpenTelemetry receiver accepted the batch but rejected ${rejected} of ${batch.length} records; OTLP forbids resending them.`] } : {};
      }
      const retryable = RETRYABLE.has(response.status);
      throw new AuditExportError(`The ${RECEIVER} answered HTTP ${response.status}.`, retryable,
        retryable ? retryAfterMs(response.headers, deps.now()) : undefined);
    },
    preview: batch => ({ location: new URL(url).host,
      bytes: Buffer.byteLength(buildOtlpLogsBody(batch, { observedAt: deps.now(), ...labels })) }),
    dispose() { headers = undefined; },
  };
}
