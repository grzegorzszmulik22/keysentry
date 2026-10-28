import { createHash } from 'node:crypto';
import { signAwsRequest, type AwsCredentials } from '../providers/aws-sigv4.js';
import { canonicalJson } from '../security/index.js';
import type { AuditExportRecord, HttpClient, HttpRequest, Vault } from '../types.js';
import { credentialText, httpFailure, readSecret, sendRequest } from './delivery.js';
import { AuditExportError, type ExportSink, type S3Target } from './types.js';

const RECEIVER = 'storage service';
const RETRYABLE = (status: number) => status === 409 || status === 429 || status === 500 || status === 502 || status === 503 || status === 504;
const AWS_ENDPOINT = /^s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com$/;
const sha256 = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

/** `<prefix><yyyy>/<mm>/<dd>/<firstSeq>-<lastSeq>.jsonl`, dated by the first record so a retry names the same object. */
export function s3ObjectKey(prefix: string, batch: readonly AuditExportRecord[]): string {
  const first = batch[0];
  const last = batch.at(-1);
  if (!first || !last) throw new AuditExportError('An empty batch cannot be stored.', false);
  const date = new Date(first.at);
  if (!Number.isFinite(date.getTime())) throw new AuditExportError('An audit entry has an unreadable time.', false);
  const yyyy = String(date.getUTCFullYear()).padStart(4, '0');
  const mm = String(date.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(date.getUTCDate()).padStart(2, '0');
  return `${prefix}${yyyy}/${mm}/${dd}/${first.seq}-${last.seq}.jsonl`;
}

/**
 * AWS endpoints use virtual-hosted-style URLs (path-style is deprecated there) unless the bucket name has a dot, which
 * the *.s3 wildcard certificate cannot cover. Other S3-compatible services get path-style URLs under their endpoint.
 */
export function s3ObjectUrl(target: S3Target, key: string): string {
  const endpoint = new URL(target.endpoint);
  const base = endpoint.pathname.replace(/\/+$/, '');
  const virtual = AWS_ENDPOINT.test(endpoint.hostname) && base === '' && !target.bucket.includes('.');
  const path = virtual ? `/${key}` : `${base}/${target.bucket}/${key}`;
  const url = new URL(`https://${virtual ? `${target.bucket}.${endpoint.hostname}` : endpoint.hostname}${path}`);
  // URL parsing removes "." and ".." segments; the stored name must be exactly the configured one.
  if (url.pathname !== path) throw new AuditExportError('The S3 prefix must not contain "." or ".." path segments.', false);
  return url.href;
}

/** The host that receives the object, for the egress allow-list. */
export function s3RequestOrigin(target: S3Target): string {
  return new URL(s3ObjectUrl(target, 'keysentry-audit-probe')).origin;
}

export function s3BatchBody(batch: readonly AuditExportRecord[]): string {
  return batch.map(record => `${canonicalJson(record)}\n`).join('');
}

export function createS3Sink(target: S3Target, deps: { http: HttpClient; vault: Vault; now: () => Date }): ExportSink {
  let credentials: AwsCredentials | undefined;
  let conditional = true;

  async function load(): Promise<AwsCredentials> {
    if (credentials) return credentials;
    const id = await readSecret(deps.vault, target.id, 'access-key-id');
    const secret = await readSecret(deps.vault, target.id, 'secret-access-key');
    const token = await readSecret(deps.vault, target.id, 'session-token');
    try {
      if (!id || !secret) throw new AuditExportError(`Store the S3 credentials first: keysentry audit export secret ${target.id} access-key-id, then secret-access-key.`, false);
      const accessKeyId = credentialText(id, 256);
      const secretAccessKey = credentialText(secret, 256);
      const sessionToken = token ? credentialText(token, 8192) : undefined;
      if (!accessKeyId || !secretAccessKey || sessionToken === null) throw new AuditExportError('The stored S3 credentials have an unsupported format.', false);
      credentials = { accessKeyId, secretAccessKey, ...(sessionToken ? { sessionToken } : {}) };
      return credentials;
    } finally { id?.fill(0); secret?.fill(0); token?.fill(0); }
  }

  function signed(request: HttpRequest, creds: AwsCredentials): HttpRequest {
    try { return signAwsRequest(request, creds, { region: target.region, service: 's3', now: deps.now() }); }
    catch { throw new AuditExportError('The S3 request could not be signed. Check the endpoint and region.', false); }
  }

  /** After 412, the object exists: it counts as delivered only if it holds exactly this batch. */
  async function confirmExisting(url: string, body: string, creds: AwsCredentials): Promise<void> {
    const response = await sendRequest(deps.http, signed({ method: 'GET', url, headers: { 'x-amz-content-sha256': sha256('') } }, creds), RECEIVER);
    if (response.status === 200) {
      if (response.text === body) return;
      throw new AuditExportError('An object with this batch\'s name already holds different records (another project, or an earlier copy of this log). Give each project its own S3 prefix.', false);
    }
    if (response.status === 404) throw new AuditExportError('The storage service reported the object both present and missing; it will be sent again.', true);
    throw new AuditExportError('An object with this batch\'s name already exists, and keysentry could not read it to confirm it holds this batch. Give each project its own prefix, or allow s3:GetObject on it.', false);
  }

  return {
    target,
    destination: `S3 bucket ${target.bucket} at ${new URL(target.endpoint).host}, prefix "${target.prefix}"`,
    async deliver(batch) {
      const key = s3ObjectKey(target.prefix, batch);
      const url = s3ObjectUrl(target, key);
      const body = s3BatchBody(batch);
      const creds = await load();
      const warnings: string[] = [];
      for (;;) {
        const headers: Record<string, string> = { 'content-type': 'application/x-ndjson', 'x-amz-content-sha256': sha256(body),
          ...(conditional ? { 'if-none-match': '*' } : {}) };
        const response = await sendRequest(deps.http, signed({ method: 'PUT', url, headers, body }, creds), RECEIVER);
        if (response.status === 200) return warnings.length ? { warnings } : {};
        if (response.status === 412 && conditional) { await confirmExisting(url, body, creds); return {}; }
        if (response.status === 501 && conditional) {
          // The service rejects conditional writes. Object names are fixed by sequence numbers and the log is
          // append-only, so a resent batch can only rewrite an object with identical records. Say so.
          conditional = false;
          warnings.push('This storage service does not support conditional writes (If-None-Match), so a resent batch may rewrite its object with identical records.');
          continue;
        }
        throw httpFailure(response, RECEIVER, deps.now(), RETRYABLE);
      }
    },
    preview(batch) {
      const key = s3ObjectKey(target.prefix, batch);
      return { location: `${target.bucket}/${key}`, bytes: Buffer.byteLength(s3BatchBody(batch)) };
    },
    dispose() { credentials = undefined; },
  };
}
