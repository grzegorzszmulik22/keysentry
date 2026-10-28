import { randomUUID } from 'node:crypto';
import type { HostAdapter, HttpClient, HttpResponse, Logger, RawVariable, ServiceRef } from '../types.js';
import { signAwsRequest, type AwsCredentials } from '../providers/aws-sigv4.js';

/**
 * AWS Secrets Manager as a keysentry host (notes/secret-stores.md).
 *
 * One secret (by ARN) is one ServiceRef. A SecretString that is a JSON object is a key/value map: each string-valued
 * key is a variable; numbers, booleans, null and nested values are kept unchanged and are not variables. Any other
 * SecretString is one variable named after the last `/`-separated segment of the secret name. SecretBinary is reported
 * as one write-only variable and is never written.
 *
 * Writes create a new version with a temporary staging label, then move AWSCURRENT from the version that was read to
 * the new one. UpdateSecretVersionStage fails when RemoveFromVersionId no longer holds AWSCURRENT, so a concurrent
 * change is never overwritten. Tags, description, KMS key, rotation and replication settings belong to the secret,
 * not the version, and are untouched. A random ClientRequestToken makes each PutSecretValue idempotent.
 */
export interface AwsSecretsManagerHostOptions {
  region: string;
  credentials: AwsCredentials;
  /** Scan only these secret names or ARNs (DescribeSecret each). */
  secretIds?: string[];
  /** ListSecrets `name` filter values (case-sensitive prefix match). Ignored when secretIds is set. */
  namePrefixes?: string[];
  http: HttpClient;
  log: Logger;
  now?: () => Date;
  randomUUID?: () => string;
}

export const AWS_SECRETS_MANAGER_PENDING_LABEL = 'KEYSENTRY_PENDING';

const REGION = /^(?:[a-z]+-)+\d+$/;
const FILTER_VALUE = /^[a-zA-Z0-9 :_@/+=.-]{1,512}$/;
const MAX_SECRET_LENGTH = 65_536;
const MAX_PAGES = 5_000;

type Operation = 'ListSecrets' | 'DescribeSecret' | 'GetSecretValue' | 'PutSecretValue' | 'UpdateSecretVersionStage';

class AwsCallError extends Error {
  constructor(readonly status: number, readonly code: string | undefined) {
    super(`AWS Secrets Manager request failed (HTTP ${status})`);
    this.name = 'AwsCallError';
  }
}

function invalidResponse(): never {
  throw new Error('AWS Secrets Manager returned an invalid response');
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalidResponse();
  return value as Record<string, unknown>;
}

function nonempty(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) invalidResponse();
  return value;
}

/** Error codes are fixed AWS identifiers; messages are never read. */
function errorCode(response: HttpResponse): string | undefined {
  try {
    const type = (response.json<Record<string, unknown>>() ?? {}).__type;
    if (typeof type !== 'string') return undefined;
    const code = type.slice(type.lastIndexOf('#') + 1);
    return /^[A-Za-z]{1,64}$/.test(code) ? code : undefined;
  } catch {
    return undefined;
  }
}

/** The variable name of a plain-string secret: the last path segment of its name. */
export function plainVariableName(secretName: string): string {
  const segment = secretName.slice(secretName.lastIndexOf('/') + 1);
  return segment || secretName;
}

function jsonObject(text: string): Record<string, unknown> | undefined {
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { return undefined; }
  return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
}

/**
 * Minified text with every string token re-encoded. Equal to JSON.stringify(JSON.parse(text)) exactly when
 * re-serializing cannot change anything but whitespace and string escapes (no lossy numbers, no duplicate keys).
 */
function canonicalText(text: string): string | undefined {
  let out = '';
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]!;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') continue;
    if (ch !== '"') { out += ch; continue; }
    let end = i + 1;
    while (end < text.length && text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
    if (end >= text.length) return undefined;
    try { out += JSON.stringify(JSON.parse(text.slice(i, end + 1)) as string); } catch { return undefined; }
    i = end;
  }
  return out;
}

/**
 * Replace the string values of existing top-level keys in place, keeping every other byte of the original text
 * (indentation, key order, line endings). Returns undefined when a key is new or the text cannot be walked; the
 * caller then writes the minified form, which parsers read identically.
 */
export function replaceJsonStringValues(text: string, updates: ReadonlyMap<string, string>): string | undefined {
  let out = '';
  let depth = 0;
  let afterColon = false;
  let key: string | undefined;
  const replaced = new Set<string>();
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]!;
    if (ch === '"') {
      let end = i + 1;
      while (end < text.length && text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      if (end >= text.length) return undefined;
      const token = text.slice(i, end + 1);
      let decoded: string;
      try { decoded = JSON.parse(token) as string; } catch { return undefined; }
      if (depth === 1 && afterColon) {
        if (key !== undefined && updates.has(key) && !replaced.has(key)) {
          out += JSON.stringify(updates.get(key));
          replaced.add(key);
        } else out += token;
        afterColon = false;
      } else {
        if (depth === 1) key = decoded;
        out += token;
      }
      i = end;
      continue;
    }
    if (ch === ':' && depth === 1) afterColon = true;
    else if (ch !== ' ' && ch !== '\t' && ch !== '\n' && ch !== '\r') {
      afterColon = false;
      if (ch === '{' || ch === '[') depth += 1;
      else if (ch === '}' || ch === ']') depth -= 1;
    }
    out += ch;
  }
  return replaced.size === updates.size ? out : undefined;
}

export function createAwsSecretsManagerHost(opts: AwsSecretsManagerHostOptions): HostAdapter {
  if (!REGION.test(opts.region)) throw new Error('AWS Secrets Manager region is invalid');
  const endpoint = `https://secretsmanager.${opts.region}.amazonaws.com/`;
  const prefixes = opts.namePrefixes ?? [];
  if (prefixes.length > 10 || prefixes.some((prefix) => !FILTER_VALUE.test(prefix))) {
    throw new Error('AWS Secrets Manager name prefixes are invalid (at most 10, no "!" negation)');
  }
  const newToken = opts.randomUUID ?? randomUUID;

  async function call(operation: Operation, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    let response: HttpResponse;
    try {
      response = await opts.http.request(signAwsRequest({
        method: 'POST',
        url: endpoint,
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': `secretsmanager.${operation}`,
        },
        body: JSON.stringify(body),
      }, opts.credentials, { region: opts.region, service: 'secretsmanager', ...(opts.now ? { now: opts.now() } : {}) }));
    } catch {
      throw new Error('AWS Secrets Manager request failed');
    }
    if (response.status < 200 || response.status >= 300) throw new AwsCallError(response.status, errorCode(response));
    try { return object(response.json<unknown>()); } catch (error) {
      if (error instanceof Error && error.message.startsWith('AWS Secrets Manager')) throw error;
      throw new Error('AWS Secrets Manager returned invalid JSON');
    }
  }

  function ref(entry: Record<string, unknown>): ServiceRef {
    return {
      host: 'aws-secrets-manager', projectId: opts.region, projectName: opts.region,
      serviceId: nonempty(entry.ARN), serviceName: nonempty(entry.Name), environmentId: '', environmentName: '',
    };
  }

  async function getValue(arn: string, versionId?: string): Promise<{ versionId: string; name: string; text?: string }> {
    const result = await call('GetSecretValue', { SecretId: arn, ...(versionId ? { VersionId: versionId } : {}) });
    const id = nonempty(result.VersionId);
    if (versionId !== undefined && id !== versionId) invalidResponse();
    if (result.SecretString !== undefined && typeof result.SecretString !== 'string') invalidResponse();
    if (result.SecretString === undefined && typeof result.SecretBinary !== 'string') invalidResponse();
    return { versionId: id, name: nonempty(result.Name), ...(typeof result.SecretString === 'string' ? { text: result.SecretString } : {}) };
  }

  async function label(arn: string, stage: string, move: string | undefined, remove: string | undefined): Promise<void> {
    await call('UpdateSecretVersionStage', {
      SecretId: arn, VersionStage: stage,
      ...(move === undefined ? {} : { MoveToVersionId: move }),
      ...(remove === undefined ? {} : { RemoveFromVersionId: remove }),
    });
  }

  return {
    id: 'aws-secrets-manager',
    // A secret store does not deploy (activation manual); whether consumers read at use time is the application's choice.
    capabilities: { readValues: true, batchWrite: true, redeploy: false },

    async listServices() {
      if (opts.secretIds !== undefined) {
        const refs: ServiceRef[] = [];
        for (const secretId of new Set(opts.secretIds)) {
          if (!secretId) throw new Error('AWS Secrets Manager secret id is empty');
          const described = await call('DescribeSecret', { SecretId: secretId });
          if (described.DeletedDate === undefined || described.DeletedDate === null) refs.push(ref(described));
        }
        return refs;
      }
      const refs: ServiceRef[] = [];
      const seen = new Set<string>();
      let nextToken: string | undefined;
      for (let page = 0; page < MAX_PAGES; page += 1) {
        const page_ = await call('ListSecrets', {
          MaxResults: 100,
          ...(prefixes.length ? { Filters: [{ Key: 'name', Values: prefixes }] } : {}),
          ...(nextToken === undefined ? {} : { NextToken: nextToken }),
        });
        if (!Array.isArray(page_.SecretList)) invalidResponse();
        for (const entry of page_.SecretList.map(object)) {
          if (entry.DeletedDate === undefined || entry.DeletedDate === null) refs.push(ref(entry));
        }
        // NextToken can arrive with an empty page; only its absence ends the listing.
        if (page_.NextToken === undefined || page_.NextToken === null) return refs;
        const token = nonempty(page_.NextToken);
        if (seen.has(token)) throw new Error('AWS Secrets Manager pagination did not advance');
        seen.add(token);
        nextToken = token;
      }
      throw new Error('AWS Secrets Manager pagination did not advance');
    },

    async readVariables(service): Promise<RawVariable[]> {
      const value = await getValue(service.serviceId);
      const plainName = plainVariableName(value.name);
      if (value.text === undefined) return [{ name: plainName, sealed: true }];
      const map = jsonObject(value.text);
      if (!map) return [{ name: plainName, value: value.text, sealed: false }];
      return Object.entries(map)
        .filter((entry): entry is [string, string] => typeof entry[1] === 'string')
        .map(([name, text]) => ({ name, value: text, sealed: false }));
    },

    async writeVariables(service, vars, _writeOptions) {
      const entries = Object.entries(vars);
      if (entries.length === 0) return;
      const arn = service.serviceId;
      const described = await call('DescribeSecret', { SecretId: arn });
      if (described.OwningService !== undefined && described.OwningService !== null) {
        throw new Error('AWS Secrets Manager secret is managed by another AWS service; update it through that service');
      }
      if (described.DeletedDate !== undefined && described.DeletedDate !== null) throw new Error('AWS Secrets Manager secret is scheduled for deletion');
      const stages = object(described.VersionIdsToStages);
      let current: string | undefined;
      for (const [versionId, labels] of Object.entries(stages)) {
        if (!Array.isArray(labels) || !labels.every((item) => typeof item === 'string')) invalidResponse();
        if (labels.includes('AWSPENDING')) {
          throw new Error('AWS Secrets Manager secret has a rotation in progress (AWSPENDING); finish or cancel it first');
        }
        if (labels.includes('AWSCURRENT')) {
          if (current !== undefined) invalidResponse();
          current = versionId;
        }
      }
      if (current === undefined) invalidResponse();
      if (described.RotationEnabled === true) {
        opts.log.warn('AWS Secrets Manager secret has automatic rotation turned on; its rotation function may replace this value later', { secret: service.serviceName });
      }

      const value = await getValue(arn, current);
      if (value.text === undefined) throw new Error('AWS Secrets Manager binary secrets are not written by keysentry');
      let next: string;
      const map = jsonObject(value.text);
      if (map) {
        if (canonicalText(value.text) !== JSON.stringify(map)) {
          throw new Error('AWS Secrets Manager secret JSON has numbers or duplicate keys that rewriting would change; update it manually');
        }
        for (const [name] of entries) {
          if (Object.hasOwn(map, name) && typeof map[name] !== 'string') {
            throw new Error('AWS Secrets Manager secret key holds a non-string value; keysentry only replaces string values');
          }
        }
        const merged = JSON.stringify(Object.fromEntries([...Object.entries(map), ...entries]));
        // Keep the secret's own formatting when only existing values change; check the result parses to the same map.
        const inPlace = replaceJsonStringValues(value.text, new Map(entries));
        next = inPlace !== undefined && JSON.stringify(jsonObject(inPlace)) === merged ? inPlace : merged;
      } else {
        const plainName = plainVariableName(value.name);
        if (entries.length !== 1 || entries[0]![0] !== plainName) {
          throw new Error('AWS Secrets Manager plain-text secret holds one value named after the secret; other keys cannot be added');
        }
        next = entries[0]![1];
        if (jsonObject(next)) {
          throw new Error('AWS Secrets Manager plain-text secret would become a JSON key/value map; update it manually');
        }
      }
      if (next === value.text) return;
      if (next.length === 0 || next.length > MAX_SECRET_LENGTH) throw new Error('AWS Secrets Manager secret value size is out of range');

      const token = newToken();
      if (!/^[A-Za-z0-9-]{32,64}$/.test(token)) throw new Error('AWS Secrets Manager client request token is invalid');
      const put = await call('PutSecretValue', {
        SecretId: arn, ClientRequestToken: token, SecretString: next, VersionStages: [AWS_SECRETS_MANAGER_PENDING_LABEL],
      });
      if (put.VersionId !== token) invalidResponse();
      try {
        // Fails unless AWSCURRENT is still on the version keysentry read.
        await label(arn, 'AWSCURRENT', token, current);
      } catch (error) {
        try { await label(arn, AWS_SECRETS_MANAGER_PENDING_LABEL, undefined, token); } catch { /* keep the original failure */ }
        if (error instanceof AwsCallError && (error.code === 'InvalidParameterException' || error.code === 'InvalidRequestException')) {
          throw new Error('AWS Secrets Manager secret changed while keysentry was writing it; the current value was left as it was. Scan again and retry.');
        }
        if (error instanceof AwsCallError) throw new Error(`AWS Secrets Manager did not make the new version current (HTTP ${error.status})`);
        throw error;
      }
      try {
        await label(arn, AWS_SECRETS_MANAGER_PENDING_LABEL, undefined, token);
      } catch {
        opts.log.warn('AWS Secrets Manager kept a temporary staging label on the new current version', { secret: service.serviceName, label: AWS_SECRETS_MANAGER_PENDING_LABEL });
      }
    },

    async redeploy() { return null; },
    async deploymentStatus() { throw new Error('AWS Secrets Manager does not create deployments'); },
  };
}
