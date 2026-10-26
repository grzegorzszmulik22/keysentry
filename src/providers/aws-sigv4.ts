import { createHash, createHmac } from 'node:crypto';
import type { HttpRequest } from '../types.js';

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface AwsSigningOptions {
  region: string;
  service: string;
  now?: Date;
}

function hash(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function hmac(key: string | Buffer, value: string): Buffer {
  return createHmac('sha256', key).update(value, 'utf8').digest();
}

function encode(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Header-based SigV4 for the IAM/STS query APIs; returns a new request without mutating its input. */
export function signAwsRequest(request: HttpRequest, credentials: AwsCredentials, options: AwsSigningOptions): HttpRequest {
  let url: URL;
  let timestamp: string;
  try {
    url = new URL(request.url);
    timestamp = (options.now ?? new Date()).toISOString().replace(/[:-]|\.\d{3}/g, '');
  } catch {
    throw new Error('AWS signing request is invalid.');
  }
  if (url.protocol !== 'https:' || url.username || url.password || !credentials.accessKeyId || !credentials.secretAccessKey
    || !options.region || !options.service) {
    throw new Error('AWS signing request is invalid.');
  }

  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(request.headers ?? {})) {
    const lower = name.toLowerCase();
    if (lower !== 'authorization' && lower !== 'x-amz-security-token') headers[lower] = value.trim().replace(/\s+/g, ' ');
  }
  headers.host = url.host;
  headers['x-amz-date'] = timestamp;
  if (credentials.sessionToken) headers['x-amz-security-token'] = credentials.sessionToken;

  const headerNames = Object.keys(headers).sort(compare);
  const canonicalHeaders = headerNames.map((name) => `${name}:${headers[name]}\n`).join('');
  const signedHeaders = headerNames.join(';');
  const query = [...url.searchParams.entries()].map(([name, value]) => [encode(name), encode(value)] as const)
    .sort(([leftName, leftValue], [rightName, rightValue]) => compare(leftName, rightName) || compare(leftValue, rightValue))
    .map(([name, value]) => `${name}=${value}`).join('&');
  const path = url.pathname.split('/').map(encode).join('/') || '/';
  const canonicalRequest = [request.method, path, query, canonicalHeaders, signedHeaders, hash(request.body ?? '')].join('\n');
  const date = timestamp.slice(0, 8);
  const scope = `${date}/${options.region}/${options.service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', timestamp, scope, hash(canonicalRequest)].join('\n');
  const dateKey = hmac(`AWS4${credentials.secretAccessKey}`, date);
  const regionKey = hmac(dateKey, options.region);
  const serviceKey = hmac(regionKey, options.service);
  const signingKey = hmac(serviceKey, 'aws4_request');
  const signature = hmac(signingKey, stringToSign).toString('hex');

  headers.authorization = `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { ...request, headers };
}
