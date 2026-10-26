import { XMLParser, XMLValidator } from 'fast-xml-parser';
import type { HttpResponse, ProviderAdapter, ProviderContext } from '../types.js';
import { signAwsRequest, type AwsCredentials } from './aws-sigv4.js';

interface CredentialPair {
  accessIdVar: string;
  credentials: AwsCredentials;
}

function validAccessId(value: string, secrets: (string | undefined)[]): boolean {
  return /^[A-Za-z0-9_]{16,128}$/.test(value) && !secrets.some((secret) => secret && value.includes(secret));
}

function credentialPair(ctx: ProviderContext, secretValue?: string): CredentialPair {
  const siblings = ctx.siblingVars ?? {};
  const candidates = Object.keys(siblings).filter((name) => name.endsWith('_ACCESS_KEY_ID') && siblings[name]);
  const accessIdVar = siblings.AWS_ACCESS_KEY_ID ? 'AWS_ACCESS_KEY_ID' : candidates.length === 1 ? candidates[0] : undefined;
  if (!accessIdVar) {
    throw new Error(candidates.length > 1 ? 'AWS access key ID is ambiguous.' : 'AWS access key ID is missing.');
  }
  const secretName = accessIdVar.replace(/_ACCESS_KEY_ID$/, '_SECRET_ACCESS_KEY');
  // Revoke uses the matching sibling pair selected by the caller, including the old pair for cleanup.
  const secretAccessKey = secretValue ?? siblings[secretName];
  if (!secretAccessKey) throw new Error('AWS secret access key is missing.');
  const sessionToken = siblings[accessIdVar.replace(/_ACCESS_KEY_ID$/, '_SESSION_TOKEN')];
  const accessKeyId = siblings[accessIdVar]!;
  if (!validAccessId(accessKeyId, [secretAccessKey, sessionToken])) throw new Error('AWS access key ID is invalid.');
  return {
    accessIdVar,
    credentials: { accessKeyId, secretAccessKey, ...(sessionToken ? { sessionToken } : {}) },
  };
}

async function query(ctx: ProviderContext, service: 'iam' | 'sts', credentials: AwsCredentials,
  parameters: Record<string, string>): Promise<HttpResponse> {
  try {
    return await ctx.http.request(signAwsRequest({
      method: 'POST',
      url: `https://${service}.amazonaws.com/`,
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
      body: new URLSearchParams(parameters).toString(),
    }, credentials, { region: 'us-east-1', service }));
  } catch {
    throw new Error('AWS request failed.');
  }
}

function ensureOk(response: HttpResponse): void {
  if (response.status < 200 || response.status >= 300) throw new Error(`AWS request failed (HTTP ${response.status}).`);
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function child(value: unknown, name: string): Record<string, unknown> {
  if (!record(value) || !record(value[name])) throw new Error('AWS returned an invalid response.');
  return value[name];
}

function stringField(value: Record<string, unknown>, name: string): string {
  const field = value[name];
  if (typeof field !== 'string' || !field.trim()) throw new Error('AWS returned an invalid response.');
  return field;
}

function parseResponse(response: HttpResponse, name: string): Record<string, unknown> {
  try {
    // AWS query responses do not need DTDs or entity expansion.
    if (/<!DOCTYPE/i.test(response.text) || XMLValidator.validate(response.text) !== true) throw new Error();
    const parser = new XMLParser({ ignoreAttributes: true, removeNSPrefix: true, parseTagValue: false,
      parseAttributeValue: false, processEntities: false, trimValues: false });
    return child(parser.parse(response.text) as unknown, name);
  } catch {
    throw new Error('AWS returned an invalid response.');
  }
}

export const awsProvider: ProviderAdapter = {
  id: 'aws',
  method: 'auto',
  async verify(value, ctx) {
    let status: number | undefined;
    try {
      const { credentials } = credentialPair(ctx, value);
      const response = await query(ctx, 'sts', credentials, { Action: 'GetCallerIdentity', Version: '2011-06-15' });
      status = response.status;
      if (status === 403) {
        const error = child(parseResponse(response, 'ErrorResponse'), 'Error');
        // The engine retries this signal only while verifying a newly created replacement.
        if (stringField(error, 'Code') === 'InvalidClientTokenId') return { ok: false, status, error: 'propagating' };
      }
      // GetCallerIdentity needs no read grant; a 403 is not evidence of a valid restricted key.
      if (status < 200 || status >= 300) return { ok: false, status, error: `AWS verification failed (HTTP ${status}).` };
      const result = child(parseResponse(response, 'GetCallerIdentityResponse'), 'GetCallerIdentityResult');
      const identity = stringField(result, 'Arn');
      const account = stringField(result, 'Account');
      if (!/^\d{12}$/.test(account) || !/^arn:[a-z0-9-]+:(?:iam|sts)::\d{12}:[A-Za-z0-9+=,.@_:/-]+$/.test(identity)
        || !identity.includes(`::${account}:`) || identity.includes(value)
        || (credentials.sessionToken && identity.includes(credentials.sessionToken))) {
        throw new Error('AWS returned an invalid response.');
      }
      return { ok: true, status, identity };
    } catch {
      return { ok: false, ...(status !== undefined ? { status } : {}), error: 'AWS verification failed.' };
    }
  },
  async rotate(oldValue, ctx) {
    const { accessIdVar, credentials } = credentialPair(ctx, oldValue);
    if (credentials.sessionToken) {
      throw new Error('AWS automatic rotation does not support session credentials; renew the temporary credentials through their issuer.');
    }
    const response = await query(ctx, 'iam', credentials, { Action: 'CreateAccessKey', Version: '2010-05-08' });
    ensureOk(response);
    const result = child(parseResponse(response, 'CreateAccessKeyResponse'), 'CreateAccessKeyResult');
    const key = child(result, 'AccessKey');
    const newId = stringField(key, 'AccessKeyId');
    const newValue = stringField(key, 'SecretAccessKey');
    if (!validAccessId(newId, [oldValue, newValue, credentials.sessionToken])) throw new Error('AWS returned an invalid response.');
    return {
      newValue,
      oldKeyRef: credentials.accessKeyId,
      newKeyRef: newId,
      oldRevoked: false,
      companions: { [accessIdVar]: newId },
      notes: 'verification may need up to ~30 s',
    };
  },
  async revoke(keyRef, ctx) {
    if (!keyRef) throw new Error('AWS access key reference is missing.');
    const { credentials } = credentialPair(ctx);
    const response = await query(ctx, 'iam', credentials, {
      Action: 'DeleteAccessKey', Version: '2010-05-08', AccessKeyId: keyRef,
    });
    ensureOk(response);
    parseResponse(response, 'DeleteAccessKeyResponse');
  },
  guidance() {
    return {
      url: 'https://console.aws.amazon.com/iam/home#/security_credentials',
      steps: [
        'Create a second access key for the IAM user; AWS allows at most two active access keys per user.',
        'Update the secret access key and its matching access key ID together, then redeploy and verify every consumer.',
        'Deactivate and delete the old access key after the new pair works. Automatic rotation needs IAM CreateAccessKey and DeleteAccessKey permissions.',
        'Temporary role credentials must be renewed through the role or identity provider; manage their session token together with the pair.',
      ],
    };
  },
};

export default awsProvider;
