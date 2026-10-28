import { signAwsRequest, type AwsCredentials } from '../providers/aws-sigv4.js';
import type { KeyWrapper, TokenRole } from '../types.js';
import { failureFor, invalidResponse, KmsError, missingCredentials, rejected } from './errors.js';
import {
  assertContext, assertDataKey, credential, decodeBase64, decodeEnvelope, encodeEnvelope, jsonObject, roleFor, send,
  type KeyWrapperDeps, type KmsOperation,
} from './shared.js';
import type { AwsKmsSettings } from './settings.js';

const PROVIDER = 'aws-kms' as const;
const ARN = /^arn:(aws|aws-us-gov):kms:([a-z0-9-]{1,32}):(\d{12}):(key|alias)\/([A-Za-z0-9/_-]{1,256})$/;
const SAFE_HEADER = /^[\x21-\x7e]{1,4096}$/;

interface ParsedArn { partition: string; region: string; account: string; type: 'key' | 'alias' }

function parseArn(value: string): ParsedArn | null {
  const match = ARN.exec(value);
  return match ? { partition: match[1]!, region: match[2]!, account: match[3]!, type: match[4] as 'key' | 'alias' } : null;
}

/** AWS KMS JSON API (TrentService.Encrypt/Decrypt) signed with SigV4. The context is the encryption context `{ keysentry: context }`. */
export function createAwsKmsWrapper(settings: AwsKmsSettings, deps: KeyWrapperDeps): KeyWrapper {
  const configured = parseArn(settings.keyId);
  if (!configured) {
    throw new KmsError('config', 'AWS KMS supports key or alias ARNs in the aws and aws-us-gov partitions. Check kms.keyId in keysentry.yaml.');
  }
  if (configured.region !== settings.region) {
    throw new KmsError('config', 'The AWS KMS key ARN names a different region than kms.region. Make them match in keysentry.yaml.');
  }
  const host = `kms.${settings.region}.amazonaws.com`;
  const now = deps.now ?? (() => new Date());

  /** The key ARN AWS reports must be the configured key, or for an alias, a key in the alias's account and region. */
  function acceptedKeyArn(value: unknown): value is string {
    if (typeof value !== 'string') return false;
    const parsed = parseArn(value);
    if (!parsed || parsed.type !== 'key') return false;
    if (configured!.type === 'key') return value === settings.keyId;
    return parsed.partition === configured!.partition && parsed.region === configured!.region && parsed.account === configured!.account;
  }

  async function awsCredentials(role: TokenRole): Promise<AwsCredentials> {
    const accessKeyId = await credential(deps.credentials, 'AWS_ACCESS_KEY_ID', role);
    const secretAccessKey = await credential(deps.credentials, 'AWS_SECRET_ACCESS_KEY', role);
    const sessionToken = await credential(deps.credentials, 'AWS_SESSION_TOKEN', role);
    if (!accessKeyId || !secretAccessKey) throw missingCredentials(PROVIDER, 'AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN for temporary credentials)');
    if (!SAFE_HEADER.test(accessKeyId) || !SAFE_HEADER.test(secretAccessKey) || (sessionToken !== null && !SAFE_HEADER.test(sessionToken))) {
      throw new KmsError('credentials', 'The AWS credentials for AWS KMS are not in a valid format. Check AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN.');
    }
    return { accessKeyId, secretAccessKey, ...(sessionToken ? { sessionToken } : {}) };
  }

  async function call(operation: KmsOperation, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const credentials = await awsCredentials(roleFor(operation));
    const target = operation === 'wrap' ? 'TrentService.Encrypt' : 'TrentService.Decrypt';
    let signed;
    try {
      signed = signAwsRequest({
        method: 'POST', url: `https://${host}/`,
        headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': target },
        body: JSON.stringify(body),
      }, credentials, { region: settings.region, service: 'kms', now: now() });
    } catch { throw new KmsError('credentials', 'The AWS credentials for AWS KMS could not sign the request. Check them and try again.'); }
    const response = await send(PROVIDER, deps.http, signed);
    const parsed = jsonObject(response);
    if (response.status !== 200) {
      const type = typeof parsed?.__type === 'string' ? parsed.__type.split('#').pop() : undefined;
      throw failureFor(PROVIDER, response.status, operation, type && /^[A-Za-z]{1,64}$/.test(type) ? type : undefined);
    }
    if (!parsed) throw invalidResponse(PROVIDER);
    return parsed;
  }

  return {
    provider: PROVIDER,
    keyRef: settings.keyId,
    async wrap(dataKey, context) {
      assertDataKey(dataKey, 4096); assertContext(context);
      const body = await call('wrap', { KeyId: settings.keyId, Plaintext: dataKey.toString('base64'), EncryptionContext: { keysentry: context } });
      const ciphertext = decodeBase64(body.CiphertextBlob, 6144);
      if (!ciphertext || !acceptedKeyArn(body.KeyId) || (body.EncryptionAlgorithm !== undefined && body.EncryptionAlgorithm !== 'SYMMETRIC_DEFAULT')) {
        ciphertext?.fill(0);
        throw invalidResponse(PROVIDER);
      }
      // The key ARN is kept so Decrypt names the exact key, even after an alias is moved to another key.
      return encodeEnvelope({ key: body.KeyId as string, ciphertext: ciphertext.toString('base64') });
    },
    async unwrap(wrapped, context) {
      assertContext(context);
      const envelope = decodeEnvelope(PROVIDER, wrapped, ['key', 'ciphertext']);
      if (!acceptedKeyArn(envelope.key) || !decodeBase64(envelope.ciphertext, 6144)) throw rejected(PROVIDER);
      const body = await call('unwrap', { KeyId: envelope.key, CiphertextBlob: envelope.ciphertext, EncryptionContext: { keysentry: context } });
      if (body.KeyId !== envelope.key) throw invalidResponse(PROVIDER);
      const plaintext = decodeBase64(body.Plaintext, 4096);
      if (!plaintext) throw invalidResponse(PROVIDER);
      return plaintext;
    },
  };
}

/** The non-secret key version label stored inside an AWS envelope (the key ARN AWS used). */
export function awsKeyVersion(wrapped: Buffer): string | undefined {
  try { return decodeEnvelope(PROVIDER, wrapped, ['key', 'ciphertext']).key; } catch { return undefined; }
}
