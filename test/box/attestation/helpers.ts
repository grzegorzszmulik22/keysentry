import { createHash, generateKeyPairSync, sign, X509Certificate, type JsonWebKey, type KeyObject } from 'node:crypto';
import type { AttestationClaims, AttestationPolicy } from '../../../src/types.js';

export const TEST_NOW = new Date('2026-10-27T12:00:00Z');
export const TEST_BOX_NONCE = createHash('sha256').update(Buffer.alloc(32, 7)).digest('base64url');
export const TEST_CHALLENGE_NONCE = Buffer.alloc(32, 9).toString('base64url');
export const TEST_POLICY: AttestationPolicy = {
  audience: 'https://keysentry.test/box',
  projectIds: ['keysentry-test'],
  serviceAccounts: ['box@keysentry-test.iam.gserviceaccount.com'],
  allowedDigests: [`sha256:${'a'.repeat(64)}`],
  hardwareModels: ['GCP_INTEL_TDX', 'GCP_AMD_SEV'],
  maxTokenAgeSeconds: 300,
  clockSkewSeconds: 60,
};

export function passingClaims(): AttestationClaims {
  const now = TEST_NOW.getTime() / 1000;
  return {
    iss: 'https://confidentialcomputing.googleapis.com',
    aud: TEST_POLICY.audience,
    exp: now + 3600,
    iat: now - 10,
    nbf: now - 10,
    eat_nonce: [TEST_BOX_NONCE, TEST_CHALLENGE_NONCE],
    secboot: true,
    dbgstat: 'disabled-since-boot',
    hwmodel: 'GCP_INTEL_TDX',
    swname: 'CONFIDENTIAL_SPACE',
    swversion: ['261000'],
    google_service_accounts: [...TEST_POLICY.serviceAccounts],
    submods: {
      confidential_space: { support_attributes: ['LATEST', 'STABLE'], monitoring_enabled: { memory: false } },
      container: {
        image_digest: TEST_POLICY.allowedDigests[0]!,
        image_reference: `us-docker.pkg.dev/keysentry-test/box/watcher@${TEST_POLICY.allowedDigests[0]}`,
        image_id: `sha256:${'b'.repeat(64)}`,
        restart_policy: 'Always',
        env: { PATH: '/usr/local/bin:/usr/bin' },
        args: ['/app/keysentry'],
      },
      gce: { project_id: TEST_POLICY.projectIds[0]!, project_number: '123456789012', zone: 'us-central1-a',
        instance_name: 'keysentry-box-test', instance_id: '1234567890123456789' },
    },
  };
}

// Minimal DER certificate construction keeps the test CA local and dependency-free.
function der(tag: number, bytes: Buffer): Buffer {
  let length: Buffer;
  if (bytes.length < 128) length = Buffer.from([bytes.length]);
  else {
    let hex = bytes.length.toString(16);
    if (hex.length % 2) hex = `0${hex}`;
    const size = Buffer.from(hex, 'hex');
    length = Buffer.concat([Buffer.from([0x80 | size.length]), size]);
  }
  return Buffer.concat([Buffer.from([tag]), length, bytes]);
}
const seq = (...parts: Buffer[]) => der(0x30, Buffer.concat(parts));
const oid = (hex: string) => der(0x06, Buffer.from(hex, 'hex'));
const rsaSha256 = seq(oid('2a864886f70d01010b'), der(0x05, Buffer.alloc(0)));
const name = (value: string) => seq(der(0x31, seq(oid('550403'), der(0x0c, Buffer.from(value)))));
const time = (value: Date, raw?: string) => der(0x17, Buffer.from(raw
  ?? value.toISOString().replace(/[-:]/g, '').slice(2, 15).replace('T', '') + 'Z'));

function certificate(input: {
  subject: string; issuer: string; publicKey: KeyObject; signer: KeyObject; ca: boolean;
  validFrom: Date; validTo: Date; rawValidFrom?: string; rawValidTo?: string; serial: number;
}): X509Certificate {
  const constraints = seq(oid('551d13'), der(0x01, Buffer.from([0xff])),
    der(0x04, input.ca ? seq(der(0x01, Buffer.from([0xff]))) : seq()));
  const tbs = seq(der(0xa0, der(0x02, Buffer.from([2]))), der(0x02, Buffer.from([input.serial])),
    rsaSha256, name(input.issuer), seq(time(input.validFrom, input.rawValidFrom), time(input.validTo, input.rawValidTo)), name(input.subject),
    input.publicKey.export({ format: 'der', type: 'spki' }), der(0xa3, seq(constraints)));
  return new X509Certificate(seq(tbs, rsaSha256, der(0x03, Buffer.concat([
    Buffer.from([0]), sign('RSA-SHA256', tbs, input.signer),
  ]))));
}

export interface TestTokenFactoryOptions {
  leafModulusLength?: number;
  leafExponent?: number;
  validFrom?: Date;
  validTo?: Date;
  leafRawValidFrom?: string;
  leafRawValidTo?: string;
  rootCa?: boolean;
  intermediateCa?: boolean;
  rootValidFrom?: Date;
  rootValidTo?: Date;
  intermediateValidFrom?: Date;
  intermediateValidTo?: Date;
  brokenLeafSignature?: boolean;
  brokenIntermediateSignature?: boolean;
  brokenRootSignature?: boolean;
}

export function createTokenFactory(options: TestTokenFactoryOptions = {}): {
  jwk: JsonWebKey; root: X509Certificate; x5c: string[]; privateKey: KeyObject;
  sign(claims?: unknown, header?: Record<string, unknown>): string;
} {
  const rootKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const intermediateKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const leafKeys = generateKeyPairSync('rsa', { modulusLength: options.leafModulusLength ?? 2048,
    publicExponent: options.leafExponent ?? 65537 });
  const validFrom = options.validFrom ?? new Date('2025-01-01T00:00:00Z');
  const validTo = options.validTo ?? new Date('2030-01-01T00:00:00Z');
  const root = certificate({ subject: 'keysentry test root', issuer: 'keysentry test root',
    publicKey: rootKeys.publicKey, signer: options.brokenRootSignature ? intermediateKeys.privateKey : rootKeys.privateKey,
    ca: options.rootCa ?? true,
    validFrom: options.rootValidFrom ?? validFrom, validTo: options.rootValidTo ?? validTo, serial: 1 });
  const intermediate = certificate({ subject: 'keysentry test intermediate', issuer: 'keysentry test root',
    publicKey: intermediateKeys.publicKey,
    signer: options.brokenIntermediateSignature ? intermediateKeys.privateKey : rootKeys.privateKey,
    ca: options.intermediateCa ?? true,
    validFrom: options.intermediateValidFrom ?? validFrom, validTo: options.intermediateValidTo ?? validTo, serial: 2 });
  const leaf = certificate({ subject: 'keysentry test signer', issuer: 'keysentry test intermediate',
    publicKey: leafKeys.publicKey, signer: options.brokenLeafSignature ? rootKeys.privateKey : intermediateKeys.privateKey,
    ca: false, validFrom, validTo, rawValidFrom: options.leafRawValidFrom,
    rawValidTo: options.leafRawValidTo, serial: 3 });
  const jwk: JsonWebKey = { ...leafKeys.publicKey.export({ format: 'jwk' }), kid: 'test-key', alg: 'RS256', use: 'sig' };
  return {
    jwk, root, x5c: [leaf, intermediate, root].map(cert => cert.raw.toString('base64')), privateKey: leafKeys.privateKey,
    sign(claims: unknown = passingClaims(), header: Record<string, unknown> = {}): string {
      const encodedHeader = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'test-key', ...header })).toString('base64url');
      const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
      const signed = `${encodedHeader}.${payload}`;
      return `${signed}.${sign('RSA-SHA256', Buffer.from(signed), leafKeys.privateKey).toString('base64url')}`;
    },
  };
}
