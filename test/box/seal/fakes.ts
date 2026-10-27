import { createCipheriv, createDecipheriv, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import type { AttestationClaims, HttpRequest } from '../../../src/types.js';
import { FakeHttp, json } from '../../helpers/fake-http.js';

export interface ReleasePolicy {
  projectId: string;
  serviceAccount: string;
  digest: string;
}

type Body = Record<string, unknown>;

export interface SealFakeControls {
  stsStatus?: number;
  kmsStatus?: number;
  stsResponse?: (body: Body) => Body;
  encryptResponse?: (body: Body) => Body;
  decryptResponse?: (body: Body) => Body;
}

export interface SealFakeOptions {
  audience?: string;
  keyName?: string;
  policy?: Partial<ReleasePolicy>;
  /** Milliseconds since the Unix epoch. */
  now?: () => number;
}

// Deliberately independent of the production table implementation.
function checksum(data: Uint8Array): string {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0);
  }
  return String((crc ^ 0xffffffff) >>> 0);
}

function bodyOf(req: HttpRequest): Body {
  const parsed: unknown = JSON.parse(req.body ?? '{}');
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid request.');
  return parsed as Body;
}

function header(req: HttpRequest, name: string): string | undefined {
  return Object.entries(req.headers ?? {}).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
}

function bytes(value: unknown): Buffer {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error('Invalid byte field.');
  }
  return Buffer.from(value, 'base64');
}

/** Local REST services only. The subject JWT and the bearer token are checked independently at each boundary. */
export function createSealFakes(options: SealFakeOptions = {}) {
  const now = options.now ?? Date.now;
  const audience = options.audience ?? '//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/box-pool/providers/box-provider';
  const keyName = options.keyName ?? 'projects/keysentry-box/locations/global/keyRings/box/cryptoKeys/seal';
  const policy: ReleasePolicy = {
    projectId: 'keysentry-box',
    serviceAccount: 'box@keysentry-box.iam.gserviceaccount.com',
    digest: `sha256:${'a'.repeat(64)}`,
    ...options.policy,
  };
  const controls: SealFakeControls = {};
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const issued = new Map<string, AttestationClaims>();
  const keys = new Map<string, Buffer>([[keyName, randomBytes(32)]]);
  const seconds = Math.floor(now() / 1000);
  const baseClaims: AttestationClaims = {
    iss: 'https://confidentialcomputing.googleapis.com',
    aud: 'https://sts.googleapis.com',
    iat: seconds,
    nbf: seconds,
    exp: seconds + 3600,
    secboot: true,
    dbgstat: 'disabled-since-boot',
    hwmodel: 'GCP_INTEL_TDX',
    swname: 'CONFIDENTIAL_SPACE',
    google_service_accounts: [policy.serviceAccount],
    submods: {
      confidential_space: { support_attributes: ['STABLE'], monitoring_enabled: { memory: false } },
      container: { image_digest: policy.digest, env_override: {}, cmd_override: [] },
      gce: { project_id: policy.projectId, project_number: '123456789', instance_id: '987654321' },
    },
  };

  function mintSubjectToken(overrides: Partial<AttestationClaims> = {}): string {
    const claims = { ...structuredClone(baseClaims), ...overrides };
    const head = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'seal-test-key' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
    const input = `${head}.${payload}`;
    return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
  }

  function permits(claims: AttestationClaims): boolean {
    const at = Math.floor(now() / 1000);
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    return claims.iss === 'https://confidentialcomputing.googleapis.com'
      && aud.includes('https://sts.googleapis.com')
      && Number.isFinite(claims.iat) && claims.iat <= at
      && Number.isFinite(claims.exp) && claims.exp > at
      && (claims.nbf === undefined || (Number.isFinite(claims.nbf) && claims.nbf <= at))
      && claims.swname === 'CONFIDENTIAL_SPACE'
      && claims.dbgstat === 'disabled-since-boot'
      && claims.submods?.confidential_space?.support_attributes?.includes('STABLE') === true
      && claims.submods?.gce?.project_id === policy.projectId
      && claims.google_service_accounts?.includes(policy.serviceAccount) === true
      && claims.submods?.container?.image_digest === policy.digest;
  }

  function subjectClaims(token: unknown): AttestationClaims {
    if (typeof token !== 'string') throw new Error('Invalid subject token.');
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid subject token.');
    const [head, payload, signature] = parts as [string, string, string];
    const decodedHeader = JSON.parse(Buffer.from(head, 'base64url').toString('utf8')) as Body;
    if (decodedHeader.alg !== 'RS256' || decodedHeader.typ !== 'JWT' || decodedHeader.kid !== 'seal-test-key'
      || !verify('RSA-SHA256', Buffer.from(`${head}.${payload}`), publicKey, Buffer.from(signature, 'base64url'))) {
      throw new Error('Invalid subject token.');
    }
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as AttestationClaims;
    if (!permits(claims)) throw new Error('Release policy refused.');
    return claims;
  }

  const http = new FakeHttp();
  http.on('POST', /^https:\/\/sts\.googleapis\.com\/v1\/token$/, (req) => {
    if (controls.stsStatus !== undefined) return json(controls.stsStatus, { error: 'release_policy_refused' });
    try {
      const body = bodyOf(req);
      const fields = ['audience', 'grantType', 'requestedTokenType', 'scope', 'subjectToken', 'subjectTokenType'];
      if (Object.keys(body).length !== fields.length || fields.some((field) => !(field in body))
        || header(req, 'Authorization') !== undefined
        || !header(req, 'Content-Type')?.startsWith('application/json')
        || body.audience !== audience
        || body.grantType !== 'urn:ietf:params:oauth:grant-type:token-exchange'
        || body.requestedTokenType !== 'urn:ietf:params:oauth:token-type:access_token'
        || body.scope !== 'https://www.googleapis.com/auth/cloud-platform'
        || body.subjectTokenType !== 'urn:ietf:params:oauth:token-type:jwt') {
        return json(400, { error: 'invalid_request' });
      }
      const claims = subjectClaims(body.subjectToken);
      const accessToken = randomBytes(32).toString('base64url');
      issued.set(accessToken, claims);
      const response = { access_token: accessToken, token_type: 'Bearer', expires_in: 3600 };
      return json(200, controls.stsResponse?.(response) ?? response);
    } catch {
      return json(403, { error: 'release_policy_refused' });
    }
  });

  http.on('POST', /^https:\/\/cloudkms\.googleapis\.com\/v1\/(.+):(encrypt|decrypt)$/, (req, match) => {
    if (controls.kmsStatus !== undefined) return json(controls.kmsStatus, { error: { status: 'PERMISSION_DENIED' } });
    const authorization = header(req, 'Authorization');
    const claims = authorization?.startsWith('Bearer ') ? issued.get(authorization.slice(7)) : undefined;
    if (!claims || !permits(claims)) return json(403, { error: { status: 'PERMISSION_DENIED' } });
    const name = match[1]!;
    const operation = match[2]!;
    const key = keys.get(name);
    if (!key) return json(404, { error: { status: 'NOT_FOUND' } });
    try {
      if (!header(req, 'Content-Type')?.startsWith('application/json')) throw new Error('Invalid request.');
      const body = bodyOf(req);
      const aad = bytes(body.additionalAuthenticatedData);
      const inputName = operation === 'encrypt' ? 'plaintext' : 'ciphertext';
      const input = bytes(body[inputName]);
      if (aad.length > 65536 || input.length > (operation === 'encrypt' ? 65536 : 65564)
        || String(body[`${inputName}Crc32c`]) !== checksum(input)
        || String(body.additionalAuthenticatedDataCrc32c) !== checksum(aad)) {
        return json(400, { error: { status: 'INVALID_ARGUMENT' } });
      }
      if (operation === 'encrypt') {
        const nonce = randomBytes(12);
        const cipher = createCipheriv('aes-256-gcm', key, nonce);
        cipher.setAAD(aad);
        const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
        const ciphertext = Buffer.concat([nonce, cipher.getAuthTag(), encrypted]);
        const response = {
          name: `${name}/cryptoKeyVersions/1`,
          ciphertext: ciphertext.toString('base64'),
          ciphertextCrc32c: checksum(ciphertext),
          verifiedPlaintextCrc32c: true,
          verifiedAdditionalAuthenticatedDataCrc32c: true,
          protectionLevel: 'SOFTWARE',
        };
        return json(200, controls.encryptResponse?.(response) ?? response);
      }
      if (input.length < 28) throw new Error('Invalid ciphertext.');
      const decipher = createDecipheriv('aes-256-gcm', key, input.subarray(0, 12));
      decipher.setAAD(aad);
      decipher.setAuthTag(input.subarray(12, 28));
      const plaintext = Buffer.concat([decipher.update(input.subarray(28)), decipher.final()]);
      const response = {
        plaintext: plaintext.toString('base64'),
        plaintextCrc32c: checksum(plaintext),
        usedPrimary: true,
        protectionLevel: 'SOFTWARE',
      };
      return json(200, controls.decryptResponse?.(response) ?? response);
    } catch {
      return json(400, { error: { status: 'INVALID_ARGUMENT' } });
    }
  });

  return { http, audience, keyName, policy, baseClaims, controls, mintSubjectToken };
}
