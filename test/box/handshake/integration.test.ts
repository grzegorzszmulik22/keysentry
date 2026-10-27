import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { generateDeviceKey } from '../../../src/security/index.js';
import { verifyAttestation } from '../../../src/box/attestation/index.js';
import type { AttestationPolicy } from '../../../src/types.js';
import {
  boxKeyBindingNonce, createHandshake, generateBoxKeyPair, handshakeAttestationNonces,
  serializeHandshakeMessage,
} from '../../../src/box/handshake/index.js';
import type { BoxAttest, BoxHello } from '../../../src/box/handshake/index.js';

const now = new Date('2026-10-27T12:00:00.000Z');
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...rsa.publicKey.export({ format: 'jwk' }), kid: 'local-handshake-test', alg: 'RS256', use: 'sig' };
const digest = 'sha256:' + 'a'.repeat(64);
const policy: AttestationPolicy = {
  audience: 'keysentry-handshake-test', projectIds: ['local-box-project'],
  serviceAccounts: ['box@local-box-project.iam.gserviceaccount.com'], allowedDigests: [digest],
  hardwareModels: ['GCP_INTEL_TDX'], maxTokenAgeSeconds: 300, clockSkewSeconds: 60,
};

function token(nonces: string[], project = 'local-box-project'): string {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: jwk.kid })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: 'https://confidentialcomputing.googleapis.com', aud: policy.audience,
    iat: now.getTime() / 1000, exp: now.getTime() / 1000 + 3600, eat_nonce: nonces,
    secboot: true, dbgstat: 'disabled-since-boot', swname: 'CONFIDENTIAL_SPACE', hwmodel: 'GCP_INTEL_TDX',
    google_service_accounts: policy.serviceAccounts,
    submods: { container: { image_digest: digest }, gce: { project_id: project },
      confidential_space: { support_attributes: ['STABLE'], monitoring_enabled: { memory: false } } },
  })).toString('base64url');
  const body = `${header}.${payload}`;
  return `${body}.${sign('RSA-SHA256', Buffer.from(body), rsa.privateKey).toString('base64url')}`;
}

function exchange(project?: string) {
  const deviceKey = generateDeviceKey(), signingKey = generateDeviceKey(), boxKey = generateBoxKeyPair();
  const cli = createHandshake('cli', { deviceKey });
  const box = createHandshake('box', { devicePublicKeyDer: deviceKey.publicKeyDer, signingKey, boxKey });
  const binding = boxKeyBindingNonce(boxKey.publicKeyRaw, Buffer.from(signingKey.publicKeyDer.subarray(-32)));
  const hello = box.next({ now, attestationToken: token([binding]) });
  const challenge = cli.next({ now, message: serializeHandshakeMessage(hello.message!) });
  if (challenge.message?.type !== 'cli-challenge') throw new Error('wrong fixture step');
  const nonces = [binding, challenge.message.challenge];
  const attest = hello.handshake.next({ now, message: serializeHandshakeMessage(challenge.message),
    attestationToken: token(nonces, project) });
  return { cli, box, hello, challenge, attest, binding, nonces };
}

describe('handshake with the real local attestation verifier', () => {
  it('verifies both bound public keys and the fresh challenge before sending tokens', async () => {
    const s = exchange();
    const message = s.attest.message as BoxAttest;
    const verifiedAttestation = await verifyAttestation({ token: message.attestationToken, jwks: async () => [jwk],
      policy, expectedNonces: handshakeAttestationNonces(message), now });
    expect(verifiedAttestation.ok).toBe(true);
    expect(verifiedAttestation.boxKeyHash).toBe(s.binding);
    const sent = s.challenge.handshake.next({ now, message, verifiedAttestation, plaintext: Buffer.from('synthetic-token') });
    const opened = s.attest.handshake.next({ now, message: serializeHandshakeMessage(sent.message!) });
    expect(opened.plaintext?.toString()).toBe('synthetic-token');
    expect(sent.handshake.next({ now, message: serializeHandshakeMessage(opened.message!) }).handshake.state).toBe('complete');
    opened.plaintext?.fill(0);
  });

  it('sends no token bundle when an authentically signed attestation belongs to another project', async () => {
    const s = exchange('other-project');
    const message = s.attest.message as BoxAttest;
    const result = await verifyAttestation({ token: message.attestationToken, jwks: async () => [jwk],
      policy, expectedNonces: s.nonces, now });
    expect(result.ok).toBe(false);
    expect(() => s.challenge.handshake.next({ now, message, verifiedAttestation: result, plaintext: Buffer.from('synthetic-token') })).toThrow(/attestation/i);
    expect(s.challenge.handshake.state).toBe('awaiting-attestation');
  });

  it('never treats the initial one-nonce hello token as authorization to send tokens', async () => {
    const s = exchange();
    const hello = s.hello.message as BoxHello;
    const result = await verifyAttestation({ token: hello.attestationToken, jwks: async () => [jwk],
      policy, expectedNonces: s.nonces, now });
    expect(result.ok).toBe(false);
    expect(() => s.challenge.handshake.next({ now, message: s.attest.message, verifiedAttestation: result,
      plaintext: Buffer.from('synthetic-token') })).toThrow(/attestation/i);
  });
});
