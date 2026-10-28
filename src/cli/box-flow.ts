import { createPublicKey, type X509Certificate } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import {
  createHandshake, handshakeAttestationNonces, parseHandshakeMessage, verifyAttestation, verifyHandshakeMessage,
  boxAttestationAudience, type BoxAttest, type BoxHello, type BoxRelay, type Handshake, type HandshakeMessage, type JwksFetcher,
} from '../box/index.js';
import type { DeviceKey } from '../security/index.js';
import type { AttestationPolicy, AttestationResult } from '../types.js';
import { CliError } from './errors.js';
import { BoxRelayError } from '../box/index.js';

/** Spec §7.10, verbatim. */
export const BOX_HONEST_CLAIM = 'Your keys are decrypted only inside a confidential machine running the exact open-source build you can verify. '
  + 'Our staff cannot log in to it and the cloud provider cannot read its memory. In the standard option we control the key-release policy; '
  + 'every change to it is public. With bring-your-own-KMS, only you control it.';

/** What the CLI trusts for one box. Allowed digests come from the verified allow-list, or the emulator's test policy. */
export interface BoxTrust {
  jwks: JwksFetcher;
  root?: X509Certificate;
  projectIds: string[];
  serviceAccounts: string[];
  allowedDigests: string[];
  hardwareModels?: AttestationPolicy['hardwareModels'];
  emulator: boolean;
}

export interface BoxCheck { name: string; ok: boolean; detail: string }
export interface BoxVerification {
  ok: boolean;
  checks: BoxCheck[];
  /** Names of failed checks, in order: what the CLI tells the user it refused on. */
  failed: string[];
  digest: string | null;
}

export interface BoxSessionOptions {
  relay: BoxRelay;
  boxId: string;
  deviceKey: DeviceKey;
  trust: BoxTrust;
  now?: () => Date;
  timeoutMs?: number;
  pollMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

export interface VerifiedBoxSession {
  verification: BoxVerification;
  /** Present only when every check passed: the next step seals to the attested key. */
  send?(plaintext: Buffer): Promise<void>;
}

const NOT_ANSWERING = 'The box did not answer within two minutes. Check that it is running, then try again.';

function parse(raw: unknown): HandshakeMessage | null {
  try { return parseHandshakeMessage(raw); } catch { return null; }
}
function signingDer(raw: string): Buffer {
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw }, format: 'jwk' }).export({ format: 'der', type: 'spki' });
}

async function until<T>(options: BoxSessionOptions, find: () => Promise<T | undefined>, message = NOT_ANSWERING): Promise<T> {
  const now = options.now ?? (() => new Date());
  const sleep = options.sleep ?? (ms => delay(ms));
  const deadline = now().getTime() + (options.timeoutMs ?? 120_000);
  while (true) {
    let found: T | undefined;
    // A busy or briefly unreachable relay only delays the session; the deadline still applies.
    try { found = await find(); } catch (error) { if (!(error instanceof BoxRelayError)) throw error; }
    if (found !== undefined) return found;
    if (now().getTime() >= deadline) throw new CliError(message);
    await sleep(options.pollMs ?? 1_000);
  }
}

/**
 * Answer the box's newest open hello with a fresh challenge, then verify the attestation that comes back against the
 * key from that hello and this challenge. Nothing is sent to the box unless every check passes.
 */
export async function openVerifiedBoxSession(options: BoxSessionOptions): Promise<VerifiedBoxSession> {
  const now = options.now ?? (() => new Date());
  const { relay } = options;
  const hello = await until(options, async () => {
    const queued = (await relay.poll()).map(raw => ({ raw, message: parse(raw) }));
    const answered = new Set(queued.filter(item => item.message?.type === 'cli-challenge').map(item => item.message!.sessionId));
    const open = queued.filter((item): item is { raw: unknown; message: BoxHello } => item.message?.type === 'box-hello'
      && !answered.has(item.message.sessionId) && Date.parse(item.message.expiresAt) > now().getTime() + 60_000);
    return open.sort((a, b) => Date.parse(b.message.sentAt) - Date.parse(a.message.sentAt))[0];
  });
  let handshake: Handshake = createHandshake('cli', { deviceKey: options.deviceKey });
  const challengeStep = handshake.next({ now: now(), message: hello.raw });
  handshake = challengeStep.handshake;
  const challenge = challengeStep.message as Extract<HandshakeMessage, { type: 'cli-challenge' }>;
  await relay.publish(challenge);
  // Expected nonces come from local state: the key in the hello this CLI answered and its own fresh challenge.
  const expectedNonces = [handshakeAttestationNonces(hello.message)[0]!, challenge.challenge];
  const sessionId = hello.message.sessionId;
  const attest = await until(options, async () => (await relay.poll(sessionId))
    .map(raw => ({ raw, message: parse(raw) }))
    .find((item): item is { raw: unknown; message: BoxAttest } => item.message?.type === 'box-attest' && item.message.sessionId === sessionId));

  const own: BoxCheck[] = [];
  const signed = verifyHandshakeMessage(attest.message, signingDer(hello.message.boxSigningPublicKey));
  own.push({ name: 'box-signature', ok: signed, detail: signed ? 'Signed by the key the box announced.' : 'Not signed by the key the box announced.' });
  const unchanged = attest.message.boxPublicKey === hello.message.boxPublicKey && attest.message.boxSigningPublicKey === hello.message.boxSigningPublicKey;
  own.push({ name: 'box-key-unchanged', ok: unchanged, detail: unchanged ? 'Same keys as the box announced.' : 'The box keys changed during the session.' });
  const policy: AttestationPolicy = { audience: boxAttestationAudience(options.boxId), projectIds: options.trust.projectIds,
    serviceAccounts: options.trust.serviceAccounts, allowedDigests: options.trust.allowedDigests,
    hardwareModels: options.trust.hardwareModels ?? ['GCP_INTEL_TDX', 'GCP_AMD_SEV'], maxTokenAgeSeconds: 300, clockSkewSeconds: 60 };
  const result: AttestationResult = await verifyAttestation({ token: attest.message.attestationToken, jwks: options.trust.jwks,
    ...(options.trust.root ? { root: options.trust.root } : {}), policy, expectedNonces, now: now() });
  const checks = [...own, ...result.checks];
  const ok = result.ok && own.every(check => check.ok);
  const verification: BoxVerification = { ok, checks, failed: checks.filter(check => !check.ok).map(check => check.name),
    digest: ok ? result.claims?.submods?.container?.image_digest ?? null : null };
  if (!ok) return { verification };
  return {
    verification,
    async send(plaintext) {
      const bundleStep = handshake.next({ now: now(), message: attest.raw, verifiedAttestation: result, plaintext });
      handshake = bundleStep.handshake;
      await relay.publish(bundleStep.message!);
      await until(options, async () => {
        for (const raw of await relay.poll(sessionId)) {
          if (parse(raw)?.type !== 'box-ack') continue;
          try { handshake = handshake.next({ now: now(), message: raw }).handshake; return true; } catch { /* not this session's ack */ }
        }
        return undefined;
      }, 'The box did not confirm it kept the bundle. Run keysentry box check, then try again.');
    },
  };
}

/** One line per check, with the claim it supports. */
export function renderBoxVerification(boxId: string, verification: BoxVerification, emulator: boolean): string {
  const lines = [`Box ${boxId}: ${verification.ok ? 'every check passed' : `refused (${verification.failed.join(', ')})`}`];
  for (const check of verification.checks) lines.push(`  ${check.ok ? 'pass' : 'FAIL'}  ${check.name.padEnd(18)} ${check.detail}`);
  if (verification.digest) lines.push(`Image digest: ${verification.digest}`);
  if (emulator) lines.push('Local emulator: these checks use the emulator\'s test signing keys and test digests, not Google\'s.');
  lines.push('', BOX_HONEST_CLAIM);
  return lines.join('\n');
}
