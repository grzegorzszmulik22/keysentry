import { generateKeyPairSync } from 'node:crypto';
import type { HttpClient } from '../../../src/types.js';
import { createAccounts } from './accounts.js';
import { startEmulator, type Emulator, type EmulatorOptions } from './emulator/index.js';
import { createProvisioner } from './provision.js';
import { createRelayStore } from './relay.js';
import { createControlPlaneServer } from './server.js';
import { createMemoryStorage } from './storage.js';

/** What an emulated box receives at boot: an in-process relay, emulator attestation tokens and emulator STS/KMS. */
export interface LocalBoxRuntime {
  boxId: string;
  relay: { publish(message: unknown): Promise<void>; poll(sessionId?: string): Promise<unknown[]> };
  /** Tokens name this box as `submods.gce.instance_name`, as a hosted box's tokens name its instance. */
  tee: { token(input: { audience: string; nonces: string[]; tokenType?: 'OIDC' | 'PKI' }): Promise<string>; defaultToken(): Promise<string> };
  /** Reaches only the emulator: STS, KMS and Compute. */
  http: HttpClient;
}
export interface LocalBoxOptions {
  boxId?: string;
  /** The caller injects the box agent; this package never imports it. */
  bootBox(runtime: LocalBoxRuntime): Promise<{ stop(): Promise<void> }>;
  /**
   * The enrollment device public key (Ed25519 SPKI DER) written to the instance's `keysentry-enroll-device-key`.
   * The in-process box takes its enrollment keys from the caller, so without this a throwaway key fills the field.
   */
  enrollmentDeviceKey?: Buffer;
  emulator?: Omit<EmulatorOptions, 'startBox'>;
  /** One local user polls over loopback; the hosted default of 120 a minute is for the public internet. */
  rateLimitPerMinute?: number;
  now?: () => number;
}
export interface LocalBox {
  boxId: string;
  /** Loopback control plane: the relay routes for this box. */
  origin: string;
  /** Bearer for the relay routes of this one box, for the user's CLI. Memory only. */
  cliToken: string;
  emulator: Emulator;
  /** Stops the box and boots it again with the same disk, as host maintenance does to a TDX VM. */
  restart(): Promise<void>;
  close(): Promise<void>;
}

/**
 * Everything on 127.0.0.1: the emulator, a control plane holding the relay, and one provisioned box booted through the
 * emulator's Compute API. Nothing reaches Google; nothing is spent. The relay also accepts this box's emulator
 * attestation token for the control plane's origin, exactly as the hosted relay authenticates a box.
 */
export async function startLocalBox(options: LocalBoxOptions): Promise<LocalBox> {
  const boxId = options.boxId ?? 'local-box';
  const storage = createMemoryStorage();
  const relay = createRelayStore({ storage, ...(options.now ? { now: options.now } : {}) });
  const deviceKey = (options.enrollmentDeviceKey ?? generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' })).toString('base64');
  let running: { stop(): Promise<void> } | undefined;
  let runtime: LocalBoxRuntime | undefined;
  const emulator: Emulator = await startEmulator({ ...options.emulator, ...(options.now ? { now: options.now } : {}),
    startBox: async config => {
      if (running || config.instanceName !== boxId) throw new Error('Unexpected box.');
      runtime = {
        boxId,
        relay: { async publish(message) { await relay.publish(boxId, message); }, poll: sessionId => relay.poll(boxId, sessionId) },
        tee: {
          async token(input) { return emulator.mintToken({ audience: input.audience, nonces: [...input.nonces], instanceName: boxId, ...(input.tokenType ? { tokenType: input.tokenType } : {}) }); },
          async defaultToken() { return emulator.mintToken({ audience: 'https://sts.googleapis.com', nonces: [], instanceName: boxId }); },
        },
        http: emulator.http,
      };
      running = await options.bootBox(runtime);
    } });
  const policy = emulator.policy;
  const server = createControlPlaneServer({ origin: 'http://127.0.0.1:0', relay, rateLimitPerMinute: options.rateLimitPerMinute ?? 6_000,
    boxRateLimitPerMinute: options.rateLimitPerMinute ?? 6_000,
    ...(options.now ? { now: options.now } : {}),
    accounts: origin => createAccounts({ storage, origin }),
    boxAttestation: { jwks: async () => emulator.jwks, root: emulator.root, projectIds: [policy.projectId], serviceAccounts: [policy.serviceAccount],
      allowedDigests: policy.allowedDigests, hardwareModels: ['GCP_INTEL_TDX'], knownBox: async id => id === boxId },
    billing: { async handle() { throw new Error('Billing is off in the local emulator.'); } } });
  try {
    const { origin } = await server.listen();
    await createProvisioner({ http: emulator.http, emulatorOrigin: emulator.computeOrigin, relayOrigin: origin, projectId: policy.projectId, zone: 'us-central1-a',
      subnetwork: `projects/${policy.projectId}/regions/us-central1/subnetworks/box-subnet`, serviceAccount: policy.serviceAccount,
      imageReference: `registry.invalid/keysentry/box@${policy.allowedDigests[0]}`, allowedDigests: policy.allowedDigests }).provision({ name: boxId, deviceKey });
    return {
      boxId, origin, cliToken: server.issueBoxToken(boxId), emulator,
      async restart() {
        if (!runtime || !running) throw new Error('The local box is not running.');
        const current = running; running = undefined;
        await current.stop();
        running = await options.bootBox(runtime);
      },
      async close() {
        const current = running; running = undefined;
        // The listeners close even when the box fails to stop; the stop error is still reported.
        try { await current?.stop(); }
        finally {
          await server.close().catch(() => undefined);
          await emulator.close();
        }
      },
    };
  } catch (error) {
    await running?.stop().catch(() => undefined);
    await server.close().catch(() => undefined);
    await emulator.close();
    throw error;
  }
}
