import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import {
  BoxPayloadError, BoxRelayError, createHttpBoxRelay, decodeBoxPayload, encodeBoxPayload, readBoxRoute, readMetadataAttribute, relayCredential,
  type BoxEnrollPayload,
} from '../../../src/box/agent/index.js';
import { generateDeviceKey } from '../../../src/security/index.js';
import type { HttpRequest } from '../../../src/types.js';
import { EventEmitter } from 'node:events';
import type { ClientRequest, IncomingMessage } from 'node:http';

const device = generateDeviceKey().publicKeyDer.toString('base64');
const enroll = (): BoxEnrollPayload => ({ v: 1, kind: 'enroll', boxId: 'alpha-box',
  settings: { mode: 'standard', audience: '//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q',
    keyName: 'projects/p/locations/global/keyRings/r/cryptoKeys/k', deviceKeys: [device] },
  deployment: { KEYSENTRY_WATCHER_KEY: 'a', KEYSENTRY_WATCHER_CONFIG: 'b', KEYSENTRY_STATE_KEY: 'c', KEYSENTRY_VAULT_PASSPHRASE: 'd', KEYSENTRY_WATCHER_VAULT: 'e' },
  notice: { channels: [{ id: 'phone', kind: 'ntfy', server: 'https://ntfy.sh' }], secrets: [{ name: 'notify/phone/topic', value: 'topic' }] } });

describe('box bundle payload', () => {
  it('round-trips an enroll and an unlock payload', () => {
    const bytes = encodeBoxPayload(enroll());
    expect(decodeBoxPayload(bytes)).toEqual(enroll());
    const unlock = { v: 1, kind: 'unlock', boxId: 'alpha-box', shareB: Buffer.alloc(32, 3).toString('base64') } as const;
    expect(decodeBoxPayload(encodeBoxPayload(unlock))).toEqual(unlock);
  });

  it('refuses unknown fields, a share outside unlock-on-restart, bad device keys and oversized bundles', () => {
    expect(() => encodeBoxPayload({ ...enroll(), extra: true } as never)).toThrow(BoxPayloadError);
    expect(() => encodeBoxPayload({ ...enroll(), shareB: Buffer.alloc(32).toString('base64') })).toThrow(/only with unlock-on-restart/);
    expect(() => encodeBoxPayload({ ...enroll(), settings: { ...enroll().settings, deviceKeys: ['AAAA'] } })).toThrow(BoxPayloadError);
    expect(() => encodeBoxPayload({ ...enroll(), settings: { ...enroll().settings, deviceKeys: [device, device] } })).toThrow(BoxPayloadError);
    expect(() => encodeBoxPayload({ ...enroll(), deployment: { ...enroll().deployment, KEYSENTRY_WATCHER_VAULT: 'x'.repeat(1024 * 1024) } })).toThrow(/1 MiB/);
    expect(() => encodeBoxPayload({ ...enroll(), boxId: 'Not_A_Box' })).toThrow(BoxPayloadError);
  });

  it('decoding errors never echo bundle contents', () => {
    const planted = 'sk-or-v1-planted-value-0123456789';
    for (const input of [Buffer.from(planted), Buffer.from(JSON.stringify({ ...enroll(), v: 2, note: planted })), Buffer.from([0xff, 0xfe])]) {
      try { decodeBoxPayload(input); expect.unreachable(); }
      catch (error) { expect(error).toBeInstanceOf(BoxPayloadError); expect(String((error as Error).message)).not.toContain(planted); }
    }
  });
});

describe('relay client', () => {
  it('sends the credential as a bearer header, never in the URL, and checks replies', async () => {
    const calls: HttpRequest[] = [];
    let reply = { status: 201, body: '{}' };
    const relay = createHttpBoxRelay({ origin: 'https://relay.example', boxId: 'alpha-box', credential: async () => 'secret-capability',
      http: { async request(input) { calls.push(input); return { status: reply.status, headers: {}, text: reply.body, json: () => JSON.parse(reply.body) }; } } });
    await relay.publish({ type: 'box-hello' } as never);
    reply = { status: 200, body: JSON.stringify({ messages: [{ a: 1 }] }) };
    expect(await relay.poll('session_1')).toEqual([{ a: 1 }]);
    expect(calls.map(call => call.url)).toEqual(['https://relay.example/boxes/alpha-box/messages', 'https://relay.example/boxes/alpha-box/messages?sessionId=session_1']);
    expect(calls.every(call => call.headers?.authorization === 'Bearer secret-capability' && !call.url.includes('secret'))).toBe(true);
    reply = { status: 403, body: '{}' };
    await expect(relay.poll()).rejects.toThrow(/refused/);
    await expect(relay.publish({} as never)).rejects.toThrow(BoxRelayError);
    reply = { status: 200, body: JSON.stringify({ messages: 'nope' }) };
    await expect(relay.poll()).rejects.toThrow(/does not understand/);
    await expect(relay.poll('bad id?')).rejects.toThrow(/session id/);
    expect(() => createHttpBoxRelay({ origin: 'https://relay.example/path', boxId: 'a', credential: async () => '', http: calls as never })).toThrow(/address/);
  });
});

describe('box routing from instance metadata', () => {
  const values: Record<string, string> = {
    'keysentry-box-id': 'alpha-box', 'keysentry-relay-origin': 'https://relay.example', 'keysentry-enroll-device-key': device,
  };
  it('reads the three attributes and validates each', async () => {
    const route = await readBoxRoute(async name => values[name]!);
    expect(route).toMatchObject({ boxId: 'alpha-box', relayOrigin: 'https://relay.example' });
    expect(route.enrollmentDeviceKey.toString('base64')).toBe(device);
    await expect(readBoxRoute(async name => ({ ...values, 'keysentry-relay-origin': 'http://relay.example' })[name]!)).rejects.toThrow(/relay address/);
    await expect(readBoxRoute(async name => ({ ...values, 'keysentry-box-id': '../x' })[name]!)).rejects.toThrow(/box id/);
    await expect(readBoxRoute(async name => ({ ...values, 'keysentry-enroll-device-key': 'AAAA' })[name]!)).rejects.toThrow(/device key/);
  });

  it('asks the metadata server with its required header and only for known attributes', async () => {
    const asked: unknown[] = [];
    const fake = (flavor: string | undefined) => ((options: unknown, callback: (response: IncomingMessage) => void) => {
      asked.push(options);
      const request = new EventEmitter() as ClientRequest;
      request.end = (() => {
        const response = new EventEmitter() as IncomingMessage;
        Object.assign(response, { statusCode: 200, headers: flavor ? { 'metadata-flavor': flavor } : {} });
        callback(response); response.emit('data', Buffer.from('alpha-box\n')); response.emit('end');
        return request;
      }) as never;
      return request;
    }) as never;
    expect(await readMetadataAttribute('keysentry-box-id', { request: fake('Google') })).toBe('alpha-box');
    expect(asked[0]).toMatchObject({ host: 'metadata.google.internal', path: '/computeMetadata/v1/instance/attributes/keysentry-box-id', headers: { 'Metadata-Flavor': 'Google' } });
    await expect(readMetadataAttribute('keysentry-box-id', { request: fake(undefined) })).rejects.toThrow(/metadata/);
    await expect(readMetadataAttribute('tee-env-SECRET', { request: fake('Google') })).rejects.toThrow(/Unknown/);
  });

  it('reuses the relay credential until shortly before the token expires', async () => {
    let clock = 1_000_000_000_000, minted = 0;
    const token = (exp: number) => `${Buffer.from('{}').toString('base64url')}.${Buffer.from(JSON.stringify({ exp })).toString('base64url')}.sig`;
    const credential = relayCredential({ async token() { minted++; return token(Math.floor(clock / 1000) + 3600); }, async defaultToken() { return ''; } },
      'https://relay.example', () => clock);
    await credential(); await credential();
    expect(minted).toBe(1);
    clock += 31 * 60_000;
    await credential();
    expect(minted).toBe(2);
  });
});

describe('Dockerfile.box', () => {
  it('pins amd64 and the Dockerfile digests, runs as non-root without a shell, and sets the launch policy', async () => {
    const box = await readFile('Dockerfile.box', 'utf8'), main = await readFile('Dockerfile', 'utf8');
    const froms = (text: string) => [...text.matchAll(/^FROM\s+(?:--platform=(\S+)\s+)?(\S+)/gm)].map(match => ({ platform: match[1], image: match[2] }));
    expect(froms(box).map(from => from.platform)).toEqual(['linux/amd64', 'linux/amd64']);
    expect(froms(box).map(from => from.image)).toEqual(froms(main).map(from => from.image));
    expect(froms(box).every(from => /@sha256:[a-f0-9]{64}$/.test(from.image!))).toBe(true);
    expect(box).toContain('"tee.launch_policy.allow_cmd_override"="false"');
    expect(box).toContain('"tee.launch_policy.log_redirect"="debugonly"');
    expect(box).toContain('"tee.launch_policy.monitoring_memory_allow"="never"');
    const instructions = box.split(/\r?\n/).filter(line => !line.trim().startsWith('#')).join('\n');
    expect(instructions).not.toMatch(/allow_env_override/);
    expect(box).toMatch(/^USER 65532$/m);
    expect(box).toMatch(/^ENTRYPOINT \["\/nodejs\/bin\/node", "\/app\/keysentry\.mjs", "box", "agent"\]$/m);
    const runtime = box.slice(box.lastIndexOf('\nFROM '));
    expect(runtime).not.toMatch(/^(?:RUN|SHELL)\b/m);
    expect(runtime).toContain('gcr.io/distroless/nodejs24');
    expect(runtime).toMatch(/^ENV KEYSENTRY_VAULT=encrypted-file NODE_ENV=production$/m);
    expect(runtime).not.toMatch(/^ENV\b.*\b\w*(?:_KEY|TOKEN|SECRET|PASSPHRASE)\w*=/m);
  });
});
