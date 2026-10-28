import { request } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { relayCredential } from '../../../src/box/agent/main.js';
import { createHttpBoxRelay } from '../../../src/box/agent/relay.js';
import { createFetchHttp } from '../../../src/http.js';
import { generateDeviceKey } from '../../../src/security/index.js';
import { startLocalBox, type LocalBox, type LocalBoxRuntime } from '../src/local-box.js';

const open: LocalBox[] = [];
afterEach(async () => { await Promise.all(open.splice(0).map(local => local.close().catch(() => undefined))); });

function status(url: string, headers: Record<string, string> = {}): Promise<number | 'closed'> {
  return new Promise(resolve => {
    const req = request(url, { headers, agent: false }, res => { res.resume(); res.on('end', () => resolve(res.statusCode!)); });
    req.on('error', () => resolve('closed'));
    req.end();
  });
}

describe('local box', () => {
  it('lets the box use the production relay credential: its attestation token for the relay origin', async () => {
    let runtime: LocalBoxRuntime | undefined;
    const device = generateDeviceKey();
    const local = await startLocalBox({ boxId: 'unit-box', enrollmentDeviceKey: device.publicKeyDer,
      bootBox: async rt => { runtime = rt; return { async stop() {} }; } });
    open.push(local);
    const relay = createHttpBoxRelay({ http: createFetchHttp(), origin: local.origin, boxId: 'unit-box', credential: relayCredential(runtime!.tee as never, local.origin) });
    expect(await relay.poll()).toEqual([]);
    const cli = createHttpBoxRelay({ http: createFetchHttp(), origin: local.origin, boxId: 'unit-box', credential: async () => local.cliToken });
    expect(await cli.poll()).toEqual([]);
    const otherBox = local.emulator.mintToken({ audience: local.origin, nonces: [], instanceName: 'other-box' });
    expect(await status(`${local.origin}/boxes/other-box/messages`, { authorization: `Bearer ${otherBox}` })).toBe(401);
    const wrongAudience = await runtime!.tee.token({ audience: 'https://elsewhere.example', nonces: [] });
    expect(await status(`${local.origin}/boxes/unit-box/messages`, { authorization: `Bearer ${wrongAudience}` })).toBe(401);
  });

  it('L3: close() releases the control plane and emulator even when the box fails to stop', async () => {
    const local = await startLocalBox({ boxId: 'unit-box', bootBox: async () => ({ async stop() { throw new Error('stop failed'); } }) });
    await expect(local.close()).rejects.toThrow('stop failed');
    expect(await status(`${local.origin}/healthz`)).toBe('closed');
    expect(await status(`${local.emulator.baseUrl}/health`)).toBe('closed');
  });
});
