// fix-verify EA H1 leftover: a deployed watcher whose carried proxy cannot be reached reports itself unhealthy on
// /healthz (with a fixed reason) after repeated failed connections to the proxy, and healthy again once it connects.
import { createServer, type AddressInfo } from 'node:net';
import { describe, expect, it } from 'vitest';
import { configSchema } from '../../src/cli/config.js';
import { setupNetwork } from '../../src/cli/network-setup.js';
import { WATCHER_NETWORK_PROBLEM, WATCHER_PROXY_UNREACHABLE, watcherNetworkHealth } from '../../src/cli/watcher-setup.js';
import { PROXY_FAILURES_UNHEALTHY } from '../../src/net/transport.js';

async function unusedPort(): Promise<number> {
  const server = createServer();
  const port = await new Promise<number>(resolve => server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));
  await new Promise<void>(resolve => server.close(() => resolve()));
  return port;
}

describe('watcher health with a carried proxy', () => {
  it('turns unhealthy with a fixed reason after repeated failed connections to the proxy', async () => {
    const port = await unusedPort();
    const network = await setupNetwork({ settings: configSchema.parse({ network: { proxy: `http://127.0.0.1:${port}` } }).network, cwd: process.cwd(), env: {}, policy: null });
    expect(network.problem).toBeNull();
    expect(network.proxyUnreachable).toBeTypeOf('function');
    const health = () => watcherNetworkHealth({ problem: null, proxyUnreachable: network.proxyUnreachable });
    for (let attempt = 0; attempt < PROXY_FAILURES_UNHEALTHY; attempt += 1) {
      expect(health()).toBeNull();
      await expect(network.transport.request({ method: 'GET', url: 'https://feeds.example.test/' })).rejects.toMatchObject({ code: 'PROXY_UNREACHABLE' });
    }
    expect(health()).toEqual({ code: 'network', reason: WATCHER_PROXY_UNREACHABLE });
    expect(WATCHER_PROXY_UNREACHABLE).not.toContain(String(port));
  });

  it('keeps the refusing-transport reason first, and has no proxy check without a proxy', async () => {
    expect(watcherNetworkHealth({ problem: 'The proxy URL cannot be used.', proxyUnreachable: () => true })).toEqual({ code: 'network', reason: WATCHER_NETWORK_PROBLEM });
    const direct = await setupNetwork({ settings: configSchema.parse({}).network, cwd: process.cwd(), env: {}, policy: null });
    expect(direct.proxyUnreachable).toBeUndefined();
    expect(watcherNetworkHealth({ problem: null, ...(direct.proxyUnreachable ? { proxyUnreachable: direct.proxyUnreachable } : {}) })).toBeNull();
  });
});
