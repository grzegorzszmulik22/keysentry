import { describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { buildInventory, buildPlan, createRedactor } from '../../src/core/index.js';
import { createMcpServer, createToolHandlers, type McpRuntime } from '../../src/mcp/server.js';
import type { RotationReport } from '../../src/types.js';
import { FakeHost, FakeProvider } from '../helpers/fakes.js';

function fixture() {
  const provider = new FakeProvider('openai', 'auto', 'sk-proj-');
  const oldKey = provider.issue();
  const host = new FakeHost('railway');
  const service = host.addService('api', { OPENAI_API_KEY: oldKey.value });
  const inventory = buildInventory([{
    host: host.id,
    services: [{ service, vars: [{ name: 'OPENAI_API_KEY', value: oldKey.value, sealed: false }] }],
  }], Buffer.alloc(32, 7));
  const redactor = createRedactor();
  redactor.register(oldKey.value);
  const runtime: McpRuntime = {
    scan: vi.fn(async () => inventory),
    inventory: vi.fn(async () => inventory),
    plan: vi.fn(async (filters) => buildPlan(inventory, filters)),
    rotate: vi.fn(async (plan, opts) => ({
      planId: plan.id, dryRun: !opts.execute, startedAt: '2026-01-01T00:00:00.000Z',
      finishedAt: '2026-01-01T00:00:00.000Z', steps: [], deployments: [], diff: [],
    } satisfies RotationReport)),
    monitorStatus: vi.fn(async () => ({ canaries: 0, autoExecute: false })),
    pendingActions: vi.fn(async () => []),
    providers: () => provider,
    redactor,
  };
  return { runtime, inventory, provider, oldKey };
}

describe('stdio MCP server tools', () => {
  it('lists the six tools and calls blast_radius over the SDK in-memory transport', async () => {
    const { runtime, oldKey } = fixture();
    const server = createMcpServer(runtime);
    const client = new Client({ name: 'keysentry-test', version: '1.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const listed = await client.listTools();
      expect(listed.tools.map((tool) => tool.name).sort()).toEqual([
        'blast_radius', 'list_pending_actions', 'monitor_status', 'plan_rotation', 'rotate', 'scan',
      ]);
      const result = await client.callTool({ name: 'blast_radius', arguments: {} });
      expect(result.isError).not.toBe(true);
      expect(JSON.stringify(result)).toContain('OPENAI_API_KEY');
      expect(JSON.stringify(result)).toContain('railway');
      expect(JSON.stringify(result)).not.toContain(oldKey.value);
      const unknown = await client.callTool({ name: oldKey.value, arguments: {} });
      expect(unknown.isError).toBe(true);
      expect(JSON.stringify(unknown)).not.toContain(oldKey.value);
      const invalid = await client.callTool({ name: 'rotate', arguments: { [oldKey.value]: oldKey.value } });
      expect(invalid.isError).toBe(true);
      expect(JSON.stringify(invalid)).not.toContain(oldKey.value);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it.each([
    [{}, false], [{ execute: true }, false], [{ confirm: 'ROTATE' }, false],
    [{ execute: true, confirm: 'rotate' }, false], [{ execute: true, confirm: 'ROTATE' }, true],
  ])('requires both explicit execution guards: %j', async (args, execute) => {
    const { runtime } = fixture();
    const result = await createToolHandlers(runtime).rotate(args);
    expect(result.isError).not.toBe(true);
    expect(runtime.rotate).toHaveBeenCalledTimes(1);
    expect(vi.mocked(runtime.rotate).mock.calls[0]?.[1].execute).toBe(execute);
  });

  it('returns guided instructions while its execution prompt always skips', async () => {
    const { runtime, inventory } = fixture();
    inventory.clusters[0]!.method = 'guided';
    inventory.clusters[0]!.provider = 'anthropic';
    runtime.rotate = vi.fn<McpRuntime['rotate']>(async (plan, opts) => {
      expect(await opts.prompt!({
        clusterId: plan.steps[0]!.clusterId, provider: 'anthropic', hint: null,
        guidance: { url: 'https://example.invalid/keys', steps: ['Create a replacement key'] }, consumers: [],
      })).toBeNull();
      return {
        planId: plan.id, dryRun: !opts.execute, startedAt: '', finishedAt: '',
        steps: [{ clusterId: plan.steps[0]!.clusterId, status: 'skipped', warnings: [] }], deployments: [], diff: [],
      };
    });
    const result = await createToolHandlers(runtime).rotate({ execute: true, confirm: 'ROTATE' });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      guidedInstructions: [{ provider: 'anthropic', guidance: { steps: ['Create a new key', 'Paste it'] } }],
      report: { steps: [{ status: 'skipped' }] },
    });
  });

  it('sanitizes all output strings, including multiline values and structuredContent', async () => {
    const { runtime, oldKey } = fixture();
    const multiline = 'opaque\nprivate\ncredential';
    runtime.redactor.register(multiline);
    runtime.monitorStatus = async () => ({ diagnostic: oldKey.value, nested: [multiline] });
    const result = await createToolHandlers(runtime).monitor_status({});
    expect(JSON.stringify(result)).not.toContain(oldKey.value);
    expect(JSON.stringify(result)).not.toContain('opaque');
    expect(JSON.stringify(result)).toContain('redacted');
  });

  it.each(['": ', '": "st'])('preserves JSON syntax when a registered value contains punctuation: %j', async (secret) => {
    const { runtime } = fixture();
    // The structural seam permits redactors that also protect short registered values.
    // Core ignores values shorter than six characters, so use such a redactor for that case.
    if (secret.length < 6) {
      const registered = new Set<string>();
      runtime.redactor = {
        register: (value) => { registered.add(value); },
        redact: (value) => {
          for (const item of registered) value = value.split(item).join('«redacted»');
          return value;
        },
      };
    }
    runtime.redactor.register(secret);
    runtime.monitorStatus = async () => ({ status: 'stable', diagnostic: `prefix${secret}suffix` });
    const result = await createToolHandlers(runtime).monitor_status({});
    const content = result.content[0]!;
    expect(content.type).toBe('text');
    if (content.type !== 'text') throw new Error('Expected text result');
    expect(() => JSON.parse(content.text)).not.toThrow();
    expect(JSON.parse(content.text)).toEqual(result.structuredContent);
    expect(result.structuredContent).toMatchObject({ status: { diagnostic: 'prefix«redacted»suffix' } });
  });

  it('does not describe sealed generated secrets as manual steps', async () => {
    const { runtime, inventory, provider } = fixture();
    inventory.clusters[0]!.method = 'generate';
    inventory.clusters[0]!.provider = 'app-secret';
    inventory.clusters[0]!.consumers[0]!.sealed = true;
    runtime.providers = () => ({
      id: 'app-secret', method: 'generate', verify: provider.verify.bind(provider), guidance: provider.guidance.bind(provider),
    });
    const result = await createToolHandlers(runtime).rotate({});
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({ guidedInstructions: [] });
  });

  it('does not return arbitrary adapter exception messages or rejected input values', async () => {
    const { runtime, oldKey } = fixture();
    runtime.scan = async () => { throw new Error(oldKey.value); };
    const handlers = createToolHandlers(runtime);
    const failed = await handlers.scan({});
    const invalid = await handlers.plan_rotation({ tiers: [oldKey.value] });
    expect(failed.isError).toBe(true);
    expect(invalid.isError).toBe(true);
    expect(JSON.stringify([failed, invalid])).not.toContain(oldKey.value);
  });
});
