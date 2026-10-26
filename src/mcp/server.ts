import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { renderBlastRadius, renderRunbook } from '../core/index.js';
import type {
  GuidedPrompt, HostId, Inventory, PendingAction, ProviderAdapter, ProviderId,
  Redactor, RiskTier, RotationPlan, RotationReport,
} from '../types.js';

export interface McpPlanFilters {
  tiers?: RiskTier[];
  clusterIds?: string[];
  hosts?: HostId[];
  serviceKeys?: string[];
}

/** A structural seam shared with the CLI; it never exposes credentials or raw variables. */
export interface McpRuntime {
  scan(): Promise<Inventory>;
  inventory(): Promise<Inventory>;
  plan(filters?: McpPlanFilters): Promise<RotationPlan>;
  rotate(plan: RotationPlan, opts: {
    execute?: boolean;
    prompt?: (prompt: GuidedPrompt) => Promise<string | null>;
    revoke?: 'after-deploy' | 'immediately' | 'never';
    redeploy?: boolean;
  }): Promise<RotationReport>;
  monitorStatus(): Promise<unknown>;
  pendingActions(): Promise<PendingAction[]>;
  providers(id: ProviderId): ProviderAdapter;
  redactor: Redactor;
}

const tiers: readonly string[] = ['crypto', 'cloud', 'database', 'payments', 'ai', 'comms', 'app', 'unknown'];
const hosts: readonly string[] = ['railway', 'vercel', 'render', 'fly', 'github-actions', 'dotenv'];
// Refine instead of enum so validation errors cannot echo an arbitrary supplied value.
const tier = z.string().refine((value) => tiers.includes(value), 'Unsupported risk tier').transform((value) => value as RiskTier);
const host = z.string().refine((value) => hosts.includes(value), 'Unsupported host').transform((value) => value as HostId);
const filters = {
  tiers: z.array(tier).optional().describe('Risk tiers to include, in their normal rotation order.'),
  clusterIds: z.array(z.string()).optional().describe('Inventory cluster IDs; every consumer of each selected key is retained.'),
  hosts: z.array(host).optional(),
  serviceKeys: z.array(z.string()).optional(),
};
const emptySchema = z.object({}).strict();
const planSchema = z.object(filters).strict();
const rotateSchema = planSchema.extend({
  execute: z.boolean().optional().default(false),
  confirm: z.string().optional().describe('Must be exactly ROTATE, with explicit human approval, to execute.'),
  revoke: z.string().refine((value) => ['after-deploy', 'immediately', 'never'].includes(value), 'Unsupported revocation policy')
    .transform((value) => value as 'after-deploy' | 'immediately' | 'never').optional(),
  redeploy: z.boolean().optional(),
});

/** Sanitize strings before serialization, including metadata and multiline registered values. */
function result(runtime: McpRuntime, value: unknown): CallToolResult {
  const clean = (item: unknown): unknown => {
    if (typeof item === 'string') return runtime.redactor.redact(item);
    if (Array.isArray(item)) return item.map(clean);
    if (item !== null && typeof item === 'object') {
      return Object.fromEntries(Object.entries(item).map(([key, child]) => [runtime.redactor.redact(key), clean(child)]));
    }
    return item;
  };
  const sanitized = clean(value);
  return {
    // Strings and keys were already redacted. Redacting JSON syntax could corrupt
    // the document when an opaque registered value happens to match punctuation.
    content: [{ type: 'text', text: JSON.stringify(sanitized, null, 2) }],
    structuredContent: sanitized as Record<string, unknown>,
  };
}

/** Handlers are exported for embedding and testing without opening stdio. */
export function createToolHandlers(runtime: McpRuntime) {
  const guarded = (handler: (args: unknown) => Promise<unknown>) => async (args: unknown = {}): Promise<CallToolResult> => {
    try {
      return result(runtime, await handler(args));
    } catch (error) {
      const message = error instanceof z.ZodError
        ? 'Invalid tool arguments. Check the tool input schema.'
        : 'keysentry tool failed. Check the local configuration and redacted diagnostics.';
      return { content: [{ type: 'text', text: runtime.redactor.redact(message) }], isError: true };
    }
  };
  return {
    scan: guarded(async (args) => {
      emptySchema.parse(args);
      return { inventory: await runtime.scan() };
    }),
    blast_radius: guarded(async (args) => {
      emptySchema.parse(args);
      const inventory = await runtime.inventory();
      return { report: renderBlastRadius(inventory), clusters: inventory.clusters.length, findings: inventory.findings.length };
    }),
    plan_rotation: guarded(async (args) => {
      const options = planSchema.parse(args);
      const plan = await runtime.plan(options);
      return { plan, runbook: renderRunbook(plan, await runtime.inventory()) };
    }),
    rotate: guarded(async (args) => {
      const { execute, confirm, revoke, redeploy, ...options } = rotateSchema.parse(args);
      const plan = await runtime.plan(options);
      const instructions: GuidedPrompt[] = plan.steps
        .filter((step) => step.method === 'guided' || runtime.providers(step.provider).method === 'guided'
          || ((step.method === 'auto' || step.method === 'atomic-roll') && step.consumers.every((consumer) => consumer.sealed)))
        .map((step) => ({
          clusterId: step.clusterId, provider: step.provider, hint: step.hint,
          guidance: runtime.providers(step.provider).guidance(), consumers: step.consumers,
        }));
      const report = await runtime.rotate(plan, {
        execute: execute === true && confirm === 'ROTATE', revoke, redeploy,
        prompt: async (prompt) => {
          if (!instructions.some((item) => item.clusterId === prompt.clusterId)) instructions.push(prompt);
          return null;
        },
      });
      return {
        report, guidedInstructions: instructions,
        confirmationRequired: !(execute === true && confirm === 'ROTATE'),
        guidance: 'Show the dry run to the human before executing. Guided replacements require the interactive CLI; MCP skips them. Verify deployments and inspect the journal after execution.',
      };
    }),
    monitor_status: guarded(async (args) => {
      emptySchema.parse(args);
      return { status: await runtime.monitorStatus() };
    }),
    list_pending_actions: guarded(async (args) => {
      emptySchema.parse(args);
      return { actions: await runtime.pendingActions() };
    }),
  };
}

export function createMcpServer(runtime: McpRuntime): McpServer {
  const server = new McpServer({ name: 'keysentry', version: '0.1.0' }, {
    instructions: 'Local-first secret response. Scan, inspect blast_radius, plan_rotation, and dry-run rotate; show the human the result. Execute only after explicit human approval with execute:true and confirm:"ROTATE". Tool results contain fingerprints and hints, never secret values.',
  });
  const handlers = createToolHandlers(runtime);
  server.registerTool('scan', {
    description: 'Scan enabled hosts and save a fingerprint-only inventory. No host or provider writes.',
    inputSchema: {}, annotations: { readOnlyHint: true },
  }, handlers.scan);
  server.registerTool('blast_radius', {
    description: 'Report every consumer of each secret, duplicate clusters, risk tiers, sealed values and scan errors.',
    inputSchema: {}, annotations: { readOnlyHint: true },
  }, handlers.blast_radius);
  server.registerTool('plan_rotation', {
    description: 'Build an ordered rotation plan and runbook, retaining all consumers of every selected secret.',
    inputSchema: filters, annotations: { readOnlyHint: true },
  }, handlers.plan_rotation);
  server.registerTool('rotate', {
    description: 'Dry-run rotation by default. Writes require both execute:true and confirm:"ROTATE", after explicit human confirmation. Guided steps return instructions and are skipped.',
    inputSchema: rotateSchema.shape, annotations: { destructiveHint: true },
  }, handlers.rotate);
  server.registerTool('monitor_status', {
    description: 'Read monitoring metadata and configured policy without polling or executing actions.',
    inputSchema: {}, annotations: { readOnlyHint: true },
  }, handlers.monitor_status);
  server.registerTool('list_pending_actions', {
    description: 'List monitoring actions awaiting human approval.',
    inputSchema: {}, annotations: { readOnlyHint: true },
  }, handlers.list_pending_actions);
  // The SDK's default unknown-tool/validation errors echo supplied names and values.
  // Keep its discovery schemas, but route every tools/call through our fixed-error boundary.
  server.server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    if (!Object.hasOwn(handlers, name)) {
      return { content: [{ type: 'text', text: runtime.redactor.redact('Unknown keysentry tool.') }], isError: true };
    }
    return handlers[name as keyof typeof handlers](request.params.arguments ?? {});
  });
  return server;
}

export async function startMcpServer(runtime: McpRuntime): Promise<McpServer> {
  const server = createMcpServer(runtime);
  await server.connect(new StdioServerTransport());
  return server;
}
