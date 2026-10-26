import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { createHash } from 'node:crypto';
import { renderBlastRadius, renderRunbook } from '../core/index.js';
import { humanizeServices } from '../cli/display.js';
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
    revokeUnconfirmed?: boolean;
    acceptUnplannedSealed?: boolean;
    allowGenerate?: boolean;
    verifyRetries?: number;
    reveal?: (info: { clusterId: string; provider: ProviderId; hint: string | null; reason: string }, value: string) => Promise<boolean>;
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
  confirm: z.string().optional().describe('Legacy field; this never authorizes execution.'),
  planId: z.string().regex(/^plan-\d{14}-[a-f0-9]{4}$/).optional().describe('Plan ID returned by an earlier rotate dry run in this MCP session.'),
  planHash: z.string().regex(/^[a-f0-9]{64}$/).optional().describe('Exact SHA-256 plan hash returned by that dry run.'),
  revoke: z.string().refine((value) => ['after-deploy', 'immediately', 'never'].includes(value), 'Unsupported revocation policy')
    .transform((value) => value as 'after-deploy' | 'immediately' | 'never').optional(),
  redeploy: z.boolean().optional(),
  revokeUnconfirmed: z.boolean().optional(),
  acceptUnplannedSealed: z.boolean().optional(),
  allowGenerate: z.boolean().optional(),
});

interface ReviewedOptions {
  revoke: 'after-deploy' | 'never';
  redeploy: true;
  revokeUnconfirmed: false;
  acceptUnplannedSealed: false;
  allowGenerate: boolean;
  verifyRetries: 4;
}
interface ReviewedPlan {
  plan: RotationPlan;
  options: ReviewedOptions;
  hash: string;
}

class ExecutionRefused extends Error {
  constructor(readonly details: { executionRefused: true; confirmationRequired: true; planId?: string; guidance: string }) {
    super('MCP execution refused.');
  }
}

function refuse(reason: string, planId?: string): never {
  throw new ExecutionRefused({
    executionRefused: true, confirmationRequired: true, ...(planId ? { planId } : {}),
    guidance: `${reason} Ask the human to run keysentry rotate --plan ${planId ?? '<id>'} --execute in a terminal. Guided replacements require the interactive CLI.`,
  });
}

function planHash(plan: RotationPlan, options: ReviewedOptions): string {
  // Steps contain every consumer and reference relationship. Include the service
  // list and all normalized MCP execution options, excluding incidental ID/time.
  return createHash('sha256').update(JSON.stringify({ steps: plan.steps, services: plan.services, options })).digest('hex');
}

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
  // Execution is bound to an immutable snapshot from this session's successful
  // dry run. A plan on disk alone is never an MCP execution authorization.
  const reviewedPlans = new Map<string, ReviewedPlan>();
  const guarded = (handler: (args: unknown) => Promise<unknown>) => async (args: unknown = {}): Promise<CallToolResult> => {
    try {
      return result(runtime, await handler(args));
    } catch (error) {
      if (error instanceof ExecutionRefused) return { ...result(runtime, error.details), isError: true };
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
      return { report: humanizeServices(renderBlastRadius(inventory), inventory.services), clusters: inventory.clusters.length, findings: inventory.findings.length };
    }),
    plan_rotation: guarded(async (args) => {
      const options = planSchema.parse(args);
      const plan = await runtime.plan(options);
      const inventory = await runtime.inventory();
      return { plan, runbook: humanizeServices(renderRunbook(plan, inventory), [...inventory.services, ...plan.services]) };
    }),
    rotate: guarded(async (args) => {
      const { execute, planId, planHash: suppliedHash, revoke, redeploy,
        revokeUnconfirmed, acceptUnplannedSealed, allowGenerate, confirm: _confirm, ...filters } = rotateSchema.parse(args);
      let reviewed: ReviewedPlan;
      if (execute) {
        if (process.env.KEYSENTRY_MCP_ALLOW_EXECUTE !== '1') {
          // Save a terminal-reviewable plan when a caller jumped straight to
          // execute, but never invoke the rotation engine for this refusal.
          const id = planId ?? (await runtime.plan(filters)).id;
          refuse('MCP execution is disabled by default (KEYSENTRY_MCP_ALLOW_EXECUTE must be 1).', id);
        }
        if (!planId || !suppliedHash) refuse('Run rotate with execute:false first; execution requires its planId and planHash.', planId);
        const saved = reviewedPlans.get(planId);
        if (!saved || saved.hash !== suppliedHash || saved.hash !== planHash(saved.plan, saved.options)) {
          refuse('The reviewed plan is missing, already used, or its hash does not match. Run a fresh dry run.', planId);
        }
        if (Object.keys(filters).length) refuse('Execution cannot change the reviewed plan selectors. Run a fresh dry run.', planId);
        if (revoke === 'immediately' || redeploy === false || revokeUnconfirmed === true || acceptUnplannedSealed === true) {
          refuse('MCP refuses immediate revocation, disabled redeployment, unconfirmed revocation, and unplanned sealed consumers.', planId);
        }
        if ((revoke !== undefined && revoke !== saved.options.revoke)
          || (allowGenerate !== undefined && allowGenerate !== saved.options.allowGenerate)) {
          refuse('Execution options differ from the reviewed dry run. Run a fresh dry run.', planId);
        }
        if (saved.plan.steps.some(step => step.method === 'atomic-roll' || runtime.providers(step.provider).method === 'atomic-roll')) {
          // A roll invalidates the old token immediately. If host recovery also
          // fails, its sole surviving value needs the CLI's interactive reveal;
          // MCP must never receive that plaintext through its result or logs.
          refuse('Plans containing atomic-roll steps require the interactive CLI recovery path.', planId);
        }
        reviewed = saved;
        // Consume before awaiting execution so concurrent/replayed requests
        // cannot rotate the same reviewed plan twice.
        reviewedPlans.delete(planId);
      } else {
        if (planId || suppliedHash) refuse('Use selectors to create a fresh dry run; planId and planHash identify execution requests.', planId);
        if (revoke === 'immediately' || redeploy === false || revokeUnconfirmed === true || acceptUnplannedSealed === true) {
          refuse('MCP refuses immediate revocation, disabled redeployment, unconfirmed revocation, and unplanned sealed consumers.');
        }
        const plan = structuredClone(await runtime.plan(filters));
        const options: ReviewedOptions = {
          revoke: revoke ?? 'after-deploy', redeploy: true, revokeUnconfirmed: false,
          acceptUnplannedSealed: false, allowGenerate: allowGenerate ?? true, verifyRetries: 4,
        };
        reviewed = { plan, options, hash: planHash(plan, options) };
      }
      const plan = structuredClone(reviewed.plan);
      const instructions: GuidedPrompt[] = plan.steps
        .filter((step) => step.method === 'guided' || runtime.providers(step.provider).method === 'guided'
          || ((step.method === 'auto' || step.method === 'atomic-roll') && step.consumers.every((consumer) => consumer.sealed)))
        .map((step) => ({
          clusterId: step.clusterId, provider: step.provider, hint: step.hint,
          guidance: runtime.providers(step.provider).guidance(), consumers: step.consumers,
        }));
      const report = await runtime.rotate(plan, {
        ...reviewed.options, execute,
        // Recovery values must never cross a tool result or a runtime's default
        // terminal reveal callback. The interactive CLI owns that recovery path.
        reveal: undefined,
        prompt: async (prompt) => {
          if (!instructions.some((item) => item.clusterId === prompt.clusterId)) instructions.push(prompt);
          return null;
        },
      });
      if (!execute) reviewedPlans.set(reviewed.plan.id, reviewed);
      return {
        planId: reviewed.plan.id, planHash: reviewed.hash, report, guidedInstructions: instructions,
        confirmationRequired: !execute,
        guidance: `Show this dry run to the human and ask them to run keysentry rotate --plan ${reviewed.plan.id} --execute in a terminal. MCP execution is disabled unless KEYSENTRY_MCP_ALLOW_EXECUTE=1; opt-in execution requires this session's planId and planHash and the exact reviewed options. Guided replacements are skipped over MCP. Verify activation and inspect the journal.`,
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
    instructions: 'Local-first secret response. Scan, inspect blast_radius, plan_rotation, and dry-run rotate; show the human the result and ask them to run keysentry rotate --plan <id> --execute in a terminal. MCP execution is disabled by default. An operator can opt in with KEYSENTRY_MCP_ALLOW_EXECUTE=1; execution then requires the exact planId and planHash from a previous dry run in this session. Plans containing atomic-roll steps always require the interactive CLI recovery path. Fixed confirmation strings do not authorize execution. Tool results contain fingerprints and hints, never secret values.',
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
    description: 'Dry-run rotation and return planId/planHash for the reviewed snapshot. Ask the human to execute it in a terminal. MCP execution is disabled unless KEYSENTRY_MCP_ALLOW_EXECUTE=1 and requires that prior dry run\'s exact planId/hash and options. Unsafe revocation overrides and atomic-roll execution are refused. Guided steps return instructions and are skipped.',
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
