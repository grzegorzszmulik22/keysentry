import { randomUUID } from 'node:crypto';
import type { HostAdapter, ServiceRef } from '../types.js';
import { serviceKey } from '../core/service-key.js';
import { createCanaryKey, openrouterProvider } from '../providers/openrouter.js';
import { findProvider, isSafeKeyRef, now, type DetectorContext } from './context.js';
import type { Canary, MonitorState } from './state.js';

export interface CreateCanaryOptions {
  provider: 'openrouter';
  host: HostAdapter;
  service: ServiceRef;
  varName?: string;
  /** Host and provider writes require explicit execution. */
  dryRun?: boolean;
}

/** The decoy value is only passed to the host; returned metadata never contains it. */
export async function createCanary(options: CreateCanaryOptions, ctx: DetectorContext): Promise<Canary | null> {
  const varName = options.varName ?? 'OPENROUTER_API_KEY_FALLBACK';
  if (options.provider !== 'openrouter') throw new Error('Unsupported canary provider.');
  if (options.host.id !== options.service.host) throw new Error('Canary service does not belong to the requested host.');
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(varName)) throw new Error('Invalid canary variable name.');
  if (options.dryRun !== false) return null;

  let exists: boolean;
  try {
    exists = (await options.host.readVariables(options.service)).some(variable => variable.name === varName);
  } catch {
    throw new Error('Unable to inspect canary destination.');
  }
  if (exists || ctx.state.canaries.some(canary => serviceKey(canary.service) === serviceKey(options.service) && canary.varName === varName)) {
    throw new Error('Canary destination variable already exists.');
  }

  const id = `canary-${randomUUID()}`;
  let created: { value: string; keyRef: string };
  try {
    created = await createCanaryKey(ctx.providerCtx, id);
  } catch {
    throw new Error('Unable to create canary key.');
  }
  if (!isSafeKeyRef(created.keyRef, ctx, created.value)) throw new Error('Canary provider returned an unsafe key reference.');
  try {
    await options.host.writeVariables(options.service, { [varName]: created.value }, { skipDeploy: true });
  } catch {
    // An orphaned decoy must not remain usable after a failed staging operation.
    const provider = findProvider(ctx, options.provider) ?? openrouterProvider;
    try {
      if (provider.revoke) await provider.revoke(created.keyRef, ctx.providerCtx);
      else await openrouterProvider.revoke!(created.keyRef, ctx.providerCtx);
    } catch {
      ctx.log.warn('Unable to revoke unplanted canary; inspect the provider key list.');
    }
    throw new Error('Unable to plant canary.');
  }

  const canary: Canary = {
    id, provider: options.provider, keyRef: created.keyRef,
    service: { ...options.service }, varName, createdAt: now(ctx).toISOString(),
  };
  ctx.state.canaries.push(canary);
  return structuredClone(canary);
}

export function listCanaries(state: MonitorState): Canary[] {
  return structuredClone(state.canaries);
}

/** HostAdapter has no variable-delete API; removal revokes the key and leaves an inert variable. */
export async function removeCanary(id: string, ctx: DetectorContext, options: { dryRun?: boolean } = {}): Promise<void> {
  const canary = ctx.state.canaries.find(candidate => candidate.id === id);
  if (!canary) throw new Error('Unknown canary.');
  if (options.dryRun !== false) return;
  const provider = findProvider(ctx, canary.provider) ?? openrouterProvider;
  if (!provider.revoke) throw new Error('Canary provider cannot revoke keys.');
  try {
    await provider.revoke(canary.keyRef, ctx.providerCtx);
  } catch {
    throw new Error('Unable to revoke canary key.');
  }
  ctx.state.canaries = ctx.state.canaries.filter(candidate => candidate.id !== id);
}
