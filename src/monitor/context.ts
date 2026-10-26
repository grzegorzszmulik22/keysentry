import { fingerprint } from '../core/fingerprint.js';
import { createRedactor } from '../core/redact.js';
import type { Cluster, HostAdapter, HostId, Inventory, Logger, ProviderAdapter, ProviderContext, ProviderId, RawVariable } from '../types.js';
import type { MonitorState } from './state.js';

export type AdapterCollection<T extends { readonly id: string }> = readonly T[] | ReadonlyMap<string, T> | Partial<Record<string, T>>;
export interface DetectorContext {
  inventory: Inventory;
  hosts: AdapterCollection<HostAdapter>;
  providers: AdapterCollection<ProviderAdapter>;
  providerCtx: ProviderContext;
  state: MonitorState;
  fingerprintKey: Buffer;
  log: Logger;
  clock?: () => Date;
}

export function now(ctx: Pick<DetectorContext, 'clock'>): Date { return ctx.clock?.() ?? new Date(); }

function find<T extends { readonly id: string }>(adapters: AdapterCollection<T>, id: string): T | undefined {
  if (Array.isArray(adapters)) return adapters.find(adapter => adapter.id === id);
  if (adapters instanceof Map) return adapters.get(id);
  return Object.hasOwn(adapters, id) ? (adapters as Partial<Record<string,T>>)[id] : undefined;
}
export function findProvider(ctx: Pick<DetectorContext,'providers'>, id: ProviderId): ProviderAdapter | undefined { return find(ctx.providers,id); }
export function findHost(ctx: Pick<DetectorContext,'hosts'>, id: HostId): HostAdapter | undefined { return find(ctx.hosts,id); }

/** Plaintext is kept solely in RawVariable.value and transient provider context. */
export async function readClusterSecret(cluster: Cluster, ctx: DetectorContext): Promise<{variable:RawVariable;providerCtx:ProviderContext}|null> {
  for (const consumer of cluster.consumers) {
    const host = findHost(ctx,consumer.service.host);
    if (!host) continue;
    try {
      const vars = await host.readVariables(consumer.service);
      const variable = vars.find(v => v.name === consumer.varName && !v.sealed && v.value !== undefined);
      if (!variable?.value) continue;
      if (cluster.fingerprint !== null && fingerprint(variable.value,ctx.fingerprintKey) !== cluster.fingerprint) continue;
      const siblingVars: Record<string,string> = Object.create(null);
      for (const v of vars) if (!v.sealed && v.value !== undefined) siblingVars[v.name] = v.value;
      return {variable,providerCtx:{...ctx.providerCtx,siblingVars}};
    } catch { ctx.log.warn('Unable to read a monitored consumer.'); }
  }
  return null;
}

/** Fail closed if an adapter mistakes a secret for a public provider reference. */
export function isSafeKeyRef(ref: string, ctx: DetectorContext, value?: string): boolean {
  const secrets = [...Object.values(ctx.providerCtx.credentials),...Object.values(ctx.providerCtx.siblingVars ?? {}),value]
    .filter((secret): secret is string => typeof secret === 'string' && secret.length > 0);
  return ref.length > 0 && ref.length <= 2048 && !/[\r\n]/.test(ref)
    && !secrets.some(secret => ref.includes(secret)) && createRedactor().redact(ref) === ref;
}

export async function resolveClusterKeyRef(cluster: Cluster, ctx: DetectorContext): Promise<string|null> {
  const saved = ctx.state.keyRefs[cluster.id];
  if (saved && isSafeKeyRef(saved,ctx)) return saved;
  const provider = findProvider(ctx,cluster.provider);
  if (!provider) return null;
  const secret = await readClusterSecret(cluster,ctx);
  if (!secret?.variable.value) return null;
  let ref: string|null = null;
  if (provider.resolveKeyRef) ref = await provider.resolveKeyRef(secret.variable.value,secret.providerCtx);
  else if (provider.listKeys) {
    const matches = (await provider.listKeys(secret.providerCtx)).filter(key => {
      if (!key.hint) return false;
      const parts = key.hint.split(/\.{2,}|\u2026|\*+/);
      return parts.length === 2 && !!parts[0] && !!parts[1]
        && secret.variable.value!.startsWith(parts[0]) && secret.variable.value!.endsWith(parts[1]);
    });
    if (matches.length === 1) ref = matches[0]!.keyRef;
  }
  if (ref && isSafeKeyRef(ref,{...ctx,providerCtx:secret.providerCtx},secret.variable.value)) { ctx.state.keyRefs[cluster.id] = ref; return ref; }
  return null;
}
