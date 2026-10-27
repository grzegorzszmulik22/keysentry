import { classify } from '../core/index.js';
import type { CrashPoint, Inventory, JournalEntry, ProviderContext, RotationPlan } from '../types.js';
import type { EngineDeps } from './engine.js';

export interface RecoveryInput {
  plan: RotationPlan;
  inventory: Inventory;
  entries: JournalEntry[];
}

// Hooks simulate process death. Preserve even primitive throws by identity; no
// recovery, journal append, or provider cleanup may run after one fires.
const crashes = new Set<unknown>();
export function crash(deps: EngineDeps, point: CrashPoint, detail: { clusterId?: string; serviceKey?: string }): void {
  try { deps.crashHook?.(point, detail); }
  catch (error) { crashes.add(error); throw error; }
}
export function isCrash(error: unknown): boolean { return crashes.has(error); }

/** Register stored values before any metadata from a recovery operation escapes. */
export async function createRecoverySafety(input: RecoveryInput, deps: EngineDeps) {
  const values = new Set<string>();
  const sensitive = new Set<string>();
  const publicRefs = new Set<string>();
  const register = (value: string, secret = true) => {
    if (secret) sensitive.add(value);
    if (value.length > 0) { values.add(value); deps.redactor.register(value); }
  };
  for (const value of Object.values(deps.providerCtx.credentials)) if (value !== undefined) register(value);
  for (const [name, value] of Object.entries(deps.providerCtx.siblingVars ?? {})) if (classify(name, value).isSecret) register(value);
  if (deps.inflight) for (const slot of await deps.inflight.slots(input.plan.id)) {
    const value = await deps.inflight.get(input.plan.id, slot);
    if (value !== null) {
      const publicId = (slot.startsWith('companion:') || slot.startsWith('old-companion:')) && /^(?:AKIA|ASIA)[A-Z0-9]{16}$/.test(value);
      register(value, !publicId);
      if (publicId) publicRefs.add(value);
    }
  }
  function clean(text: string): string {
    for (const value of [...values].sort((a, b) => b.length - a.length)) text = text.split(value).join('«redacted»');
    return deps.redactor.redact(text);
  }
  function sanitize<T>(data: T, preserveRefs = true): T {
    if (typeof data === 'string') return clean(data) as T;
    if (Array.isArray(data)) return data.map(value => sanitize(value, preserveRefs)) as T;
    if (data && typeof data === 'object') return Object.fromEntries(Object.entries(data).map(([key, value]) => {
      // IAM access IDs are public references required to resume revocation. The
      // secret access key and all freeform text are always masked, as in engine.
      const publicRef = preserveRefs && ['keyRef', 'oldKeyRef', 'newKeyRef'].includes(key)
        && typeof value === 'string' && publicRefs.has(value) && !sensitive.has(value);
      return [clean(key), publicRef ? value : sanitize(value, preserveRefs)];
    })) as T;
    return data;
  }
  const logged = (level: keyof ProviderContext['log']) => (message: string, data?: Record<string, unknown>) =>
    deps.providerCtx.log[level](clean(message), data === undefined ? undefined : sanitize(data, false));
  const log: ProviderContext['log'] = { info: logged('info'), warn: logged('warn'), error: logged('error'), debug: logged('debug') };
  const ctx: ProviderContext = { ...deps.providerCtx, credentials: { ...deps.providerCtx.credentials }, log };
  async function journal(event: JournalEntry['event'], fields: Omit<JournalEntry, 'at' | 'planId' | 'event'> = {}): Promise<void> {
    await deps.journal.append(sanitize({ at: (deps.now?.() ?? new Date()).toISOString(), planId: input.plan.id, event, ...fields }));
  }
  return { sanitize, journal, ctx };
}
