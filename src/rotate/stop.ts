import { RotationAbortedError, type HostAdapter, type ProviderAdapter } from '../types.js';
import type { EngineDeps } from './engine.js';

/** Distinguishes a remote stop from an interactive cancellation after preparation. */
export class StopRequestedError extends RotationAbortedError {}

const guarded = new WeakSet<EngineDeps>();

/** Poll immediately before effects, including HTTP after an awaited provider lookup. */
export function withStopChecks(deps: EngineDeps): EngineDeps {
  if (!deps.shouldStop || guarded.has(deps)) return deps;
  let stopped = false;
  async function active(): Promise<void> {
    if (!stopped) {
      try { if (await deps.shouldStop!()) stopped = true; }
      catch { stopped = true; }
    }
    if (stopped) throw new StopRequestedError();
  }
  function guard<T extends HostAdapter | ProviderAdapter>(target: T, effects: string[]): T {
    return new Proxy(target, {
      get(object, property) {
        const value: unknown = Reflect.get(object, property, object);
        if (typeof value !== 'function') return value;
        if (typeof property !== 'string' || !effects.includes(property)) return value.bind(object);
        return async (...args: unknown[]) => { await active(); return Reflect.apply(value, object, args); };
      },
    });
  }
  const hosts: EngineDeps['hosts'] = {};
  for (const [id, host] of Object.entries(deps.hosts)) {
    if (host) hosts[id as keyof typeof hosts] = guard(host, ['writeVariables', 'redeploy']);
  }
  const result: EngineDeps = { ...deps, hosts,
    providers: id => guard(deps.providers(id), ['rotate', 'rotateByRef', 'revoke', 'cap']),
    providerCtx: { ...deps.providerCtx, http: {
      async request(request) {
        if (request.method !== 'GET') await active();
        return deps.providerCtx.http.request(request);
      },
    } },
  };
  guarded.add(result);
  return result;
}
