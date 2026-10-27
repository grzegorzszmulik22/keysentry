// In-memory fakes for engine, monitor and e2e tests (owned by the orchestrator).
import type {
  DeployState,
  HostAdapter,
  HostCapabilities,
  HostId,
  ProviderAdapter,
  ProviderContext,
  ProviderId,
  ProviderKeyInfo,
  RawVariable,
  RotationMethod,
  RotationResult,
  ServiceRef,
  UsageSample,
  VerifyResult,
} from '../../src/types.js';

export function svc(host: HostId, serviceId: string, environmentId = 'production', projectId = 'proj1'): ServiceRef {
  return {
    host,
    projectId,
    projectName: projectId,
    serviceId,
    serviceName: serviceId,
    environmentId,
    environmentName: environmentId,
  };
}

interface FakeService {
  ref: ServiceRef;
  vars: Map<string, { value: string; sealed: boolean }>;
}

/** A host with services and variables kept in memory. Records every write and redeploy. */
export class FakeHost implements HostAdapter {
  readonly capabilities: HostCapabilities;
  readonly writes: { serviceId: string; vars: Record<string, string>; skipDeploy: boolean }[] = [];
  readonly redeploys: string[] = [];
  /** serviceIds whose next writeVariables call throws. */
  failWritesFor = new Set<string>();
  /** serviceIds whose deployments end in 'failed'. */
  failDeploysFor = new Set<string>();
  /** How many deploymentStatus polls return 'pending' before the final state. */
  pendingPolls = 1;
  private services = new Map<string, FakeService>();
  private deploys = new Map<string, { serviceId: string; polls: number }>();
  private seq = 0;

  constructor(
    readonly id: HostId,
    caps: Partial<HostCapabilities> = {},
  ) {
    this.capabilities = { readValues: true, batchWrite: true, redeploy: true, ...caps };
  }

  addService(serviceId: string, vars: Record<string, string>, sealed: string[] = [], environmentId = 'production'): ServiceRef {
    const ref = svc(this.id, serviceId, environmentId);
    const m = new Map<string, { value: string; sealed: boolean }>();
    for (const [k, v] of Object.entries(vars)) m.set(k, { value: v, sealed: sealed.includes(k) });
    this.services.set(serviceId, { ref, vars: m });
    return ref;
  }

  /** Test inspection: current plaintext value (bypasses sealing). */
  peek(serviceId: string, name: string): string | undefined {
    return this.services.get(serviceId)?.vars.get(name)?.value;
  }

  async listServices(): Promise<ServiceRef[]> {
    return [...this.services.values()].map((s) => s.ref);
  }

  async readVariables(service: ServiceRef): Promise<RawVariable[]> {
    const s = this.mustGet(service.serviceId);
    return [...s.vars.entries()].map(([name, v]) =>
      v.sealed || !this.capabilities.readValues ? { name, sealed: true } : { name, value: v.value, sealed: false },
    );
  }

  async writeVariables(service: ServiceRef, vars: Record<string, string>, opts: { skipDeploy: boolean }): Promise<void> {
    if (this.failWritesFor.has(service.serviceId)) throw new Error(`fake write failure for ${service.serviceId}`);
    const s = this.mustGet(service.serviceId);
    this.writes.push({ serviceId: service.serviceId, vars: { ...vars }, skipDeploy: opts.skipDeploy });
    for (const [k, v] of Object.entries(vars)) {
      const prev = s.vars.get(k);
      s.vars.set(k, { value: v, sealed: prev?.sealed ?? false });
    }
  }

  async redeploy(service: ServiceRef): Promise<string | null> {
    if (!this.capabilities.redeploy) return null;
    this.mustGet(service.serviceId);
    this.redeploys.push(service.serviceId);
    const id = `dep-${++this.seq}`;
    this.deploys.set(id, { serviceId: service.serviceId, polls: 0 });
    return id;
  }

  async deploymentStatus(_service: ServiceRef, deploymentId: string): Promise<DeployState> {
    const d = this.deploys.get(deploymentId);
    if (!d) return 'failed';
    d.polls++;
    if (d.polls <= this.pendingPolls) return 'pending';
    return this.failDeploysFor.has(d.serviceId) ? 'failed' : 'success';
  }

  private mustGet(serviceId: string): FakeService {
    const s = this.services.get(serviceId);
    if (!s) throw new Error(`unknown fake service ${serviceId}`);
    return s;
  }
}

interface FakeKey {
  ref: string;
  value: string;
  active: boolean;
  costUsd: number;
  requests: number;
  byModel: Record<string, number>;
  limitUsd: number | null;
  name: string;
  createdAt: string;
}

/**
 * A provider whose keys live in memory. Supports every optional capability so tests can exercise auto, atomic-roll,
 * generate and guided flows (set `method`), verification, revocation, usage and caps.
 */
export class FakeProvider implements ProviderAdapter {
  readonly keys = new Map<string, FakeKey>(); // by ref
  readonly revoked: string[] = [];
  readonly capped: string[] = [];
  /** Make the next verify of a NEW key fail. */
  failVerifyOfNew = false;
  /** Clock for key creation times (listKeys createdAt). */
  now: () => Date = () => new Date();
  private seq = 0;

  constructor(
    readonly id: ProviderId,
    readonly method: RotationMethod = 'auto',
    private readonly prefix = 'sk-fake-',
  ) {}

  /** Create a key that already exists before rotation (e.g. the one stored in hosts). */
  issue(name = 'existing', limitUsd: number | null = null): { value: string; ref: string } {
    const ref = `key_${++this.seq}`;
    const value = `${this.prefix}${ref}_${'x'.repeat(24)}${this.seq}`;
    this.keys.set(ref, { ref, value, active: true, costUsd: 0, requests: 0, byModel: {}, limitUsd, name, createdAt: this.now().toISOString() });
    return { value, ref };
  }

  /** Simulate traffic on a key. */
  spend(ref: string, usd: number, requests = 1, model = 'fake-model'): void {
    const k = this.keys.get(ref);
    if (!k) throw new Error(`unknown key ${ref}`);
    k.costUsd += usd;
    k.requests += requests;
    k.byModel[model] = (k.byModel[model] ?? 0) + usd;
  }

  /** Simulate the provider revoking a key on its own (e.g. after a host breach notice). */
  revokeUpstream(ref: string): void {
    const k = this.keys.get(ref);
    if (k) k.active = false;
  }

  refOf(value: string): string | null {
    for (const k of this.keys.values()) if (k.value === value) return k.ref;
    return null;
  }

  async verify(value: string, _ctx: ProviderContext): Promise<VerifyResult> {
    const ref = this.refOf(value);
    const k = ref ? this.keys.get(ref) : undefined;
    if (!k || !k.active) return { ok: false, status: 401, error: 'invalid key' };
    if (this.failVerifyOfNew && k.name.startsWith('rotated')) return { ok: false, status: 500, error: 'verify failed' };
    return { ok: true, status: 200, identity: k.name };
  }

  async rotate(oldValue: string, _ctx: ProviderContext): Promise<RotationResult> {
    const oldRef = this.refOf(oldValue);
    const { value, ref } = this.issue(`rotated-${this.seq + 1}`);
    if (this.method === 'atomic-roll' && oldRef) {
      const k = this.keys.get(oldRef);
      if (k) k.active = false;
    }
    return {
      newValue: value,
      oldKeyRef: oldRef,
      newKeyRef: ref,
      oldRevoked: this.method === 'atomic-roll',
    };
  }

  async revoke(keyRef: string, _ctx: ProviderContext): Promise<void> {
    const k = this.keys.get(keyRef);
    if (!k) throw new Error(`unknown key ref ${keyRef}`);
    k.active = false;
    this.revoked.push(keyRef);
  }

  async resolveKeyRef(value: string, _ctx: ProviderContext): Promise<string | null> {
    return this.refOf(value);
  }

  guidance() {
    return { url: `https://example.invalid/${this.id}/keys`, steps: ['Create a new key', 'Paste it'] };
  }

  async listKeys(_ctx: ProviderContext): Promise<ProviderKeyInfo[]> {
    return [...this.keys.values()].map((k) => ({
      keyRef: k.ref,
      name: k.name,
      hint: `${k.value.slice(0, 8)}...${k.value.slice(-4)}`,
      disabled: !k.active,
      limitUsd: k.limitUsd,
      createdAt: k.createdAt,
    }));
  }

  async usage(keyRef: string, window: { from: Date; to: Date }, _ctx: ProviderContext): Promise<UsageSample> {
    const k = this.keys.get(keyRef);
    if (!k) throw new Error(`unknown key ref ${keyRef}`);
    return {
      keyRef,
      from: window.from.toISOString(),
      to: window.to.toISOString(),
      costUsd: 0,
      cumulativeCostUsd: k.costUsd,
      requests: k.requests,
      byModel: { ...k.byModel },
    };
  }

  async cap(keyRef: string, _ctx: ProviderContext): Promise<void> {
    const k = this.keys.get(keyRef);
    if (!k) throw new Error(`unknown key ref ${keyRef}`);
    k.active = false;
    this.capped.push(keyRef);
  }
}
