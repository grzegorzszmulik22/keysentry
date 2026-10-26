import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildPlan, renderBlastRadius, renderRunbook } from '../../src/core/plan.js';
import type { Cluster, Consumer, Inventory, RiskTier, RotationMethod, RotationPlan, ServiceRef } from '../../src/types.js';

function service(name: string, host: ServiceRef['host'] = 'railway', environmentId = 'production'): ServiceRef {
  return { host, projectId: 'acme', projectName: 'Acme', serviceId: name, serviceName: name, environmentId, environmentName: environmentId };
}

const web = service('web');
const worker = service('worker', 'vercel');

function consumer(ref: ServiceRef, varName = 'API_KEY', sealed = false): Consumer {
  return { service: ref, varName, fingerprint: sealed ? null : 'fingerprint', hint: sealed ? null : 'sk_live…1234', sealed };
}

function cluster(id: string, tier: RiskTier, consumers: Consumer[] = [consumer(web)], method: RotationMethod = 'guided'): Cluster {
  return { id, fingerprint: id, provider: tier === 'payments' ? 'stripe' : tier === 'app' ? 'app-secret' : 'openai', tier, method, hint: 'sk_live…1234', consumers };
}

function inventory(clusters: Cluster[] = []): Inventory {
  return { version: 1, scannedAt: '2026-10-25T12:00:00.000Z', hosts: ['railway', 'vercel'], services: [web, worker], findings: [], clusters, errors: [] };
}

function fixedPlan(inv: Inventory): RotationPlan {
  return { ...buildPlan(inv), id: 'plan-20261026123456-abcd', createdAt: '2026-10-26T12:34:56.000Z' };
}

afterEach(() => vi.useRealTimers());

describe('buildPlan', () => {
  it('orders by risk tier, number of variable locations, then cluster id without changing the inventory', () => {
    const inv = inventory([
      cluster('z-app', 'app'), cluster('z-ai', 'ai', [consumer(web), consumer(worker)]),
      cluster('a-ai', 'ai', [consumer(web), consumer(web, 'ALIAS')]), cluster('one-ai', 'ai'),
      cluster('unknown', 'unknown'), cluster('comms', 'comms'), cluster('payments', 'payments'),
      cluster('database', 'database'), cluster('cloud', 'cloud'), cluster('crypto', 'crypto'),
    ]);
    const original = structuredClone(inv);
    expect(buildPlan(inv).steps.map(step => step.clusterId)).toEqual([
      'crypto', 'cloud', 'database', 'payments', 'a-ai', 'z-ai', 'one-ai', 'comms', 'z-app', 'unknown',
    ]);
    expect(inv).toEqual(original);
  });

  it('keeps every copy when a host or service filter selects a shared secret', () => {
    const inv = inventory([cluster('shared', 'ai', [consumer(web), consumer(worker)]), cluster('other', 'app', [consumer(worker)])]);
    for (const opts of [{ hosts: ['railway'] as const }, { serviceKeys: ['railway:acme/production/web'] }]) {
      const plan = buildPlan(inv, { ...opts, hosts: 'hosts' in opts ? [...opts.hosts] : undefined });
      expect(plan.steps.map(step => step.clusterId)).toEqual(['shared']);
      expect(plan.steps[0]?.consumers.map(item => item.service.host)).toEqual(['railway', 'vercel']);
      expect(plan.services.map(item => item.serviceName)).toEqual(['web', 'worker']);
    }
  });

  it('ANDs all filter dimensions while allowing their matches on different consumers', () => {
    const inv = inventory([cluster('shared', 'ai', [consumer(web), consumer(worker)]), cluster('other', 'ai')]);
    const opts = { tiers: ['ai'] as RiskTier[], clusterIds: ['shared'], hosts: ['railway'] as ServiceRef['host'][], serviceKeys: ['vercel:acme/production/worker'] };
    expect(buildPlan(inv, opts).steps.map(step => step.clusterId)).toEqual(['shared']);
    expect(buildPlan(inv, { ...opts, tiers: ['cloud'] }).steps).toEqual([]);
    expect(buildPlan(inv, { ...opts, clusterIds: ['missing'] }).steps).toEqual([]);
    expect(buildPlan(inv, { ...opts, hosts: ['fly'] }).steps).toEqual([]);
    expect(buildPlan(inv, { ...opts, serviceKeys: ['missing'] }).steps).toEqual([]);
  });

  it.each(['tiers', 'clusterIds', 'hosts', 'serviceKeys'] as const)('treats an explicitly empty %s filter as selecting nothing', dimension => {
    const plan = buildPlan(inventory([cluster('one', 'ai')]), { [dimension]: [] });
    expect(plan.steps).toEqual([]);
    expect(plan.services).toEqual([]);
  });

  it('deduplicates cloned service refs by host, project, environment and service ids', () => {
    const inv = inventory([cluster('one', 'ai', [
      consumer(web), consumer({ ...web }, 'ALIAS'), consumer({ ...web, projectId: 'other' }),
      consumer(service('web', 'railway', 'preview')), consumer(service('web', 'vercel')),
    ])]);
    expect(buildPlan(inv).services.map(item => `${item.host}:${item.projectId}/${item.environmentId}/${item.serviceId}`)).toEqual([
      'railway:acme/production/web', 'railway:other/production/web', 'railway:acme/preview/web', 'vercel:acme/production/web',
    ]);
  });

  it('uses one UTC instant for createdAt and the plan id, with four random hex digits', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-26T14:34:56+02:00'));
    const plan = buildPlan(inventory());
    expect(plan.createdAt).toBe('2026-10-26T12:34:56.000Z');
    expect(plan.id).toMatch(/^plan-20261026123456-[a-f0-9]{4}$/);
    expect(plan.steps).toEqual([]);
    expect(plan.services).toEqual([]);
  });
});

describe('renderRunbook', () => {
  it('keeps reference consumers in the redeploy pass without instructing an overwrite', () => {
    const source = consumer(web, 'OPENAI_API_KEY');
    const reference = { ...consumer(service('worker'), 'MODEL_TOKEN'), reference: true };
    const inv = inventory([cluster('shared', 'ai', [source, reference], 'auto')]);
    const output = renderRunbook(fixedPlan(inv), inv);
    expect(output).toContain('reference — redeploy only; do not overwrite');
    expect(output).toContain('Leave reference variables unchanged');
    expect(output.split('## One redeploy per service')[1]).toContain('railway/worker');
  });

  it('renders a guided shared secret and one redeploy per affected service', () => {
    const inv = inventory([cluster('shared', 'payments', [consumer(web, 'STRIPE_KEY'), consumer(worker, 'BILLING_KEY')])]);
    const output = renderRunbook(fixedPlan(inv), inv);
    expect(output).toContain('https://dashboard.stripe.com/apikeys');
    expect(output).toContain('railway/web:STRIPE_KEY');
    expect(output).toContain('vercel/worker:BILLING_KEY');
    expect(output).toMatchInlineSnapshot(`
      "# Rotation runbook

      Plan: \`plan-20261026123456-abcd\`
      Created: \`2026-10-26T12:34:56.000Z\`
      Inventory scanned: \`2026-10-25T12:00:00.000Z\`

      1 secret clusters · 2 variable locations · 2 services · 2 hosts.

      Review this plan and run a dry run before executing writes.

      ## Rotation steps

      ### 1. payments · stripe

      Cluster: \`shared\`
      Hint: \`sk_live…1234\`
      Method: \`guided\`

      Consumers:

      - \`railway/web:STRIPE_KEY\` (project \`Acme\`, environment \`production\`)
      - \`vercel/worker:BILLING_KEY\` (project \`Acme\`, environment \`production\`)

      1. Open https://dashboard.stripe.com/apikeys and create a replacement with the required permissions, keeping the old key active where supported.
      2. Provide the replacement through the hidden prompt; never put its value in this runbook.
      3. Verify the replacement before changing consumers; stop on any verification failure and keep the old key.
      4. Stage the replacement in every consumer listed above, suppressing deployments until all plan steps are staged.
      5. Keep the old key active through the shared redeploy and verification pass below. Revoke last. If the issuer only supports an immediate roll, coordinate that outage before proceeding.

      ## One redeploy per service

      After every plan step is staged, redeploy each service below exactly once (or apply its host-specific next-deployment procedure).

      - \`railway/web\` (project \`Acme\`, environment \`production\`; \`railway:acme/production/web\`)
      - \`vercel/worker\` (project \`Acme\`, environment \`production\`; \`vercel:acme/production/worker\`)

      Wait for every deployment to succeed. Verify each replacement credential and application health across every consumer; stop on any failure and keep any old keys that are still active.
      Revoke old keys only after all consumers have the replacement and deployments and verification have succeeded. Atomic-roll keys are already revoked by the provider.

      ## Scan errors

      No scan errors.
      "
    `);
  });

  it('describes creation, verification and staging before a shared deployment pass, with revoke last', () => {
    const clusters = [cluster('auto', 'ai', [consumer(web)], 'auto'), cluster('atomic', 'cloud', [consumer(web)], 'atomic-roll'), cluster('generate', 'app', [consumer(web)], 'generate')];
    clusters[1]!.provider = 'cloudflare';
    const inv = inventory(clusters);
    const output = renderRunbook(fixedPlan(inv), inv);
    expect(output).toContain('provider API');
    expect(output).toContain('old key is invalidated immediately');
    expect(output).toContain('cryptographically random');
    expect(output).toContain('Verify the replacement');
    expect(output).toContain('Stage the replacement in every consumer');
    const deploymentSection = output.split('## One redeploy per service')[1] ?? '';
    expect(deploymentSection.match(/railway\/web/g)).toHaveLength(1);
    expect(deploymentSection.indexOf('Verify')).toBeLessThan(deploymentSection.lastIndexOf('Revoke'));
    expect(output).toContain('stop');
  });

  it('uses issuer-specific guidance when there is no universal provider dashboard', () => {
    const unknown = cluster('unknown', 'unknown');
    unknown.provider = 'unknown';
    const inv = inventory([unknown]);
    expect(renderRunbook(fixedPlan(inv), inv)).toContain('issuing provider');
  });

  it('defers atomic rolls until manual work is ready and deploys atomic consumers first', () => {
    const manual = cluster('manual', 'crypto', [consumer(worker)], 'guided');
    manual.provider = 'crypto-wallet';
    const atomic = cluster('atomic', 'cloud', [consumer(web)], 'atomic-roll');
    atomic.provider = 'cloudflare';
    const inv = inventory([manual, atomic]);
    const output = renderRunbook(fixedPlan(inv), inv);
    expect(output).toContain('Defer the irreversible roll until every guided task and all other replacements are prepared and verified.');
    expect(output).toContain('Do not wait for further manual work after rolling an atomic key.');
    const deploymentSection = output.split('## One redeploy per service')[1] ?? '';
    expect(deploymentSection.indexOf('railway/web')).toBeLessThan(deploymentSection.indexOf('vercel/worker'));
  });

  it('renders an empty plan without suggesting deployments', () => {
    const inv = inventory();
    const output = renderRunbook(fixedPlan(inv), inv);
    expect(output).toContain('0 secret clusters');
    expect(output).toContain('No rotation steps selected.');
    expect(output).toContain('No services to redeploy.');
  });
});

describe('renderBlastRadius', () => {
  it('reports shared secrets before single-copy secrets, tier counts, blind rotations and scan failures', () => {
    const sealed = cluster('sealed', 'cloud', [consumer(web, 'CLOUD_TOKEN', true)]);
    sealed.hint = null;
    sealed.fingerprint = null;
    const inv = inventory([sealed, cluster('shared', 'payments', [consumer(web, 'STRIPE_KEY'), consumer(worker, 'BILLING_KEY')])]);
    inv.errors.push({ host: 'fly', message: 'Host scan failed' });
    const output = renderBlastRadius(inv);
    expect(output.indexOf('shared')).toBeLessThan(output.indexOf('### 2.'));
    expect(output).toContain('this key lives in 2 places');
    expect(output).toContain('rotated blind');
    expect(output).toContain('Host scan failed');
    expect(output).toMatchInlineSnapshot(`
      "# Secret blast radius

      Inventory scanned: \`2026-10-25T12:00:00.000Z\`

      2 secret clusters · 3 variable locations · 2 affected services · 2 scanned services · 2 scanned hosts.

      ## Secret clusters

      ### 1. \`shared\`

      payments · stripe · \`guided\`
      Hint: \`sk_live…1234\`
      Shared secret: this key lives in 2 places. Rotate every copy together.

      - \`railway/web:STRIPE_KEY\` (project \`Acme\`, environment \`production\`)
      - \`vercel/worker:BILLING_KEY\` (project \`Acme\`, environment \`production\`)

      ### 2. \`sealed\`

      cloud · openai · \`guided\`
      Hint: unavailable
      This key lives in 1 place.

      - \`railway/web:CLOUD_TOKEN\` (project \`Acme\`, environment \`production\`) — sealed

      ## Tier breakdown

      | Tier | Secret clusters | Variable locations |
      | --- | ---: | ---: |
      | crypto | 0 | 0 |
      | cloud | 1 | 1 |
      | database | 0 | 0 |
      | payments | 1 | 2 |
      | ai | 0 | 0 |
      | comms | 0 | 0 |
      | app | 0 | 0 |
      | unknown | 0 | 0 |

      ## Sealed secrets

      1 sealed variable locations must be rotated blind. Their values cannot be read or matched to copies elsewhere; the true blast radius may be larger.

      - \`railway/web:CLOUD_TOKEN\` (project \`Acme\`, environment \`production\`) — sealed

      ## Scan errors

      The scan is incomplete; unscanned copies may exist.

      - \`fly\`: \`Host scan failed\`
      "
    `);
  });

  it('counts affected services independently from scanned services and variable locations', () => {
    const inv = inventory([cluster('one', 'app', [consumer(web), consumer({ ...web }, 'ALIAS')])]);
    const output = renderBlastRadius(inv);
    expect(output).toContain('1 secret clusters');
    expect(output).toContain('2 variable locations');
    expect(output).toContain('1 affected services');
    expect(output).toContain('2 scanned services');
    expect(output).toContain('| app | 1 | 2 |');
  });

  it('renders an empty inventory without inventing risks', () => {
    const output = renderBlastRadius(inventory());
    expect(output).toContain('0 secret clusters');
    expect(output).toContain('No secret clusters found.');
    expect(output).toContain('No sealed secret locations.');
    expect(output).toContain('No scan errors.');
  });
});

describe('render safety', () => {
  it('redacts unregistered recognizable credentials in freeform metadata and errors', () => {
    const raw = ['sk-proj-' + 'A'.repeat(48), 'ghp_' + 'B'.repeat(36), 'sk_live_' + 'C'.repeat(32)];
    const unsafeService = { ...web, serviceName: `service ${raw[0]}` };
    const unsafe = cluster(`cluster ${raw[1]}`, 'payments', [consumer(unsafeService, `TOKEN_${raw[2]}`)]);
    const inv = inventory([unsafe]);
    inv.errors.push({ host: 'fly', message: `Request failed with ${raw.join(' ')}` });
    const plan = fixedPlan(inv);
    for (const output of [renderRunbook(plan, inv), renderBlastRadius(inv)]) {
      for (const value of raw) expect(output).not.toContain(value);
      expect(output).toContain('«redacted»');
    }
  });

  it('does not expose original values supplied to buildInventory', async () => {
    const { buildInventory } = await import('../../src/core/inventory.js');
    const raw = ['sk-proj-' + 'D'.repeat(48), 'sk_live_' + 'E'.repeat(32), 'a-much-longer-app-session-secret-for-tests'];
    const inv = buildInventory([{ host: 'railway', services: [{ service: web, vars: [
      { name: 'OPENAI_API_KEY', value: raw[0], sealed: false },
      { name: 'STRIPE_SECRET_KEY', value: raw[1], sealed: false },
      { name: 'SESSION_SECRET', value: raw[2], sealed: false },
    ] }] }], Buffer.alloc(32, 1), new Date('2026-10-25T12:00:00.000Z'));
    expect(inv.clusters.length).toBeGreaterThanOrEqual(2);
    for (const output of [renderRunbook(fixedPlan(inv), inv), renderBlastRadius(inv)]) {
      for (const value of raw) expect(output).not.toContain(value);
    }
  });
});
