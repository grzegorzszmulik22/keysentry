import { describe, expect, test } from 'vitest';
import type { ArmedCluster, ArmedPlan, Cluster, Consumer, HostId, Inventory, ServiceRef } from '../../src/types.js';
import { serviceKey } from '../../src/core/service-key.js';
import { checkScope } from '../../src/autopilot/scope.js';

const now = '2026-10-27T12:00:00.000Z';
const adopted = { fingerprint: 'a'.repeat(32), keyRef: 'key-1', at: now };

function service(id: string, host: HostId = 'railway'): ServiceRef {
  return { host, projectId: 'project', projectName: 'Project', serviceId: id, serviceName: id,
    environmentId: 'production', environmentName: 'Production' };
}

function consumer(id = 'api', overrides: Partial<Consumer> = {}): Consumer {
  return { service: service(id), varName: 'OPENAI_API_KEY', fingerprint: 'a'.repeat(32), hint: null, sealed: false, ...overrides };
}

function cluster(id = 'cluster-1', consumers = [consumer()], overrides: Partial<Cluster> = {}): Cluster {
  return { id, fingerprint: 'a'.repeat(32), provider: 'openai', tier: 'ai', method: 'auto', hint: null, consumers, ...overrides };
}

function inventory(clusters: Cluster[]): Inventory {
  return { version: 1, scannedAt: now, hosts: [...new Set(clusters.flatMap(c => c.consumers.map(v => v.service.host)))],
    services: clusters.flatMap(c => c.consumers.map(v => v.service)), findings: [], clusters, errors: [] };
}

function armed(c: Cluster, overrides: Partial<ArmedCluster> = {}): ArmedCluster {
  return { clusterId: c.id, provider: c.provider, method: c.method as 'auto' | 'generate',
    consumers: c.consumers.map(v => ({ serviceKey: serviceKey(v.service), varName: v.varName, fingerprint: v.fingerprint })), ...overrides };
}

function plan(clusters: Cluster[], overrides: Partial<ArmedPlan> = {}): ArmedPlan {
  return { v: 1, id: 'arm-20261027-12345678', projectId: 'project', createdAt: now, expiresAt: '2027-01-25T12:00:00.000Z',
    hosts: ['railway'], clusters: clusters.map(c => armed(c)), maxServicesPerWave: 10, graceSeconds: 900,
    healthChecks: [], nextDeployAcceptance: [], quiet: {}, signer: { keyId: 'test', publicKeyDer: 'test' }, sig: 'test', ...overrides };
}

function scope(p: ArmedPlan, clusters: Cluster[], candidates = clusters.map(c => c.id), host: HostId = 'railway') {
  return checkScope({ plan: p, inventory: inventory(clusters), candidateClusterIds: candidates, host });
}

describe('checkScope', () => {
  test('unchanged armed consumers may execute across all their services', () => {
    const c = cluster('c', [consumer('api'), consumer('worker', { service: service('worker', 'render') })]);
    expect(scope(plan([c]), [c])).toEqual({ execute: ['c'], ask: [] });
  });

  test('clusters not in the plan ask as not armed', () => {
    const c = cluster();
    expect(scope(plan([]), [c])).toEqual({ execute: [], ask: [{ clusterId: c.id, reasons: ['not armed'] }] });
  });

  test('new consumer since arming downgrades to ask', () => {
    const original = cluster();
    const added = consumer('worker');
    const current = { ...original, consumers: [...original.consumers, added] };
    expect(scope(plan([original]), [current])).toEqual({ execute: [], ask: [{ clusterId: original.id,
      reasons: [`a new consumer appeared since arming: ${serviceKey(added.service)}:${added.varName}`] }] });
  });

  test('changing a variable name is a new consumer and a removed consumer', () => {
    const original = cluster();
    const current = cluster(original.id, [consumer('api', { varName: 'OPENAI_KEY' })]);
    expect(scope(plan([original]), [current]).ask[0]?.reasons).toEqual([
      `a new consumer appeared since arming: ${serviceKey(current.consumers[0]!.service)}:OPENAI_KEY`, 'consumer removed',
    ]);
  });

  test('changed consumer fingerprint downgrades to ask', () => {
    const c = cluster();
    expect(scope(plan([c]), [cluster(c.id, [consumer('api', { fingerprint: 'b'.repeat(32) })])])).toEqual({ execute: [],
      ask: [{ clusterId: c.id, reasons: ["a consumer's value changed since arming"] }] });
  });

  test.each([[null, 'a'.repeat(32)], ['a'.repeat(32), null]])('null fingerprints match only null (%s to %s)', (before, after) => {
    const c = cluster('c', [consumer('api', { fingerprint: before })]);
    const current = cluster('c', [consumer('api', { fingerprint: after })]);
    expect(scope(plan([c]), [current]).ask[0]?.reasons).toContain("a consumer's value changed since arming");
  });

  test('null fingerprints remain executable when both snapshots are null', () => {
    const c = cluster('c', [consumer('api', { fingerprint: null })]);
    expect(scope(plan([c]), [c])).toEqual({ execute: ['c'], ask: [] });
  });

  test('removed consumer downgrades to ask even when it is on a different host', () => {
    const c = cluster('c', [consumer('api'), consumer('worker', { service: service('worker', 'render') })]);
    expect(scope(plan([c]), [cluster('c')])).toEqual({ execute: [], ask: [{ clusterId: 'c', reasons: ['consumer removed'] }] });
  });

  test('wave larger than maxServicesPerWave asks for the whole wave', () => {
    const a = cluster('a', [consumer('api')]);
    const b = cluster('b', [consumer('worker')]);
    const unarmed = cluster('unarmed', [consumer('other')]);
    expect(scope(plan([a, b], { maxServicesPerWave: 1 }), [a, b, unarmed])).toEqual({ execute: [], ask: [
      { clusterId: 'a', reasons: ['would touch 2 services (limit 1)'] },
      { clusterId: 'b', reasons: ['would touch 2 services (limit 1)'] },
      { clusterId: 'unarmed', reasons: ['not armed', 'would touch 2 services (limit 1)'] },
    ] });
  });

  test('wave service limit counts distinct service keys rather than clusters or variable names', () => {
    const a = cluster('a');
    const b = cluster('b', [consumer('api', { varName: 'OPENAI_SECOND_KEY' })]);
    expect(scope(plan([a, b], { maxServicesPerWave: 1 }), [a, b])).toEqual({ execute: ['a', 'b'], ask: [] });
  });

  test('clusters already asking do not consume the automatic wave service limit', () => {
    const a = cluster('a');
    const b = cluster('b', [consumer('worker')]);
    expect(scope(plan([a], { maxServicesPerWave: 1 }), [a, b])).toEqual({ execute: ['a'],
      ask: [{ clusterId: 'b', reasons: ['not armed'] }] });
  });

  test('consumer ordering does not change scope', () => {
    const c = cluster('c', [consumer('api'), consumer('worker')]);
    expect(scope(plan([c]), [{ ...c, consumers: [...c.consumers].reverse() }])).toEqual({ execute: ['c'], ask: [] });
  });

  test('service count includes armed consumers on hosts other than the incident host', () => {
    const c = cluster('c', [consumer('api'), consumer('worker', { service: service('worker', 'render') })]);
    expect(scope(plan([c], { maxServicesPerWave: 1 }), [c]).ask).toEqual([
      { clusterId: 'c', reasons: ['would touch 2 services (limit 1)'] },
    ]);
  });

  test('incident on a host outside plan.hosts asks', () => {
    const c = cluster('c', [consumer('api', { service: service('api', 'render') })]);
    expect(scope(plan([c]), [c], ['c'], 'render')).toEqual({ execute: [], ask: [{ clusterId: 'c',
      reasons: ['host not covered by the armed plan'] }] });
  });

  test.each(['railway', 'fly', 'github-actions'] as const)('write-only %s consumer without signed adoption asks', (host) => {
    const c = cluster('c', [consumer('api', { service: service('api', host), sealed: host === 'railway', fingerprint: null })]);
    const p = plan([c], { hosts: [host] });
    expect(scope(p, [c], ['c'], host)).toEqual({ execute: [], ask: [{ clusterId: 'c',
      reasons: ['write-only consumer was not adopted'] }] });
  });

  test('signed adoption covers a fresh write-only inventory without an adoption field', () => {
    const c = cluster('c', [consumer('api', { service: service('api', 'fly'), fingerprint: null })]);
    const p = plan([c], { hosts: ['fly'], clusters: [armed(c, { adopted })] });
    expect(scope(p, [c], ['c'], 'fly')).toEqual({ execute: ['c'], ask: [] });
  });

  test('unsigned current adoption cannot replace missing signed adoption', () => {
    const c = Object.assign(cluster('c', [consumer('api', { sealed: true, fingerprint: null })]), { adopted });
    expect(scope(plan([c]), [c]).ask[0]?.reasons).toEqual(['write-only consumer was not adopted']);
  });

  test.each([
    { provider: 'resend', tier: 'comms' },
    { method: 'guided' },
    { method: 'generate' },
    { tier: 'payments' },
  ] as Partial<Cluster>[])('provider, method and tier drift cannot execute (%j)', overrides => {
    const c = cluster();
    const current = { ...c, ...overrides };
    expect(scope(plan([c]), [current])).toEqual({ execute: [], ask: [{ clusterId: c.id,
      reasons: ['method not allowed automatically'] }] });
  });

  test('only named candidates are considered and duplicate ids appear once', () => {
    const a = cluster('a');
    const b = cluster('b');
    expect(scope(plan([a, b]), [a, b], ['a', 'a'])).toEqual({ execute: ['a'], ask: [] });
  });

  test('missing armed candidate asks as removed', () => {
    const c = cluster();
    expect(scope(plan([c]), [], [c.id])).toEqual({ execute: [], ask: [{ clusterId: c.id, reasons: ['consumer removed'] }] });
  });

  test('candidate without a consumer on the incident host cannot execute', () => {
    const c = cluster('c', [consumer('api', { service: service('api', 'render') })]);
    expect(scope(plan([c]), [c])).toEqual({ execute: [], ask: [{ clusterId: 'c',
      reasons: ['host not covered by the armed plan'] }] });
  });
});
