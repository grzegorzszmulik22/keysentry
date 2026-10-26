import { setImmediate } from 'node:timers/promises';
import { describe, expect, it } from 'vitest';
import { buildInventory, scanHosts, type HostScan } from '../../src/core/inventory.js';
import { serviceKey } from '../../src/core/service-key.js';
import type { HostId, Logger, RawVariable } from '../../src/types.js';
import { FakeHost, svc } from '../helpers/fakes.js';

const key = Buffer.alloc(32, 7);
const now = new Date('2026-10-26T17:00:00.000Z');
const openaiValue = `sk-proj-${'aZ7m'.repeat(15)}`;
const randomValue = 'Q7m2Za8Ps4Nc9Ld6Wr0Yb3Xv5Tk1Hu8As2Df6Gj9';

function quietLogger(lines: string[] = []): Logger {
  const record = (message: string, data?: Record<string, unknown>) => {
    lines.push(JSON.stringify({ message, data }));
  };
  return { info: record, warn: record, error: record, debug: record };
}

describe('serviceKey', () => {
  it('includes the host, project, environment and service without changing empty IDs', () => {
    expect(serviceKey(svc('railway', 'api', 'production', 'project')))
      .toBe('railway:project/production/api');
    expect(serviceKey(svc('railway', '', '', 'project'))).toBe('railway:project//');
    expect(serviceKey(svc('github-actions', 'owner/repo', '', 'owner')))
      .toBe('github-actions:owner//owner/repo');
  });
});

describe('buildInventory', () => {
  it('groups the same value under three names in two services into one cluster', () => {
    const first = svc('railway', 'api');
    const second = svc('vercel', 'frontend');
    const inventory = buildInventory([
      { host: 'railway', services: [{ service: first, vars: [
        { name: 'OPENAI_API_KEY', value: openaiValue, sealed: false },
        { name: 'MODEL_TOKEN', value: openaiValue, sealed: false },
      ] }] },
      { host: 'vercel', services: [{ service: second, vars: [
        { name: 'AI_TOKEN', value: openaiValue, sealed: false },
      ] }] },
    ], key, now);

    expect(inventory).toMatchObject({
      version: 1,
      scannedAt: '2026-10-26T17:00:00.000Z',
      hosts: ['railway', 'vercel'],
      services: [first, second],
      errors: [],
    });
    expect(inventory.findings).toHaveLength(3);
    expect(inventory.clusters).toHaveLength(1);
    expect(inventory.clusters[0]).toMatchObject({ provider: 'openai', tier: 'ai', method: 'auto' });
    expect(inventory.clusters[0]?.id).toMatch(/^[a-f0-9]{32}$/);
    expect(inventory.clusters[0]?.consumers.map((consumer) => consumer.varName))
      .toEqual(['OPENAI_API_KEY', 'MODEL_TOKEN', 'AI_TOKEN']);
    expect(new Set(inventory.findings.map((finding) => finding.fingerprint)).size).toBe(1);
  });

  it('keeps each sealed variable separate and retains sealed names that look like ordinary config', () => {
    const inventory = buildInventory([{ host: 'fly', services: [
      { service: svc('fly', 'api'), vars: [
        { name: 'OPENAI_API_KEY', sealed: true },
        { name: 'PORT', value: openaiValue, sealed: true },
      ] },
      { service: svc('fly', 'worker'), vars: [{ name: 'OPENAI_API_KEY', sealed: true }] },
    ] }], key, now);

    expect(inventory.clusters.map((cluster) => cluster.id)).toEqual([
      'sealed:fly:proj1/production/api:OPENAI_API_KEY',
      'sealed:fly:proj1/production/api:PORT',
      'sealed:fly:proj1/production/worker:OPENAI_API_KEY',
    ]);
    expect(inventory.clusters.every((cluster) => cluster.fingerprint === null && cluster.hint === null))
      .toBe(true);
    expect(inventory.findings[1]).toMatchObject({
      provider: 'unknown', tier: 'unknown', isSecret: true, confidence: 'low', sealed: true,
      fingerprint: null, hint: null,
    });
  });

  it('drops readable nonsecrets while keeping their service in the scanned service list', () => {
    const service = svc('dotenv', '.env', '');
    const inventory = buildInventory([{ host: 'dotenv', services: [{ service, vars: [
      { name: 'PORT', value: '3000', sealed: false },
      { name: 'NODE_ENV', value: 'production', sealed: false },
      { name: 'PUBLIC_SITE_URL', value: 'https://example.com', sealed: false },
      { name: 'FEATURE_ENABLED', value: 'true', sealed: false },
      { name: 'STRIPE_PUBLISHABLE_KEY', value: 'pk_live_12345678901234567890', sealed: false },
      { name: 'DATABASE_URL', value: 'postgresql://localhost/app', sealed: false },
      { name: 'MODEL_TOKEN', value: '${{shared.OPENAI_API_KEY}}', sealed: false },
    ] }] }], key, now);

    expect(inventory.findings).toEqual([]);
    expect(inventory.clusters).toEqual([]);
    expect(inventory.services).toEqual([service]);
  });

  it('selects the provider, tier and method from the highest confidence consumer', () => {
    const inventory = buildInventory([{ host: 'railway', services: [{ service: svc('railway', 'api'), vars: [
      { name: 'API_KEY', value: randomValue, sealed: false },
      { name: 'AWS_SECRET_ACCESS_KEY', value: randomValue, sealed: false },
      { name: 'OTHER_TOKEN', value: randomValue, sealed: false },
    ] }] }], key, now);

    expect(inventory.findings.map((finding) => finding.confidence)).toEqual(['low', 'high', 'low']);
    expect(inventory.clusters).toHaveLength(1);
    expect(inventory.clusters[0]).toMatchObject({ provider: 'aws', tier: 'cloud', method: 'auto' });
  });

  it('keeps the first provider and tier when classifications have equal confidence', () => {
    const inventory = buildInventory([{ host: 'railway', services: [{ service: svc('railway', 'api'), vars: [
      { name: 'CLOUDFLARE_API_TOKEN', value: randomValue, sealed: false },
      { name: 'JWT_SECRET', value: randomValue, sealed: false },
    ] }] }], key, now);

    expect(inventory.findings.map((finding) => finding.confidence)).toEqual(['medium', 'medium']);
    expect(inventory.clusters[0]).toMatchObject({
      provider: 'cloudflare', tier: 'cloud', method: 'atomic-roll',
    });
  });

  it('does not preserve variable payloads or unsafe scan error messages in serialized output', () => {
    const variable: RawVariable & { debugValue: string } = {
      name: 'OPENAI_API_KEY', value: openaiValue, sealed: false, debugValue: randomValue,
    };
    const inventory = buildInventory([{ host: 'railway', services: [
      { service: svc('railway', 'api'), vars: [variable] },
    ], error: `request failed with credential ${openaiValue}` }], key, now);
    const serialized = JSON.stringify(inventory);

    expect(serialized).not.toContain(openaiValue);
    expect(serialized).not.toContain(randomValue);
    expect(serialized).not.toContain('debugValue');
    expect(serialized).not.toContain('"value"');
    expect(inventory.findings[0]).not.toBe(variable);
    expect(inventory.errors).toHaveLength(1);
    expect(inventory.errors[0]?.host).toBe('railway');
    expect(inventory.clusters[0]?.consumers[0]).not.toHaveProperty('confidence');
  });

  it('treats a secret with an unexpectedly missing value as sealed without inventing a fingerprint', () => {
    const inventory = buildInventory([{ host: 'railway', services: [{ service: svc('railway', 'api'), vars: [
      { name: 'OPENAI_API_KEY', sealed: false },
      { name: 'CONFIG_LABEL', sealed: false },
    ] }] }], key, now);

    expect(inventory.findings).toHaveLength(1);
    expect(inventory.findings[0]).toMatchObject({ sealed: true, fingerprint: null, hint: null });
    expect(inventory.clusters[0]?.id).toBe('sealed:railway:proj1/production/api:OPENAI_API_KEY');
  });

  it('deduplicates hosts and scanned services without dropping consumers', () => {
    const service = svc('railway', 'api');
    const scan: HostScan = { host: 'railway', services: [{ service, vars: [
      { name: 'OPENAI_API_KEY', value: openaiValue, sealed: false },
    ] }] };
    const inventory = buildInventory([scan, scan], key, now);

    expect(inventory.hosts).toEqual(['railway']);
    expect(inventory.services).toEqual([service]);
    expect(inventory.clusters).toHaveLength(1);
    expect(inventory.clusters[0]?.consumers).toHaveLength(2);
  });
});

describe('scanHosts', () => {
  it('isolates host list failures and never exposes thrown credentials in the inventory or logs', async () => {
    const failed = new FakeHost('railway');
    failed.listServices = async () => { throw new Error(`Authorization: Bearer ${openaiValue}`); };
    const healthy = new FakeHost('vercel');
    healthy.addService('frontend', { OPENAI_API_KEY: openaiValue });
    const lines: string[] = [];

    const inventory = await scanHosts([failed, healthy], key, quietLogger(lines));

    expect(inventory.hosts).toEqual(['railway', 'vercel']);
    expect(inventory.findings).toHaveLength(1);
    expect(inventory.errors).toHaveLength(1);
    expect(inventory.errors[0]?.host).toBe('railway');
    expect(JSON.stringify({ inventory, lines })).not.toContain(openaiValue);
    expect(healthy.writes).toEqual([]);
    expect(healthy.redeploys).toEqual([]);
  });

  it('retains successful service reads when another service on the same host fails', async () => {
    const host = new FakeHost('railway');
    host.addService('first', { OPENAI_API_KEY: openaiValue });
    host.addService('broken', { API_KEY: randomValue });
    host.addService('last', { AWS_SECRET_ACCESS_KEY: randomValue });
    const readVariables = host.readVariables.bind(host);
    host.readVariables = async (service) => {
      if (service.serviceId === 'broken') throw new Error(`unsafe ${randomValue}`);
      return readVariables(service);
    };

    const inventory = await scanHosts([host], key, quietLogger());

    expect(inventory.findings.map((finding) => finding.varName)).toEqual(['OPENAI_API_KEY', 'AWS_SECRET_ACCESS_KEY']);
    expect(inventory.services.map((service) => service.serviceId)).toEqual(['first', 'broken', 'last']);
    expect(inventory.errors).toHaveLength(1);
    expect(inventory.errors[0]?.host).toBe('railway');
    expect(JSON.stringify(inventory)).not.toContain(randomValue);
    expect(host.writes).toEqual([]);
    expect(host.redeploys).toEqual([]);
  });

  it('keeps input order and the first confidence tie winner when reads finish out of order', async () => {
    const firstHost = new FakeHost('railway');
    firstHost.addService('first', { CLOUDFLARE_API_TOKEN: randomValue });
    firstHost.addService('last', { JWT_SECRET: randomValue });
    const secondHost = new FakeHost('vercel');
    secondHost.addService('frontend', { API_KEY: randomValue });
    let releaseFirst = () => {};
    const gate = new Promise<void>((resolve) => { releaseFirst = resolve; });
    const completed: string[] = [];
    const readVariables = firstHost.readVariables.bind(firstHost);
    firstHost.readVariables = async (service) => {
      if (service.serviceId === 'first') await gate;
      const vars = await readVariables(service);
      completed.push(service.serviceId);
      return vars;
    };

    const pending = scanHosts([firstHost, secondHost], key, quietLogger());
    await setImmediate();
    releaseFirst();
    const inventory = await pending;

    expect(completed).toEqual(['last', 'first']);
    expect(inventory.findings.map((finding) => finding.varName))
      .toEqual(['CLOUDFLARE_API_TOKEN', 'JWT_SECRET', 'API_KEY']);
    expect(inventory.clusters[0]).toMatchObject({
      provider: 'cloudflare', tier: 'cloud', method: 'atomic-roll',
    });
  });

  it('limits every list and read across all hosts to four active calls and preserves scan order', async () => {
    let active = 0;
    let maximum = 0;
    async function tracked<T>(operation: () => Promise<T>): Promise<T> {
      active += 1;
      maximum = Math.max(maximum, active);
      try {
        await setImmediate();
        return await operation();
      } finally {
        active -= 1;
      }
    }
    const ids: HostId[] = ['railway', 'vercel', 'render', 'fly', 'github-actions', 'dotenv'];
    const hosts = ids.map((id) => {
      const host = new FakeHost(id);
      for (let index = 0; index < 5; index += 1) {
        host.addService(`service-${index}`, { OPENAI_API_KEY: openaiValue });
      }
      const listServices = host.listServices.bind(host);
      const readVariables = host.readVariables.bind(host);
      host.listServices = () => tracked(listServices);
      host.readVariables = (service) => tracked(() => readVariables(service));
      return host;
    });

    const inventory = await scanHosts(hosts, key, quietLogger());

    expect(maximum).toBe(4);
    expect(active).toBe(0);
    expect(inventory.hosts).toEqual(ids);
    expect(inventory.findings).toHaveLength(30);
    expect(inventory.clusters).toHaveLength(1);
    expect(inventory.findings.slice(0, 5).map((finding) => finding.service.serviceId))
      .toEqual(['service-0', 'service-1', 'service-2', 'service-3', 'service-4']);
    expect(hosts.every((host) => host.writes.length === 0 && host.redeploys.length === 0)).toBe(true);
  });
});
