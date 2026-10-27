import { afterEach, expect, test } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configSchema, loadConfigMetadata } from '../../src/cli/config.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

test('phase2 settings contain policy and channel metadata without secret fields', () => {
  const settings = configSchema.parse({
    autopilot: { graceMinutes: 20, maxServices: 3, showHints: false, healthChecks: [{ serviceKey: 'railway:p/e/s', url: 'https://health.example.test/ready' }] },
    notify: { channels: [{ id: 'phone', kind: 'ntfy', server: 'https://push.example.test' }], relay: { server: 'https://relay.example.test' } },
  });
  expect(settings).toMatchObject({ autopilot: { graceMinutes: 20, maxServices: 3 }, notify: { channels: [{ id: 'phone', kind: 'ntfy' }] } });
});

test.each(['webhookUrl', 'botToken', 'password', 'topic'])('phase2 config refuses secret channel setting %s', field => {
  expect(configSchema.safeParse({ notify: { channels: [{ id: 'one', kind: 'webhook', [field]: 'private-value' }] } }).success).toBe(false);
});

test('phase2 defaults do not enable autopilot or notifications by themselves', () => {
  const settings = configSchema.parse({});
  expect(settings).toMatchObject({ autopilot: { graceMinutes: 15, maxServices: 10, showHints: false, healthChecks: [] }, notify: { channels: [] } });
});

test('health check config contributes the configured-purpose user egress rule', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'keysentry-phase2-config-')); dirs.push(cwd);
  await writeFile(join(cwd, 'keysentry.yaml'), 'autopilot:\n  healthChecks:\n    - serviceKey: railway:p/e/s\n      url: https://health.example.test/ready\n');
  const metadata = await loadConfigMetadata({ cwd, env: {} });
  expect(metadata.userHostRules).toContainEqual({ host: 'health.example.test', owner: 'user', purpose: 'health check you configured' });
});
