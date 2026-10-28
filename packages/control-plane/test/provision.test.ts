import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { FakeHttp, json } from '../../../test/helpers/fake-http.js';
import { createProvisioner } from '../src/provision.js';

const digest = `sha256:${'a'.repeat(64)}`;
const config = {
  projectId: 'keysentry-test', zone: 'us-central1-a',
  subnetwork: 'projects/keysentry-test/regions/us-central1/subnetworks/box-subnet',
  serviceAccount: 'box-vm@keysentry-test.iam.gserviceaccount.com',
  imageReference: `us-central1-docker.pkg.dev/keysentry-test/box/agent@${digest}`,
  allowedDigests: [digest], emulatorOrigin: 'http://127.0.0.1:34567', relayOrigin: 'https://control.example',
};
const deviceKey = generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

describe('Compute provisioning', () => {
  it('posts a private production TDX instance to the local emulator', async () => {
    const http = new FakeHttp().on('POST', /^http:\/\/127\.0\.0\.1:34567\/compute\/v1\/projects\/keysentry-test\/zones\/us-central1-a\/instances$/, () => json(200, {
      name: 'operation-1', status: 'PENDING', targetId: '1',
    }));
    const provisioner = createProvisioner({ ...config, http });
    expect(await provisioner.provision({ name: 'box-one', deviceKey })).toEqual({ name: 'operation-1', status: 'PENDING', targetId: '1' });
    expect(http.calls).toHaveLength(1);
    const request = http.calls[0]!;
    expect(request.headers).toEqual({ 'content-type': 'application/json' });
    expect(JSON.parse(request.body!)).toEqual({
      name: 'box-one',
      machineType: 'zones/us-central1-a/machineTypes/c3-standard-4',
      confidentialInstanceConfig: { enableConfidentialCompute: true, confidentialInstanceType: 'TDX' },
      shieldedInstanceConfig: { enableSecureBoot: true },
      scheduling: { onHostMaintenance: 'TERMINATE', automaticRestart: true },
      disks: [{ boot: true, autoDelete: true, initializeParams: {
        sourceImage: 'projects/confidential-space-images/global/images/family/confidential-space',
        diskType: 'zones/us-central1-a/diskTypes/pd-balanced', diskSizeGb: '20',
      } }],
      networkInterfaces: [{ subnetwork: config.subnetwork }],
      serviceAccounts: [{ email: config.serviceAccount, scopes: ['https://www.googleapis.com/auth/cloud-platform'] }],
      metadata: { items: [
        { key: 'tee-image-reference', value: config.imageReference }, { key: 'tee-restart-policy', value: 'Always' },
        { key: 'keysentry-box-id', value: 'box-one' }, { key: 'keysentry-relay-origin', value: 'https://control.example' },
        { key: 'keysentry-enroll-device-key', value: deviceKey },
      ] },
    });
  });

  it('M5: writes exactly the routing attributes the box agent reads, and nothing secret', async () => {
    const { METADATA_ATTRIBUTES, readBoxRoute } = await import('../../../src/box/agent/main.js');
    const http = new FakeHttp().on('POST', /.*/, () => json(200, { name: 'operation-1', status: 'DONE' }));
    await createProvisioner({ ...config, http }).provision({ name: 'box-one', deviceKey });
    const items = (JSON.parse(http.calls[0]!.body!) as { metadata: { items: { key: string; value: string }[] } }).metadata.items;
    const metadata = new Map(items.map(item => [item.key, item.value]));
    expect(Object.values(METADATA_ATTRIBUTES).every(key => metadata.has(key))).toBe(true);
    const route = await readBoxRoute(async name => metadata.get(name)!);
    expect(route).toEqual({ boxId: 'box-one', relayOrigin: 'https://control.example', enrollmentDeviceKey: Buffer.from(deviceKey, 'base64') });
  });

  it.each([
    ['not base64', 'not-a-key'], ['an X25519 key', generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64')],
    ['raw bytes', Buffer.alloc(32, 1).toString('base64')], ['missing', undefined],
  ])('rejects an enrollment device key that is %s without making a request', async (_name, key) => {
    const http = new FakeHttp();
    await expect(createProvisioner({ ...config, http }).provision({ name: 'box-one', deviceKey: key as string })).rejects.toThrow('Invalid enrollment device key');
    expect(http.calls).toHaveLength(0);
  });

  it.each([
    ['plain HTTP off loopback', { relayOrigin: 'http://control.example' }],
    ['a path', { relayOrigin: 'https://control.example/relay' }],
    ['loopback HTTP without an emulator', { relayOrigin: 'http://127.0.0.1:8080', emulatorOrigin: undefined }],
    ['missing', { relayOrigin: undefined }],
  ])('rejects a relay origin with %s', (_name, override) => {
    expect(() => createProvisioner({ ...config, ...override, http: new FakeHttp() } as never)).toThrow('Invalid provisioning configuration');
  });

  it('accepts a loopback relay only next to a loopback emulator', () => {
    expect(() => createProvisioner({ ...config, relayOrigin: 'http://127.0.0.1:8080', http: new FakeHttp() })).not.toThrow();
  });

  it('refuses the live endpoint before invoking even an injected client', async () => {
    const http = new FakeHttp();
    const { emulatorOrigin: _origin, ...liveConfig } = config;
    const provisioner = createProvisioner({ ...liveConfig, http });
    await expect(provisioner.provision({ name: 'box-one', deviceKey })).rejects.toThrow('Live provisioning is disabled');
    expect(http.calls).toHaveLength(0);
  });

  it.each([
    'https://compute.googleapis.com', 'http://localhost:34567', 'http://127.0.0.1.evil:34567',
    'http://127.0.0.1:34567/path', 'http://127.0.0.1:34567?query=value',
    'http://user@127.0.0.1:34567', 'http://2130706433:34567', 'http://127.0.0.1',
    'http://127.0.0.1:34567/', 'http://127.0.0.1:34567#fragment',
  ])('rejects an emulator origin outside an exact loopback origin: %s', (emulatorOrigin) => {
    expect(() => createProvisioner({ ...config, emulatorOrigin, http: new FakeHttp() })).toThrow('Invalid emulator origin');
  });

  it.each([
    { projectId: '../other-project' }, { zone: 'us-central1-a?secret=value' },
    { serviceAccount: 'box-vm@other-project.iam.gserviceaccount.com' },
    { imageReference: 'registry.example/box:latest' }, { allowedDigests: [] },
    { allowedDigests: [`sha256:${'b'.repeat(64)}`] },
    { subnetwork: 'https://evil.example/subnetworks/box' },
    { subnetwork: 'projects/other-project/regions/us-central1/subnetworks/box-subnet' },
    { subnetwork: 'projects/keysentry-test/regions/europe-west1/subnetworks/box-subnet' },
  ])('rejects configuration that cannot create the expected box: %j', (override) => {
    expect(() => createProvisioner({ ...config, ...override, http: new FakeHttp() })).toThrow('Invalid provisioning configuration');
  });

  it.each(['../box', 'BOX', 'box?token=planted-secret', '', `b${'x'.repeat(63)}`])('rejects invalid instance names without making a request: %s', async (name) => {
    const http = new FakeHttp();
    const provisioner = createProvisioner({ ...config, http });
    await expect(provisioner.provision({ name, deviceKey })).rejects.toThrow('Invalid box name');
    expect(http.calls).toHaveLength(0);
  });

  it('sanitizes HTTP failures and upstream bodies', async () => {
    const http = new FakeHttp().on('POST', /.*/, () => json(403, { error: 'planted-secret-value' }));
    await expect(createProvisioner({ ...config, http }).provision({ name: 'box-one', deviceKey })).rejects.toThrow(/^Box provisioning failed\.$/);
  });

  it('sanitizes client exceptions', async () => {
    const http = new FakeHttp().on('POST', /.*/, () => { throw new Error('planted-secret-value'); });
    await expect(createProvisioner({ ...config, http }).provision({ name: 'box-one', deviceKey })).rejects.toThrow(/^Box provisioning failed\.$/);
  });

  it.each([{ name: 'operation-one', status: 'DONE', error: { errors: [{ message: 'planted-secret' }] } }, { name: 'planted-secret' }, { status: 'DONE' }])('refuses invalid or failed Compute operation responses', async (response) => {
    const http = new FakeHttp().on('POST', /.*/, () => json(200, response));
    await expect(createProvisioner({ ...config, http }).provision({ name: 'box-one', deviceKey })).rejects.toThrow(/^Box provisioning failed\.$/);
  });
});
