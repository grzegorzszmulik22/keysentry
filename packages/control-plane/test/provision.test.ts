import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { FakeHttp, json } from '../../../test/helpers/fake-http.js';
import { createProvisioner, ProvisionError } from '../src/provision.js';

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

describe('N1: what a failed provision means for the reservation', () => {
  const outcome = (promise: Promise<unknown>) => promise.then(() => 'created', (error: { outcome?: string; message: string }) => {
    expect(error).toBeInstanceOf(ProvisionError);
    expect(error.message).not.toContain('planted');
    return error.outcome;
  });
  it.each([400, 401, 403, 404, 412, 429])('a %i from Compute is a definite refusal: no instance was created', async status => {
    const http = new FakeHttp().on('POST', /.*/, () => json(status, { error: { message: 'planted' } }));
    expect(await outcome(createProvisioner({ ...config, http }).provision({ name: 'box-one', deviceKey }))).toBe('refused');
  });
  it.each([408, 409, 500, 503])('a %i leaves the outcome unknown: the instance may exist', async status => {
    const http = new FakeHttp().on('POST', /.*/, () => json(status, { error: { message: 'planted' } }));
    expect(await outcome(createProvisioner({ ...config, http }).provision({ name: 'box-one', deviceKey }))).toBe('unknown');
  });
  it('a transport error after sending is unknown; an egress refusal before any I/O is a refusal', async () => {
    const lost = new FakeHttp().on('POST', /.*/, () => { throw new Error('planted socket hang up'); });
    expect(await outcome(createProvisioner({ ...config, http: lost }).provision({ name: 'box-one', deviceKey }))).toBe('unknown');
    const blocked = new FakeHttp().on('POST', /.*/, () => { throw Object.assign(new Error('planted'), { code: 'EGRESS_BLOCKED' }); });
    expect(await outcome(createProvisioner({ ...config, http: blocked }).provision({ name: 'box-one', deviceKey }))).toBe('refused');
  });
  it('an accepted insert with an unreadable or failed operation is unknown, never a refusal', async () => {
    for (const reply of [json(200, { name: 'operation-1', status: 'DONE', error: { errors: [] } }), json(200, []), { status: 200, headers: {}, text: 'not json', json() { throw new Error('planted'); } }]) {
      const http = new FakeHttp().on('POST', /.*/, () => reply as ReturnType<typeof json>);
      expect(await outcome(createProvisioner({ ...config, http }).provision({ name: 'box-one', deviceKey }))).toBe('unknown');
    }
  });
  it('live calls without a usable access token send nothing and are refusals', async () => {
    vi.stubEnv('KEYSENTRY_CONTROL_PLANE_LIVE', '1');
    try {
      const { emulatorOrigin: _origin, ...liveConfig } = config;
      for (const accessToken of [undefined, async () => { throw new Error('planted'); }, async () => 'bad\ntoken']) {
        const http = new FakeHttp();
        const provisioner = createProvisioner({ ...liveConfig, http, ...(accessToken ? { accessToken } : {}) });
        expect(await outcome(provisioner.provision({ name: 'box-one', deviceKey }))).toBe('refused');
        expect(await outcome(provisioner.inspect('box-one'))).toBe('refused');
        expect(http.calls).toHaveLength(0);
      }
    } finally { vi.unstubAllEnvs(); }
  });
});

describe('instances.get, stop and start', () => {
  const base = 'http://127.0.0.1:34567/compute/v1/projects/keysentry-test/zones/us-central1-a/instances';
  const exact = (url: string) => new RegExp(`^${url.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}$`);
  const resource = (items: { key: string; value: string }[], extra: Record<string, unknown> = {}) => json(200, { name: 'box-one', status: 'RUNNING', metadata: { items }, ...extra });
  it('reads an instance and its keysentry routing metadata, or reports it absent', async () => {
    const http = new FakeHttp()
      .on('GET', exact(`${base}/box-one`), () => resource([{ key: 'keysentry-box-id', value: 'box-one' }, { key: 'keysentry-enroll-device-key', value: deviceKey }, { key: 'tee-image-reference', value: 'x' }]))
      .on('GET', exact(`${base}/box-two`), () => json(404, { error: { message: 'planted' } }));
    const provisioner = createProvisioner({ ...config, http });
    expect(await provisioner.inspect('box-one')).toEqual({ exists: true, status: 'RUNNING', boxId: 'box-one', deviceKey });
    expect(await provisioner.inspect('box-two')).toEqual({ exists: false });
    expect(http.calls.map(call => [call.method, call.url, call.body, call.headers])).toEqual([['GET', `${base}/box-one`, undefined, {}], ['GET', `${base}/box-two`, undefined, {}]]);
  });
  it('leaves out metadata that is not a box id or device key, and refuses a reply about another instance', async () => {
    const http = new FakeHttp().on('GET', /box-one$/, () => resource([{ key: 'keysentry-box-id', value: 'Not A Box' }, { key: 'keysentry-enroll-device-key', value: 'planted' }]));
    expect(await createProvisioner({ ...config, http }).inspect('box-one')).toEqual({ exists: true, status: 'RUNNING' });
    for (const reply of [resource([], { name: 'box-two' }), resource([], { status: 'planted lower case' }), json(403, {}), json(500, {})]) {
      const other = new FakeHttp().on('GET', /.*/, () => reply);
      await expect(createProvisioner({ ...config, http: other }).inspect('box-one')).rejects.toMatchObject({ outcome: 'unknown', message: 'Box provisioning failed.' });
    }
  });
  it('stops and starts with an empty body; a stop of a missing instance is not an error', async () => {
    const http = new FakeHttp()
      .on('POST', exact(`${base}/box-one/stop`), () => json(200, { name: 'operation-2', status: 'RUNNING' }))
      .on('POST', exact(`${base}/box-one/start`), () => json(200, { name: 'operation-3', status: 'RUNNING' }))
      .on('POST', exact(`${base}/box-two/stop`), () => json(404, {}))
      .on('POST', exact(`${base}/box-two/start`), () => json(500, { error: { message: 'planted' } }));
    const provisioner = createProvisioner({ ...config, http });
    expect(await provisioner.stop('box-one')).toBe('stopping');
    await provisioner.start('box-one');
    expect(await provisioner.stop('box-two')).toBe('absent');
    await expect(provisioner.start('box-two')).rejects.toThrow(/^Box provisioning failed\.$/);
    expect(http.calls.every(call => call.body === undefined && !('content-type' in (call.headers ?? {})))).toBe(true);
  });
  it.each(['../box', 'BOX', 'box?x=1', ''])('refuses an invalid instance name without a request: %s', async name => {
    const http = new FakeHttp();
    const provisioner = createProvisioner({ ...config, http });
    for (const call of [provisioner.inspect(name), provisioner.stop(name), provisioner.start(name)]) await expect(call).rejects.toMatchObject({ outcome: 'refused', message: 'Invalid box name.' });
    expect(http.calls).toHaveLength(0);
  });
});
