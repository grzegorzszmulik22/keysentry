import { hkdfSync, randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { AttestationClaims, BoxSealMode } from '../../../src/types.js';
import { openBytes } from '../../../src/security/index.js';
import { createBoxSealer, createByoKmsSealer, deriveUnlockDataKey, exchangeForAccessToken, kmsEncrypt, MAX_BOX_BUNDLE_BYTES, type BoxSealOptions } from '../../../src/box/seal/index.js';
import { createSealFakes } from './fakes.js';

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))); });

async function setup(mode: BoxSealMode = 'standard', fakeOptions = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'keysentry-seal-'));
  dirs.push(dir);
  const fakes = createSealFakes(fakeOptions);
  const tokenPath = join(dir, 'launcher-token');
  await writeFile(tokenPath, fakes.mintSubjectToken(), { mode: 0o600 });
  const options: BoxSealOptions = {
    http: fakes.http, stateDir: join(dir, 'state'), attestationTokenPath: tokenPath,
    config: { boxId: 'box-test', mode, audience: fakes.audience, keyName: fakes.keyName },
  };
  return { dir, fakes, tokenPath, options, sealer: createBoxSealer(options), file: join(options.stateDir, 'sealed-bundle.json') };
}

async function changeRecord(file: string, field: 'wrappedKey' | 'sealedBundle') {
  const record = JSON.parse(await readFile(file, 'utf8'));
  const bytes = Buffer.from(record[field], 'base64');
  bytes[bytes.length - 1]! ^= 1;
  record[field] = bytes.toString('base64');
  await writeFile(file, JSON.stringify(record));
}

describe('box sealing at rest', () => {
  it.each(['standard', 'byo-kms', 'unlock-on-restart'] as const)('round trips %s across a new instance without writing bundle or shares', async (mode) => {
    const s = await setup(mode);
    const bundle = Buffer.from('planted-provider-token-long-enough-to-find');
    const shareB = randomBytes(32);
    await s.sealer.sealBundle(bundle, mode === 'unlock-on-restart' ? shareB : undefined);
    const result = await createBoxSealer(s.options).openSealed(mode === 'unlock-on-restart' ? shareB : undefined);
    expect(result.status).toBe('open');
    if (result.status === 'open') {
      expect(result.bundle.equals(bundle)).toBe(true);
      result.bundle.fill(0);
    }
    expect(await readdir(s.options.stateDir)).toEqual(['sealed-bundle.json']);
    const disk = await readFile(s.file);
    expect(disk.includes(bundle)).toBe(false);
    expect(disk.toString().includes(bundle.toString('base64'))).toBe(false);
    expect(disk.includes(shareB)).toBe(false);
    expect(disk.toString().includes(shareB.toString('base64'))).toBe(false);
    // KMS sees only a 32-byte key/share, never the provider bundle.
    const request = s.fakes.http.calls.find((call) => call.url.endsWith(':encrypt'))!;
    const body = JSON.parse(request.body!);
    expect(Buffer.from(body.plaintext, 'base64')).toHaveLength(32);
    expect(Buffer.from(body.additionalAuthenticatedData, 'base64').toString()).toBe('keysentry-box-dek:v1:box-test');
    expect(JSON.stringify(s.fakes.http.calls).includes(bundle.toString())).toBe(false);
    if (process.platform !== 'win32') expect((await stat(s.file)).mode & 0o777).toBe(0o600);
  });

  it('uses the customer audience and key without a different encryption scheme', async () => {
    const s = await setup('byo-kms', {
      audience: '//iam.googleapis.com/projects/999999/locations/global/workloadIdentityPools/customer/providers/box',
      keyName: 'projects/customer/locations/europe-west3/keyRings/customer/cryptoKeys/tokens',
    });
    const byo = createByoKmsSealer({ ...s.options, config: { ...s.options.config, mode: 'byo-kms' } });
    await byo.sealBundle(Buffer.from('customer-token'));
    expect((await byo.openSealed()).status).toBe('open');
    const tokenRequest = s.fakes.http.calls.find((call) => call.url.includes('sts.googleapis.com'))!;
    expect(JSON.parse(tokenRequest.body!).audience).toBe(s.fakes.audience);
    expect(s.fakes.http.calls.some((call) => call.url === `https://cloudkms.googleapis.com/v1/${s.fakes.keyName}:decrypt`)).toBe(true);
  });

  it('uses the phase 1 envelope under the KMS-wrapped data key', async () => {
    const s = await setup();
    await s.sealer.sealBundle(Buffer.from('envelope-test'));
    const request = s.fakes.http.calls.find((call) => call.url.endsWith(':encrypt'))!;
    const dek = Buffer.from(JSON.parse(request.body!).plaintext, 'base64');
    const record = JSON.parse(await readFile(s.file, 'utf8'));
    expect(openBytes(dek, Buffer.from(record.sealedBundle, 'base64'), 'keysentry-box-bundle:v1:box-test:standard').toString()).toBe('envelope-test');
    dek.fill(0);
  });

  it('seals bundles larger than the KMS plaintext limit locally', async () => {
    const s = await setup();
    const bundle = randomBytes(128 * 1024);
    await s.sealer.sealBundle(bundle);
    const result = await s.sealer.openSealed();
    expect(result.status === 'open' && result.bundle.equals(bundle)).toBe(true);
  });

  it('refuses an oversized bundle before requesting key material', async () => {
    const s = await setup();
    await expect(s.sealer.sealBundle(Buffer.alloc(MAX_BOX_BUNDLE_BYTES + 1))).rejects.toThrow(/bundle.*at most/i);
    expect(s.fakes.http.calls).toHaveLength(0);
  });

  it('cleans temporary ciphertext files when a filesystem write cannot commit', async () => {
    const s = await setup();
    await s.sealer.sealBundle(Buffer.from('first-token'));
    await rm(s.file);
    await writeFile(join(s.options.stateDir, 'keep'), 'unrelated');
    // A directory at the destination forces rename to fail after the temporary file was written.
    await mkdir(s.file);
    await expect(s.sealer.sealBundle(Buffer.from('second-token'))).rejects.toThrow(/store.*sealed/i);
    expect((await readdir(s.options.stateDir)).sort()).toEqual(['keep', 'sealed-bundle.json']);
    expect(await readFile(join(s.options.stateDir, 'keep'), 'utf8')).toBe('unrelated');
  });

  it.each(['truncated JSON', 'unknown version', 'invalid base64', 'wrong mode'])('refuses malformed state before HTTP: %s', async (reason) => {
    const s = await setup();
    await s.sealer.sealBundle(Buffer.from('token'));
    const record = JSON.parse(await readFile(s.file, 'utf8'));
    if (reason === 'unknown version') record.version = 2;
    if (reason === 'invalid base64') record.wrappedKey = 'bad!!';
    if (reason === 'wrong mode') record.mode = 'byo-kms';
    await writeFile(s.file, reason === 'truncated JSON' ? '{' : JSON.stringify(record));
    const before = s.fakes.http.calls.length;
    await expect(s.sealer.openSealed()).rejects.toThrow(/open.*sealed/i);
    expect(s.fakes.http.calls.length).toBe(before);
  });

  it('reads the default launcher token path through the injected reader', async () => {
    const s = await setup();
    let readPath = '';
    const { attestationTokenPath: _path, ...options } = s.options;
    const sealer = createBoxSealer({ ...options, readAttestationToken: async (path) => { readPath = path; return s.fakes.mintSubjectToken(); } });
    await sealer.sealBundle(Buffer.from('token'));
    expect(readPath).toBe('/run/container_launcher/attestation_verifier_claims_token');
  });

  it('rereads launcher attestation after sealing and refuses a changed workload identity', async () => {
    const s = await setup();
    await s.sealer.sealBundle(Buffer.from('planted-provider-token'));
    await writeFile(s.tokenPath, s.fakes.mintSubjectToken({ dbgstat: 'enabled' }));
    await expect(s.sealer.openSealed()).rejects.toThrow(/attestation.*policy/i);
  });

  it.each(['wrong digest', 'other project', 'debug', 'service account', 'missing STABLE', 'wrong swname'])('refuses policy mismatch: %s without a state file', async (reason) => {
    const s = await setup();
    const base = s.fakes.baseClaims;
    const overrides: Partial<AttestationClaims> = reason === 'debug' ? { dbgstat: 'enabled' }
      : reason === 'service account' ? { google_service_accounts: ['other@example.test'] }
      : reason === 'wrong swname' ? { swname: 'GCE' }
      : { submods: { ...base.submods,
          ...(reason === 'wrong digest' ? { container: { ...base.submods?.container, image_digest: `sha256:${'b'.repeat(64)}` } } : {}),
          ...(reason === 'other project' ? { gce: { ...base.submods?.gce, project_id: 'other-project' } } : {}),
          ...(reason === 'missing STABLE' ? { confidential_space: { support_attributes: ['LATEST'] } } : {}),
        } };
    await writeFile(s.tokenPath, s.fakes.mintSubjectToken(overrides));
    const refused = s.sealer.sealBundle(Buffer.from('planted-provider-token'));
    await expect(refused).rejects.toThrow(/attestation.*policy/i);
    await expect(refused).rejects.not.toThrow('planted-provider-token');
    await expect(readFile(s.file)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(s.fakes.http.calls.some((call) => call.url.includes('cloudkms.googleapis.com'))).toBe(false);
  });

  it('refuses a wrong audience before releasing the key', async () => {
    const s = await setup();
    const sealer = createBoxSealer({ ...s.options, config: { ...s.options.config,
      audience: '//iam.googleapis.com/projects/111111/locations/global/workloadIdentityPools/other/providers/box' } });
    await expect(sealer.sealBundle(Buffer.from('token'))).rejects.toThrow(/audience.*policy/i);
    await expect(readFile(s.file)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('preserves the prior sealed state when KMS refuses resealing', async () => {
    const s = await setup();
    await s.sealer.sealBundle(Buffer.from('first-token'));
    const old = await readFile(s.file);
    s.fakes.controls.kmsStatus = 403;
    await expect(s.sealer.sealBundle(Buffer.from('planted-second-token'))).rejects.toThrow(/KMS.*policy/i);
    expect((await readFile(s.file)).equals(old)).toBe(true);
    const refused = s.sealer.openSealed();
    await expect(refused).rejects.toThrow(/KMS.*policy/i);
    await expect(refused).rejects.not.toThrow('first-token');
    delete s.fakes.controls.kmsStatus;
    const result = await s.sealer.openSealed();
    expect(result.status === 'open' && result.bundle.toString() === 'first-token').toBe(true);
  });

  it.each(['wrappedKey', 'sealedBundle'] as const)('refuses tampered %s without returning plaintext', async (field) => {
    const s = await setup();
    await s.sealer.sealBundle(Buffer.from('planted-private-token'));
    await changeRecord(s.file, field);
    const rejected = s.sealer.openSealed();
    await expect(rejected).rejects.toThrow();
    await expect(rejected).rejects.not.toThrow('planted-private-token');
  });

  it('binds a wrapped key to the box id using KMS AAD', async () => {
    const s = await setup();
    await s.sealer.sealBundle(Buffer.from('private-token'));
    await expect(createBoxSealer({ ...s.options, config: { ...s.options.config, boxId: 'another-box' } }).openSealed()).rejects.toThrow();
  });

  it('refuses an encrypt CRC mismatch without creating state', async () => {
    const s = await setup();
    s.fakes.controls.encryptResponse = (body) => ({ ...body, ciphertextCrc32c: String((Number(body.ciphertextCrc32c) + 1) >>> 0) });
    await expect(s.sealer.sealBundle(Buffer.from('token'))).rejects.toThrow(/integrity/i);
    await expect(readFile(s.file)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('refuses a decrypt CRC mismatch without exposing the key', async () => {
    const s = await setup();
    await s.sealer.sealBundle(Buffer.from('token'));
    s.fakes.controls.decryptResponse = (body) => ({ ...body, plaintextCrc32c: String((Number(body.plaintextCrc32c) + 1) >>> 0) });
    await expect(s.sealer.openSealed()).rejects.toThrow(/integrity/i);
  });

  it('rejects an authenticated KMS unwrap that is not a 32-byte key', async () => {
    const s = await setup();
    await s.sealer.sealBundle(Buffer.from('private-token'));
    const access = await exchangeForAccessToken(s.fakes.http, { audience: s.fakes.audience, subjectToken: s.fakes.mintSubjectToken() });
    const shortWrapped = await kmsEncrypt(s.fakes.http, access, s.fakes.keyName, Buffer.alloc(31, 7), Buffer.from('keysentry-box-dek:v1:box-test'));
    const record = JSON.parse(await readFile(s.file, 'utf8'));
    record.wrappedKey = shortWrapped.toString('base64');
    await writeFile(s.file, JSON.stringify(record));
    await expect(s.sealer.openSealed()).rejects.toThrow(/invalid box key length/i);
  });

  it('sanitizes token-file errors and does not create state', async () => {
    const s = await setup();
    const sealer = createBoxSealer({ ...s.options, readAttestationToken: async () => { throw new Error('planted-file-secret'); } });
    const rejected = sealer.sealBundle(Buffer.from('token'));
    await expect(rejected).rejects.toThrow(/attestation token/i);
    await expect(rejected).rejects.not.toThrow('planted-file-secret');
    await expect(readFile(s.file)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});

describe('unlock on restart', () => {
  it('derives the data key with share A as IKM, box id as salt, and share B as info', () => {
    const a = Buffer.alloc(32, 0xa1);
    const b = Buffer.alloc(32, 0xb2);
    const expected = Buffer.from(hkdfSync('sha256', a, Buffer.from('box-test'), b, 32));
    expect(deriveUnlockDataKey(a, 'box-test', b).equals(expected)).toBe(true);
  });

  it('restarts locked, notifies once, and unlocks only after receiving the device share', async () => {
    const s = await setup('unlock-on-restart');
    const shareB = randomBytes(32);
    await s.sealer.sealBundle(Buffer.from('private-token'), shareB);
    expect((await s.sealer.openSealed()).status).toBe('open');
    let notices = 0;
    const restarted = createBoxSealer({ ...s.options, onLocked: () => { notices++; } });
    const before = s.fakes.http.calls.length;
    expect(await restarted.openSealed()).toEqual({ status: 'locked' });
    expect(await restarted.openSealed()).toEqual({ status: 'locked' });
    expect(notices).toBe(1);
    await restarted.lock();
    expect(await restarted.openSealed()).toEqual({ status: 'locked' });
    expect(notices).toBe(1);
    expect(s.fakes.http.calls.length).toBe(before);
    const opened = await restarted.openSealed(shareB);
    expect(opened.status === 'open' && opened.bundle.toString() === 'private-token').toBe(true);
    // The box owns a copy; the caller can clear the delivery buffer.
    shareB.fill(0);
    expect((await restarted.openSealed()).status).toBe('open');
    await restarted.lock();
    expect(await restarted.openSealed()).toEqual({ status: 'locked' });
    expect(notices).toBe(2);
  });

  it('does not retain a wrong device share or return plaintext', async () => {
    const s = await setup('unlock-on-restart');
    const shareB = randomBytes(32);
    await s.sealer.sealBundle(Buffer.from('planted-private-token'), shareB);
    const restarted = createBoxSealer(s.options);
    const rejected = restarted.openSealed(randomBytes(32));
    await expect(rejected).rejects.toThrow(/open.*sealed/i);
    await expect(rejected).rejects.not.toThrow('planted-private-token');
    expect(await restarted.openSealed()).toEqual({ status: 'locked' });
    expect((await restarted.openSealed(shareB)).status).toBe('open');
  });

  it('requires exactly 32 bytes of device share before doing HTTP or writing state', async () => {
    const s = await setup('unlock-on-restart');
    await expect(s.sealer.sealBundle(Buffer.from('token'))).rejects.toThrow(/device share/i);
    await expect(s.sealer.sealBundle(Buffer.from('token'), Buffer.alloc(31))).rejects.toThrow(/32 bytes/i);
    expect(s.fakes.http.calls).toHaveLength(0);
  });
});
