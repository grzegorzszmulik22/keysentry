import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { expect, test } from 'vitest';
import { FakeHttp, text } from '../helpers/fake-http.js';
import { verifyRelease } from '../../src/release/verify.js';
import { RELEASE_PUBLIC_KEYS, RELEASE_REPO } from '../../src/release/release-key.js';
import { BUILD_COMMIT, BUILD_VERSION } from '../../src/release/build-info.js';

const bundleHash = 'a'.repeat(64);
const base = 'https://github.com/grzegorzszmulik22/keysentry/releases/download/v1.0.0/';
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const publicDer = publicKey.export({ type: 'spki', format: 'der' });
const keyId = createHash('sha256').update(publicDer).digest('hex').slice(0, 16);
const keys = [{ keyId, publicKeyDer: publicDer.toString('base64') }];
const sums = `${bundleHash}  keysentry.mjs\n${'b'.repeat(64)}  release-manifest.json\n`;

function signature(contents = sums, id = keyId, prefix = 'keysentry-release:v1\n'): string {
  return `${id} ${sign(null, Buffer.from(prefix + contents, 'utf8'), privateKey).toString('base64')}\n`;
}
function httpFor(contents = sums, sig = signature(contents)): FakeHttp {
  return new FakeHttp()
    .on('GET', /\/SHA256SUMS$/, () => text(200, contents))
    .on('GET', /\/SHA256SUMS\.sig$/, () => text(200, sig));
}

test('verifyRelease verifies a signed SHA256SUMS and lists both fetched URLs', async () => {
  const http = httpFor();
  expect(await verifyRelease({ http, version: '1.0.0', bundleSha256: bundleHash, keys })).toEqual({
    status: 'verified', checked: [base + 'SHA256SUMS', base + 'SHA256SUMS.sig'],
  });
  expect(http.calls.map(call => [call.method, call.url])).toEqual([
    ['GET', base + 'SHA256SUMS'], ['GET', base + 'SHA256SUMS.sig'],
  ]);
});

test('verifyRelease returns unconfigured without any network request when no keys are pinned', async () => {
  const http = new FakeHttp();
  expect(await verifyRelease({ http, version: '1.0.0', bundleSha256: bundleHash })).toEqual({
    status: 'unconfigured', checked: [],
  });
  expect(http.calls).toEqual([]);
});

test('verifyRelease uses an explicitly selected repository', async () => {
  const http = httpFor();
  expect(await verifyRelease({ http, version: '1.0.0', bundleSha256: bundleHash, keys, repo: 'other/project' }))
    .toEqual({ status: 'verified', checked: [
      'https://github.com/other/project/releases/download/v1.0.0/SHA256SUMS',
      'https://github.com/other/project/releases/download/v1.0.0/SHA256SUMS.sig',
    ] });
});

test.each(['SHA256SUMS', 'SHA256SUMS.sig'])('verifyRelease reports not-found on 404 for %s', async missing => {
  const http = new FakeHttp()
    .on('GET', /\/SHA256SUMS$/, () => text(missing === 'SHA256SUMS' ? 404 : 200, sums))
    .on('GET', /\/SHA256SUMS\.sig$/, () => text(missing === 'SHA256SUMS.sig' ? 404 : 200, signature()));
  const result = await verifyRelease({ http, version: '1.0.0', bundleSha256: bundleHash, keys });
  expect(result.status).toBe('not-found');
  expect(result.checked).toEqual(http.calls.map(call => call.url));
});

test('verifyRelease rejects a signature when signed checksum bytes change', async () => {
  const http = httpFor(sums.replace(/a/, 'c'), signature());
  expect(await verifyRelease({ http, version: '1.0.0', bundleSha256: bundleHash, keys }))
    .toMatchObject({ status: 'bad-signature' });
});

test('verifyRelease signs exact UTF-8 bytes without normalizing line endings', async () => {
  const http = httpFor(sums.replaceAll('\n', '\r\n'), signature());
  expect(await verifyRelease({ http, version: '1.0.0', bundleSha256: bundleHash, keys }))
    .toMatchObject({ status: 'bad-signature' });
});

test('verifyRelease requires the domain-separated signature message', async () => {
  const http = httpFor(sums, signature(sums, keyId, ''));
  expect(await verifyRelease({ http, version: '1.0.0', bundleSha256: bundleHash, keys }))
    .toMatchObject({ status: 'bad-signature' });
});

test('verifyRelease requires the verifying keyId to match the signature line', async () => {
  const http = httpFor(sums, signature(sums, '0'.repeat(16)));
  expect(await verifyRelease({ http, version: '1.0.0', bundleSha256: bundleHash, keys }))
    .toMatchObject({ status: 'bad-signature' });
});

test.each([
  '', 'garbage\n', `${keyId} not-base64\n`, signature().trimEnd(), signature() + signature(), signature() + '\n',
  signature().replace(' ', '  '), signature().replace(/==\n$/, '!\n'),
])('verifyRelease reports bad-signature for malformed signature file %j', async sig => {
  const http = httpFor(sums, sig);
  expect(await verifyRelease({ http, version: '1.0.0', bundleSha256: bundleHash, keys }))
    .toMatchObject({ status: 'bad-signature' });
});

test('verifyRelease rejects invalid public-key DER without throwing', async () => {
  expect(await verifyRelease({ http: httpFor(), version: '1.0.0', bundleSha256: bundleHash,
    keys: [{ keyId, publicKeyDer: 'invalid' }] })).toMatchObject({ status: 'bad-signature' });
});

test('verifyRelease compares the bundle only after a valid signature', async () => {
  expect(await verifyRelease({ http: httpFor(), version: '1.0.0', bundleSha256: 'c'.repeat(64), keys }))
    .toMatchObject({ status: 'hash-mismatch' });
  expect(await verifyRelease({ http: httpFor(sums, 'invalid'), version: '1.0.0', bundleSha256: 'c'.repeat(64), keys }))
    .toMatchObject({ status: 'bad-signature' });
});

test.each([
  `${bundleHash}  some-other.mjs\n`,
  `${bundleHash} keysentry.mjs\n`,
  `${bundleHash}  keysentry.mjs\n${bundleHash}  keysentry.mjs\n`,
  `${bundleHash}  keysentry.mjs\n${'b'.repeat(64)}  keysentry.mjs\n`,
])('verifyRelease reports hash-mismatch for absent or ambiguous bundle checksum %j', async contents => {
  expect(await verifyRelease({ http: httpFor(contents), version: '1.0.0', bundleSha256: bundleHash, keys }))
    .toMatchObject({ status: 'hash-mismatch' });
});

test('verifyRelease never treats a failed HTTP response as verified or includes its body in errors', async () => {
  const http = new FakeHttp().on('GET', /\/SHA256SUMS$/, () => text(503, 'private response body'));
  await expect(verifyRelease({ http, version: '1.0.0', bundleSha256: bundleHash, keys }))
    .rejects.toThrow(/HTTP 503/);
  await expect(verifyRelease({ http, version: '1.0.0', bundleSha256: bundleHash, keys }))
    .rejects.not.toThrow('private response body');
});

test.each(['owner/repo/../../other', 'owner/repo?token=value', 'https://example.com/repo'])
  ('verifyRelease rejects an invalid repository before requesting %j', async repo => {
    const http = new FakeHttp();
    await expect(verifyRelease({ http, version: '1.0.0', bundleSha256: bundleHash, keys, repo }))
      .rejects.toThrow(TypeError);
    expect(http.calls).toEqual([]);
  });

test('build info has safe source-mode defaults', () => {
  expect(BUILD_VERSION).toBe('0.0.0-dev');
  expect(BUILD_COMMIT).toBe('dev');
  expect(RELEASE_REPO).toBe('grzegorzszmulik22/keysentry');
  expect(RELEASE_PUBLIC_KEYS).toEqual([]);
});
