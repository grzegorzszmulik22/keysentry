import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, test } from 'vitest';
import { appendAllowList } from '../../../scripts/allowlist-append.mjs';
import { isAllowed, verifyAllowList } from '../../../src/box/allowlist/index.js';

test('standalone append output verifies through the public reader and extends a saved checkpoint', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'keysentry-allowlist-integration-'));
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateDer = privateKey.export({ format: 'der', type: 'pkcs8' });
  const publicKeyDer = publicKey.export({ format: 'der', type: 'spki' });
  const keys = [{ keyId: createHash('sha256').update(publicKeyDer).digest('hex').slice(0, 16), publicKeyDer }];
  const env = { KEYSENTRY_RELEASE_SIGNING_KEY: privateDer.toString('base64') };
  const options = {
    logPath: join(directory, 'log.jsonl'), headPath: join(directory, 'head.json'),
    digest: `sha256:${'c'.repeat(64)}`, reference: 'release "v1" / λ \\ archive',
    reason: 'release\nreviewed', at: '2026-10-27T10:00:00.000Z',
  };
  try {
    const { head: previousHead } = await appendAllowList(options, env);
    await appendAllowList({ ...options, reason: 'revoked', at: '2026-10-27T11:00:00.000Z' }, env);
    const result = verifyAllowList(
      await readFile(options.logPath, 'utf8'), await readFile(options.headPath, 'utf8'), keys, { previousHead },
    );
    expect(result.ok).toBe(true);
    expect(result.problems).toEqual([]);
    expect(result.entries).toHaveLength(2);
    expect(isAllowed(result.entries, options.digest, options.at)).toBe(true);
    expect(isAllowed(result.entries, options.digest, '2026-10-27T11:00:00.000Z')).toBe(false);
  } finally {
    privateDer.fill(0);
    await rm(directory, { recursive: true, force: true });
  }
});
